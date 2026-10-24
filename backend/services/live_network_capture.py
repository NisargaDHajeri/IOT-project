"""Passive, bounded live packet metadata capture for prototype assessment."""

import math
import platform
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from services.agent_service import record_live_network_prototype_assessment
from services.ciciot_classifier import NETWORK_FEATURE_COLUMNS, validate_network_features


MAX_CAPTURE_SECONDS = 300
DEFAULT_CAPTURE_SECONDS = 60
WINDOW_SECONDS = 10
MIN_PACKETS_PER_WINDOW = 10
MAX_TRACKED_FLOWS = 4096
MAX_WINDOW_FLOWS = 1024
CAPTURE_FILTER = "ip"
CAPTURE_SNAPLEN = 34


class CaptureUnavailable(RuntimeError):
    """Raised when the packet-capture runtime cannot be used."""


class CaptureBusy(RuntimeError):
    """Raised when another capture is already active."""


@dataclass(frozen=True)
class PacketMetadata:
    timestamp: float
    flow_key: Tuple[Any, ...]
    packet_size: int
    header_length: int
    protocol_type: int
    ttl: Optional[int]
    protocol: str
    tcp_flags: int = 0
    service_ports: Tuple[int, ...] = ()
    is_ipv4: bool = False
    is_ipv6: bool = False
    is_arp: bool = False
    is_icmp: bool = False
    is_igmp: bool = False
    is_llc: bool = False


def _scapy_capture_api():
    if platform.system() not in {"Windows", "Linux", "Darwin"}:
        raise CaptureUnavailable(
            f"Packet capture is not supported on {platform.system()}."
        )
    try:
        from scapy.all import AsyncSniffer
        from scapy.arch import get_if_list
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP, Ether, LLC
    except ImportError as exc:
        raise CaptureUnavailable(
            "Scapy is not installed in the Python environment running the backend."
        ) from exc
    return AsyncSniffer, get_if_list, {
        "ARP": ARP,
        "Ether": Ether,
        "ICMP": ICMP,
        "IP": IP,
        "IPv6": IPv6,
        "LLC": LLC,
        "TCP": TCP,
        "UDP": UDP,
    }


def list_capture_interfaces() -> List[Dict[str, str]]:
    """Enumerate selectable interfaces; never choose one automatically."""
    _, get_if_list, _ = _scapy_capture_api()
    if platform.system() == "Windows":
        from scapy.config import conf

        if not conf.use_pcap:
            raise CaptureUnavailable(
                "Npcap is required for Windows packet capture. Install Npcap, "
                "restart the backend, and use an Administrator terminal to capture."
            )
    try:
        names = get_if_list()
    except Exception as exc:
        raise CaptureUnavailable(
            "Could not enumerate capture interfaces. On Windows, install Npcap "
            "and run the backend with packet-capture permissions."
        ) from exc

    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list

            descriptions = {}
            for item in get_windows_if_list():
                guid = str(item.get("guid", "")).strip("{}").casefold()
                description = item.get("description") or item.get("name", "")
                if guid:
                    descriptions[guid] = description
        except Exception:
            descriptions = {}
    else:
        descriptions = {}

    interfaces = []
    for name in names:
        if not name:
            continue
        guid = name.split("{", 1)[-1].split("}", 1)[0].casefold()
        interfaces.append({
            "name": name,
            "description": descriptions.get(guid, name),
        })
    return interfaces


def _create_passive_sniffer(interface: str, callback: Callable[[Any], None]):
    """Open a non-promiscuous IPv4 capture truncated before transport payloads."""
    from scapy.arch.libpcap import _L2libpcapSocket, open_pcap
    from scapy.all import AsyncSniffer

    class HeaderOnlySocket(_L2libpcapSocket):
        def __init__(self):
            self.iface = interface
            handle = open_pcap(
                device=interface,
                snaplen=CAPTURE_SNAPLEN,
                promisc=False,
                to_ms=100,
                monitor=None,
            )
            super().__init__(handle)
            self.pcap_fd.setfilter(CAPTURE_FILTER)

    socket = HeaderOnlySocket()
    try:
        return AsyncSniffer(
            opened_socket=socket,
            prn=callback,
            store=False,
        ), socket
    except Exception:
        socket.close()
        raise


def extract_packet_metadata(packet: Any) -> Optional[PacketMetadata]:
    """Read only the captured Ethernet/IPv4 header; never inspect transport data."""
    _, _, layers = _scapy_capture_api()
    try:
        has_layer = packet.haslayer
        get_layer = packet.getlayer
        ipv4 = get_layer(layers["IP"]) if has_layer(layers["IP"]) else None
        ether = get_layer(layers["Ether"]) if has_layer(layers["Ether"]) else None
    except Exception as exc:
        raise ValueError("Captured packet headers could not be decoded.") from exc

    if ipv4 is None:
        return None

    protocol_type = int(ipv4.proto or 0)
    protocol_name = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
    }.get(protocol_type, "IP")
    header_length = int(ipv4.ihl or 5) * 4
    packet_size = int(ipv4.len or header_length)
    source, destination = str(ipv4.src), str(ipv4.dst)
    if ether is not None:
        header_length += 14
        packet_size += 14

    try:
        timestamp = float(packet.time)
    except (AttributeError, TypeError, ValueError):
        timestamp = time.time()

    flow_protocol = protocol_name
    return PacketMetadata(
        timestamp=timestamp,
        flow_key=(source, destination, flow_protocol),
        packet_size=max(0, packet_size),
        header_length=max(0, header_length),
        protocol_type=protocol_type,
        ttl=int(ipv4.ttl or 0),
        protocol=protocol_name,
        is_ipv4=True,
    )


class NetworkWindow:
    """Fixed-size aggregate counters; packet payloads and flow IDs are not retained."""

    def __init__(self):
        self.packet_count = 0
        self.total_bytes = 0
        self.minimum_size: Optional[int] = None
        self.maximum_size = 0
        self.sum_squared_sizes = 0.0
        self.header_length_total = 0
        self.ttl_total = 0
        self.ttl_count = 0
        self.protocol_counts: Counter[int] = Counter()
        self.protocol_names: Counter[str] = Counter()
        self.service_counts: Counter[str] = Counter()
        self.flag_counts: Counter[str] = Counter()
        self._last_timestamp: Optional[float] = None
        self._interarrival_total = 0.0
        self._interarrival_count = 0
        self._flow_keys = set()
        self.flow_tracking_saturated = False

    def add(self, packet: PacketMetadata) -> bool:
        self.packet_count += 1
        size = packet.packet_size
        self.total_bytes += size
        self.minimum_size = size if self.minimum_size is None else min(
            self.minimum_size, size
        )
        self.maximum_size = max(self.maximum_size, size)
        self.sum_squared_sizes += float(size * size)
        self.header_length_total += packet.header_length
        self.protocol_counts[packet.protocol_type] += 1
        self.protocol_names[packet.protocol] += 1
        if packet.ttl is not None:
            self.ttl_total += packet.ttl
            self.ttl_count += 1

        if packet.flow_key not in self._flow_keys:
            if len(self._flow_keys) < MAX_WINDOW_FLOWS:
                self._flow_keys.add(packet.flow_key)
            else:
                self.flow_tracking_saturated = True

        if self._last_timestamp is not None:
            gap = packet.timestamp - self._last_timestamp
            if math.isfinite(gap) and gap >= 0:
                self._interarrival_total += gap
                self._interarrival_count += 1
        self._last_timestamp = packet.timestamp

        flags = packet.tcp_flags
        for name, mask in (
            ("fin_flag_number", 0x01),
            ("syn_flag_number", 0x02),
            ("rst_flag_number", 0x04),
            ("psh_flag_number", 0x08),
            ("ack_flag_number", 0x10),
            ("ece_flag_number", 0x40),
            ("cwr_flag_number", 0x80),
        ):
            if flags & mask:
                self.flag_counts[name] += 1

        ports = set(packet.service_ports)
        for name, recognized in (
            ("HTTP", {80, 8080}),
            ("HTTPS", {443, 8443}),
            ("DNS", {53}),
            ("Telnet", {23}),
            ("SMTP", {25, 465, 587}),
            ("SSH", {22}),
            ("IRC", {6667, 6697}),
            ("DHCP", {67, 68}),
        ):
            if ports & recognized:
                self.service_counts[name] += 1
        for name, matched in (
            ("TCP", packet.protocol == "TCP"),
            ("UDP", packet.protocol == "UDP"),
            ("ARP", packet.is_arp),
            ("ICMP", packet.is_icmp),
            ("IGMP", packet.is_igmp),
            ("IPv", packet.is_ipv4 or packet.is_ipv6),
            ("LLC", packet.is_llc),
        ):
            if matched:
                self.service_counts[name] += 1
        return True

    @property
    def flow_count(self) -> int:
        return len(self._flow_keys)

    def to_feature_vector(self, elapsed_seconds: float) -> Dict[str, float]:
        """Build CICIoT-named proxies for schema checks only, not model inference."""
        if self.packet_count < MIN_PACKETS_PER_WINDOW:
            raise ValueError(
                f"At least {MIN_PACKETS_PER_WINDOW} packets are required for a window."
            )

        count = float(self.packet_count)
        elapsed = max(float(elapsed_seconds), 0.001)
        average_size = self.total_bytes / count
        variance = max(
            0.0,
            self.sum_squared_sizes / count - average_size * average_size,
        )
        protocol_type = min(
            self.protocol_counts,
            key=lambda item: (-self.protocol_counts[item], item),
        )
        features = {
            "Header_Length": self.header_length_total / count,
            "Protocol Type": float(protocol_type),
            "Time_To_Live": self.ttl_total / self.ttl_count if self.ttl_count else 0.0,
            "Rate": count / elapsed,
            "fin_flag_number": self.flag_counts["fin_flag_number"] / count,
            "syn_flag_number": self.flag_counts["syn_flag_number"] / count,
            "rst_flag_number": self.flag_counts["rst_flag_number"] / count,
            "psh_flag_number": self.flag_counts["psh_flag_number"] / count,
            "ack_flag_number": self.flag_counts["ack_flag_number"] / count,
            "ece_flag_number": self.flag_counts["ece_flag_number"] / count,
            "cwr_flag_number": self.flag_counts["cwr_flag_number"] / count,
            "ack_count": float(self.flag_counts["ack_flag_number"]),
            "syn_count": float(self.flag_counts["syn_flag_number"]),
            "fin_count": float(self.flag_counts["fin_flag_number"]),
            "rst_count": float(self.flag_counts["rst_flag_number"]),
            "HTTP": self.service_counts["HTTP"] / count,
            "HTTPS": self.service_counts["HTTPS"] / count,
            "DNS": self.service_counts["DNS"] / count,
            "Telnet": self.service_counts["Telnet"] / count,
            "SMTP": self.service_counts["SMTP"] / count,
            "SSH": self.service_counts["SSH"] / count,
            "IRC": self.service_counts["IRC"] / count,
            "TCP": self.service_counts["TCP"] / count,
            "UDP": self.service_counts["UDP"] / count,
            "DHCP": self.service_counts["DHCP"] / count,
            "ARP": self.service_counts["ARP"] / count,
            "ICMP": self.service_counts["ICMP"] / count,
            "IGMP": self.service_counts["IGMP"] / count,
            "IPv": self.service_counts["IPv"] / count,
            "LLC": self.service_counts["LLC"] / count,
            "Tot sum": float(self.total_bytes),
            "Min": float(self.minimum_size or 0),
            "Max": float(self.maximum_size),
            "AVG": average_size,
            "Std": math.sqrt(variance),
            "Tot size": average_size,
            "IAT": (
                self._interarrival_total / self._interarrival_count
                if self._interarrival_count
                else 0.0
            ),
            "Number": count,
            "Variance": variance,
        }
        if tuple(features) != NETWORK_FEATURE_COLUMNS:
            raise RuntimeError("Live feature proxy order differs from model schema.")
        return validate_network_features(features)


class LiveNetworkCapture:
    """Single-capture owner-controlled manager with bounded duration and memory."""

    def __init__(
        self,
        sniffer_factory: Optional[Callable[..., Any]] = None,
        assessment_writer: Callable[..., Dict[str, Any]] = (
            record_live_network_prototype_assessment
        ),
    ):
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._sniffer_factory = sniffer_factory
        self._assessment_writer = assessment_writer
        self._sniffer = None
        self._capture_socket = None
        self._monitor_thread = None
        self._state = "STOPPED"
        self._interface: Optional[str] = None
        self._started_at: Optional[str] = None
        self._started_monotonic: Optional[float] = None
        self._duration_seconds = DEFAULT_CAPTURE_SECONDS
        self._total_packets = 0
        self._total_flows = 0
        self._last_packet_at: Optional[str] = None
        self._last_flow_at: Optional[str] = None
        self._assessment_count = 0
        self._error: Optional[str] = None
        self._seen_flow_keys = set()
        self._flow_tracking_saturated = False
        self._window = NetworkWindow()
        self._window_started = 0.0
        self._window_capture_started_at = ""

    def _get_sniffer_factory(self):
        if self._sniffer_factory is not None:
            return self._sniffer_factory
        sniffer_type, _, _ = _scapy_capture_api()
        return sniffer_type

    def snapshot(self, include_interfaces: bool = False) -> Dict[str, Any]:
        with self._lock:
            self._refresh_running_state()
            result = {
                "status": self._state,
                "interface": self._interface,
                "capture_started_at": self._started_at,
                "duration_seconds": self._duration_seconds,
                "maximum_duration_seconds": MAX_CAPTURE_SECONDS,
                "packet_count": self._total_packets,
                "flow_count": self._total_flows,
                "last_packet_at": self._last_packet_at,
                "last_flow_at": self._last_flow_at,
                "flow_count_is_lower_bound": self._flow_tracking_saturated,
                "assessment_count": self._assessment_count,
                "error": self._error,
                "assessment_mode": "ASSESSMENT_ONLY",
                "feature_model_compatible": False,
                "captured_bytes_per_packet_max": CAPTURE_SNAPLEN,
                "live_capture_enabled": self._state in {"STARTING", "RUNNING"},
            }
        if include_interfaces:
            try:
                result["interfaces"] = list_capture_interfaces()
            except CaptureUnavailable as exc:
                result["interfaces"] = []
                result["capability_error"] = str(exc)
                if result["status"] == "STOPPED":
                    result["status"] = "ERROR"
        return result

    def _refresh_running_state(self) -> None:
        if self._state != "STARTING" or self._sniffer is None:
            return
        if getattr(self._sniffer, "running", False):
            self._state = "RUNNING"
            return
        exception = getattr(self._sniffer, "exception", None)
        if exception is not None:
            self._state = "ERROR"
            self._error = self._friendly_capture_error(exception)

    @staticmethod
    def _friendly_capture_error(error: BaseException) -> str:
        detail = str(error).strip()
        if "permission" in detail.lower() or "access is denied" in detail.lower():
            return "Capture permission denied. On Windows, install Npcap and run "
            "the backend from an Administrator terminal."
        if "pcap" in detail.lower() or "winpcap" in detail.lower():
            return "Npcap/libpcap is unavailable. Install Npcap and restart the backend."
        return detail or "Packet capture failed; verify the interface and permissions."

    def start(self, interface: str, duration_seconds: int) -> Dict[str, Any]:
        if not isinstance(interface, str) or not interface.strip():
            raise ValueError("Select a network interface before starting capture.")
        if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int):
            raise ValueError("Capture duration must be a whole number of seconds.")
        if not 10 <= duration_seconds <= MAX_CAPTURE_SECONDS:
            raise ValueError(
                f"Capture duration must be between 10 and {MAX_CAPTURE_SECONDS} seconds."
            )
        available = list_capture_interfaces()
        if interface not in {item["name"] for item in available}:
            raise ValueError("Selected interface is unavailable; refresh the interface list.")

        with self._lock:
            if self._state in {"STARTING", "RUNNING"}:
                raise CaptureBusy("A live capture is already active.")
            self._state = "STARTING"
            self._interface = interface
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._started_monotonic = time.monotonic()
            self._duration_seconds = duration_seconds
            self._total_packets = 0
            self._total_flows = 0
            self._last_packet_at = None
            self._last_flow_at = None
            self._assessment_count = 0
            self._error = None
            self._seen_flow_keys.clear()
            self._flow_tracking_saturated = False
            self._window = NetworkWindow()
            self._window_started = self._started_monotonic
            self._window_capture_started_at = self._started_at
            self._stop_event.clear()

            try:
                if self._sniffer_factory is None:
                    self._sniffer, self._capture_socket = _create_passive_sniffer(
                        interface,
                        self._on_packet,
                    )
                else:
                    factory = self._get_sniffer_factory()
                    self._sniffer = factory(
                        iface=interface,
                        filter=CAPTURE_FILTER,
                        prn=self._on_packet,
                        store=False,
                        promisc=False,
                    )
                self._sniffer.start()
            except Exception as exc:
                self._state = "ERROR"
                self._error = self._friendly_capture_error(exc)
                self._sniffer = None
                if self._capture_socket is not None:
                    self._capture_socket.close()
                    self._capture_socket = None
                raise CaptureUnavailable(self._error) from exc

            self._monitor_thread = threading.Thread(
                target=self._monitor_capture,
                name="live-network-capture-monitor",
                daemon=True,
            )
            self._monitor_thread.start()
            self._refresh_running_state()
        return self.snapshot()

    def _on_packet(self, packet: Any) -> None:
        try:
            metadata = extract_packet_metadata(packet)
        except (ValueError, CaptureUnavailable):
            with self._lock:
                self._error = "A captured packet's network headers could not be decoded."
            return
        if metadata is None:
            return
        with self._lock:
            if self._state not in {"STARTING", "RUNNING"}:
                return
            self._total_packets += 1
            packet_time = datetime.fromtimestamp(
                metadata.timestamp, timezone.utc
            ).isoformat()
            self._last_packet_at = packet_time
            if metadata.flow_key not in self._seen_flow_keys:
                if len(self._seen_flow_keys) < MAX_TRACKED_FLOWS:
                    self._seen_flow_keys.add(metadata.flow_key)
                    self._total_flows += 1
                    self._last_flow_at = packet_time
                else:
                    self._flow_tracking_saturated = True
            self._window.add(metadata)

    def _monitor_capture(self) -> None:
        capture_started_monotonic = self._started_monotonic or time.monotonic()
        stop_reason = None
        while not self._stop_event.wait(0.25):
            now = time.monotonic()
            with self._lock:
                self._refresh_running_state()
                if self._state == "ERROR":
                    stop_reason = "capture_error"
                elif now - capture_started_monotonic >= self._duration_seconds:
                    stop_reason = "maximum_duration_reached"
                elif self._state == "STARTING" and now - capture_started_monotonic > 5:
                    self._state = "ERROR"
                    self._error = (
                        "Capture did not start. Verify Npcap, interface availability, "
                        "and packet-capture permissions."
                    )
                    stop_reason = "capture_start_timeout"
                if self._state == "RUNNING" and now - self._window_started >= WINDOW_SECONDS:
                    pending = self._take_window(now)
                else:
                    pending = None
            if pending is not None:
                self._persist_window(*pending)
            if stop_reason:
                break

        sniffer = self._sniffer
        try:
            if sniffer is not None and getattr(sniffer, "running", False):
                sniffer.stop(join=True)
        except Exception as exc:
            with self._lock:
                self._state = "ERROR"
                self._error = self._friendly_capture_error(exc)
        finally:
            capture_socket = self._capture_socket
            self._capture_socket = None
            if capture_socket is not None:
                try:
                    capture_socket.close()
                except Exception as exc:
                    with self._lock:
                        self._state = "ERROR"
                        self._error = self._friendly_capture_error(exc)

        now = time.monotonic()
        with self._lock:
            if self._window.packet_count:
                pending = self._take_window(now)
            else:
                pending = None
        if pending is not None:
            self._persist_window(*pending)
        with self._lock:
            if self._state != "ERROR":
                self._state = "STOPPED"
            self._sniffer = None

    def _take_window(self, now: float):
        elapsed = max(0.001, now - self._window_started)
        if self._window.packet_count < MIN_PACKETS_PER_WINDOW:
            self._window = NetworkWindow()
            self._window_started = now
            self._window_capture_started_at = datetime.now(timezone.utc).isoformat()
            return None
        features = self._window.to_feature_vector(elapsed)
        flow_count = self._window.flow_count
        if self._window.flow_tracking_saturated:
            self._flow_tracking_saturated = True
        ended_at = datetime.now(timezone.utc).isoformat()
        started_at = self._window_capture_started_at
        interface = self._interface or "unknown"
        last_packet_at = (
            datetime.fromtimestamp(
                self._window._last_timestamp, timezone.utc
            ).isoformat()
            if self._window._last_timestamp is not None
            else ended_at
        )
        self._window = NetworkWindow()
        self._window_started = now
        self._window_capture_started_at = ended_at
        return interface, started_at, ended_at, features, flow_count, last_packet_at

    def _persist_window(
        self, interface, started_at, ended_at, features, flow_count, last_packet_at
    ):
        packet_count = int(features["Number"])
        try:
            result = self._assessment_writer(
                interface=interface,
                capture_started_at=started_at,
                capture_ended_at=ended_at,
                packet_count=packet_count,
                flow_count=flow_count,
                last_packet_at=last_packet_at,
                features=features,
            )
        except Exception:
            with self._lock:
                self._state = "ERROR"
                self._error = "Live metadata was captured, but its assessment could not be persisted."
                self._stop_event.set()
            return
        with self._lock:
            if not result.get("duplicate_event", False):
                self._assessment_count += 1

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if self._state not in {"STARTING", "RUNNING"}:
                return self.snapshot()
            self._stop_event.set()
            monitor = self._monitor_thread
        if monitor is not None:
            monitor.join(timeout=10)
            if monitor.is_alive():
                raise CaptureBusy("Capture shutdown is still in progress.")
        return self.snapshot()


live_network_capture = LiveNetworkCapture()
