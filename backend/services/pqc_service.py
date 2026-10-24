"""Post-Quantum Cryptography (PQC) Profile & Execution Service.

Adheres to NIST Post-Quantum Cryptographic standards:
- LOW: ML-KEM-512 (Kyber-512) + ML-DSA-44 (Dilithium-2)
- MEDIUM: ML-KEM-768 (Kyber-768) + ML-DSA-65 (Dilithium-3)
- HIGH: ML-KEM-1024 (Kyber-1024) + ML-DSA-87 (Dilithium-5)

Explicitly differentiates:
1. Algorithm selection (always dynamic and driven by AI Agent)
2. Cryptographic execution (executed via liboqs-python when available, or transparently marked as selected).
"""

from typing import Dict, Any, Optional
from config import PQC_PROFILES

try:
    import oqs
    OQS_AVAILABLE = True
    OQS_ERROR = ""
except Exception as exc:
    oqs = None
    OQS_AVAILABLE = False
    OQS_ERROR = str(exc)


def get_pqc_profile(risk_level: str) -> Dict[str, Any]:
    """Returns the adaptive NIST PQC cryptographic profile for a given risk level."""
    normalized = (risk_level or "LOW").upper()
    if normalized not in PQC_PROFILES:
        normalized = "LOW"
    
    profile = PQC_PROFILES[normalized].copy()
    profile["oqs_installed"] = OQS_AVAILABLE
    profile["execution_mode"] = "NATIVE_LIBOQS" if OQS_AVAILABLE else "PROFILE_SELECTION_ONLY"
    return profile


def execute_pqc_operation(risk_level: str) -> Dict[str, Any]:
    """Executes or validates the PQC transaction for the selected profile.
    
    If liboqs is available, generates keypair and encapsulates shared secret;
    Otherwise, returns profile specifications with transparent capability status.
    """
    profile = get_pqc_profile(risk_level)
    
    if not OQS_AVAILABLE:
        return {
            "status": "PROFILE_SELECTED",
            "risk_tier": risk_level,
            "kem_algorithm": profile["kem"],
            "signature_algorithm": profile["signature"],
            "nist_security_level": profile["nist_level"],
            "execution_status": "PROFILE_SELECTION_ONLY (native liboqs unavailable)",
            "native_execution_available": False,
            "is_native_pqc": False,
        }
    
    try:
        kem_alg = profile["kem"]
        sig_alg = profile["signature"]
        
        with oqs.KeyEncapsulation(kem_alg) as kem:
            client_pub = kem.generate_keypair()
            ciphertext, shared_secret_server = kem.encap_secret(client_pub)
            shared_secret_client = kem.decap_secret(ciphertext)
            kem_verified = (shared_secret_client == shared_secret_server)
        
        with oqs.Signature(sig_alg) as sig:
            sig_pub = sig.generate_keypair()
            msg = b"DOOR_ACCESS_TOKEN_AUTHENTICATED"
            signature = sig.sign(msg)
            sig_verified = sig.verify(msg, signature, sig_pub)
            
        return {
            "status": "PQC_NATIVE_EXECUTION_SUCCESS",
            "risk_tier": risk_level,
            "kem_algorithm": kem_alg,
            "signature_algorithm": sig_alg,
            "nist_security_level": profile["nist_level"],
            "kem_verified": kem_verified,
            "signature_verified": sig_verified,
            "ciphertext_len": len(ciphertext),
            "signature_len": len(signature),
            "is_native_pqc": True,
            "execution_status": "NATIVE_LIBOQS_EXECUTED",
        }
    except Exception as exc:
        return {
            "status": "PQC_EXECUTION_ERROR",
            "risk_tier": risk_level,
            "kem_algorithm": profile["kem"],
            "signature_algorithm": profile["signature"],
            "execution_status": "NATIVE_EXECUTION_FAILED",
            "native_execution_available": True,
            "is_native_pqc": False,
        }


def get_pqc_system_status() -> Dict[str, Any]:
    """Returns overall PQC subsystem capabilities for dashboard health checks."""
    return {
        "liboqs_available": OQS_AVAILABLE,
        "supported_profiles": list(PQC_PROFILES.keys()),
        "profiles": PQC_PROFILES,
        "default_profile": "LOW",
        "crypto_backend": "liboqs-python (C-based OpenQuantumSafe)" if OQS_AVAILABLE else "Dynamic Profile Dispatcher",
    }
