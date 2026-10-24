# Direct LAN REST migration

Google Apps Script and Google Sheets are no longer required for live door operation.
The runtime path is ESP8266 -> Flask -> SQLite/security services -> command queue.

## Device API

All device routes require `X-Device-Token`: `POST /api/device/heartbeat`,
`POST /api/device/keypad-activity`, `POST /api/device/authenticate`,
`GET /api/device/commands`, `POST /api/device/commands/<id>/ack`, and the
`/api/device/reset/*` routes. Keypad activity sends only input length and action.

## Windows LAN setup

1. Put the ESP8266 and Windows PC on the same non-guest Wi-Fi network.
2. Run `ipconfig`; copy the Wi-Fi IPv4 address into
   `esp8266/smart_door_esp8266/secrets.h` as `DEVICE_API_BASE_URL`.
3. Set the same token in backend `.env` (`DEVICE_SECRET`) and firmware
   `DEVICE_TOKEN`.
4. Run Flask from `backend` with `py -m flask --app app run --host 0.0.0.0 --port 5000`.
5. In an elevated PowerShell, allow Private-profile TCP 5000:
   `New-NetFirewallRule -DisplayName "Smart Door Flask LAN" -Direction Inbound -Profile Private -Protocol TCP -LocalPort 5000 -Action Allow`.

## ESP8266

Keep Wi-Fi credentials unchanged. In `secrets.h`, set the Windows Wi-Fi IPv4
address (not 127.0.0.1) and the shared device token; then compile and upload
from the Arduino IDE. This prototype uses HTTP on a trusted LAN. Its token stops
unauthorized API use but does not encrypt traffic; use a trusted HTTPS certificate
and an ESP8266 trust anchor before deploying outside that network.

## Reset privacy

The hardware and browser reset flows submit SHA-256 values for the new and
confirmation PINs. The hardware route never accepts plaintext PIN fields.
