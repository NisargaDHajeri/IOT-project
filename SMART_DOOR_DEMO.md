# Smart Door Demo

## Authorized passwords

- `1234` -> DAD
- `5678` -> MOM

Press Enter after typing the password, or click UNLOCK.

## Wrong-password escalation

Failed attempts are stored in `backend/data/security_events.json`.

The demo builds security context from the accumulated failed-attempt count:

- early failures -> low-risk recording
- repeated failures -> medium-risk monitoring
- sustained failures + network/threat indicators -> high-risk lock

The Random Forest still provides the initial risk perception and the
LangGraph agent still performs reassessment, planning, decision, action,
recommendation and reflection.

## Admin dashboard

Open:

`http://127.0.0.1:5000`

The dashboard automatically refreshes the audit table every 3 seconds.

It displays:
- exact local date/time
- entered password (DEMO ONLY)
- user
- success/failure
- ML risk
- final Agent risk
- escalation
- PQC KEM/signature
- action

## Phone

If your Flask server is exposed through a working Cloudflare Tunnel,
open the tunnel's root URL on the administrator's phone. Do not reuse
an expired tunnel URL; use the currently active URL shown by cloudflared.

## Security note

This is a college-project demonstration. Plaintext passwords are stored
only because the requested demo needs to show the typed credential in the
admin audit. A real smart lock should never retain plaintext passwords.

The project does not directly drive a physical lock yet. The action is a
security command ready to be connected to a vetted door-controller
implementation.
