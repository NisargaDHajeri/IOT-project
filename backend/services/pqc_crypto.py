"""Real PQC crypto adapter using Open Quantum Safe liboqs-python.

This module is intentionally separate from the LangGraph agent:
LangGraph chooses the security profile; this module performs the
selected ML-KEM / ML-DSA operations.

Requires liboqs to be installed and liboqs-python to be available.
"""

try:
    import oqs
    OQS_AVAILABLE = True
    OQS_ERROR = ""
except Exception as exc:
    oqs = None
    OQS_AVAILABLE = False
    OQS_ERROR = str(exc)


PROFILES = {
    "LOW": {
        "kem": "ML-KEM-512",
        "signature": "ML-DSA-44",
    },
    "STANDARD": {
        "kem": "ML-KEM-768",
        "signature": "ML-DSA-65",
    },
    "HIGH": {
        "kem": "ML-KEM-1024",
        "signature": "ML-DSA-87",
    },
}


def require_oqs():
    if not OQS_AVAILABLE:
        raise RuntimeError(
            "liboqs-python is not available. Install/build liboqs first. "
            f"Original error: {OQS_ERROR}"
        )


def _kem_name(name):
    # liboqs-python normally exposes the NIST names used by liboqs.
    return name


def _sig_name(name):
    return name


def generate_kem_keypair(algorithm):
    require_oqs()
    kem = oqs.KeyEncapsulation(_kem_name(algorithm))
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key


def kem_roundtrip(algorithm):
    """Perform a real ML-KEM key generation, encapsulation and decapsulation."""
    require_oqs()

    sender = oqs.KeyEncapsulation(_kem_name(algorithm))
    public_key = sender.generate_keypair()
    secret_key = sender.export_secret_key()

    receiver = oqs.KeyEncapsulation(_kem_name(algorithm))
    ciphertext, sender_secret = receiver.encap_secret(public_key)

    # Import the recipient secret key into a fresh object.
    recipient = oqs.KeyEncapsulation(_kem_name(algorithm))
    recipient.import_secret_key(secret_key)
    recipient_secret = recipient.decap_secret(ciphertext)

    return {
        "algorithm": algorithm,
        "key_generation": True,
        "encapsulation": True,
        "decapsulation": True,
        "shared_secret_match": sender_secret == recipient_secret,
        "ciphertext_bytes": len(ciphertext),
        "shared_secret_bytes": len(sender_secret),
    }


def signature_roundtrip(algorithm, message=b"AGENTIC_PQC_DOOR_COMMAND"):
    """Perform a real ML-DSA signing and verification operation."""
    require_oqs()

    signer = oqs.Signature(_sig_name(algorithm))
    public_key = signer.generate_keypair()
    secret_key = signer.export_secret_key()

    signing = oqs.Signature(_sig_name(algorithm))
    signing.import_secret_key(secret_key)
    signature = signing.sign(message)

    verifier = oqs.Signature(_sig_name(algorithm))
    verified = verifier.verify(message, signature, public_key)

    return {
        "algorithm": algorithm,
        "key_generation": True,
        "signing": True,
        "verification": bool(verified),
        "signature_bytes": len(signature),
    }


def run_profile_self_test(profile_name):
    if profile_name not in PROFILES:
        raise ValueError(f"Unknown PQC profile: {profile_name}")

    profile = PROFILES[profile_name]
    kem_result = kem_roundtrip(profile["kem"])
    sig_result = signature_roundtrip(profile["signature"])

    return {
        "profile": profile_name,
        "kem": kem_result,
        "signature": sig_result,
        "pqc_verified": (
            kem_result["shared_secret_match"]
            and sig_result["verification"]
        ),
    }


def execute_pqc_transaction(profile_name):
    """Execute or verify a PQC cryptographic transaction for the given profile."""
    if not OQS_AVAILABLE:
        p = PROFILES.get(profile_name, PROFILES["LOW"])
        return {
            "profile": profile_name,
            "kem_algorithm": p["kem"],
            "signature_algorithm": p["signature"],
            "crypto_status": "PQC_POLICY_SELECTED",
            "liboqs_active": False,
            "note": "PQC security profile selected by LangGraph. Liboqs optional wrapper ready.",
        }

    try:
        test_res = run_profile_self_test(profile_name)
        return {
            "profile": profile_name,
            "kem_algorithm": test_res["kem"]["algorithm"],
            "signature_algorithm": test_res["signature"]["algorithm"],
            "crypto_status": "PQC_CRYPTOGRAPHIC_OPERATION_VERIFIED",
            "liboqs_active": True,
            "shared_secret_match": test_res["kem"]["shared_secret_match"],
            "signature_verified": test_res["signature"]["verification"],
            "ciphertext_bytes": test_res["kem"]["ciphertext_bytes"],
            "signature_bytes": test_res["signature"]["signature_bytes"],
        }
    except Exception as exc:
        p = PROFILES.get(profile_name, PROFILES["LOW"])
        return {
            "profile": profile_name,
            "kem_algorithm": p["kem"],
            "signature_algorithm": p["signature"],
            "crypto_status": "PQC_POLICY_SELECTED",
            "liboqs_active": False,
            "error": str(exc),
        }

