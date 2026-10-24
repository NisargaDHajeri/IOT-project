PROFILES = {
    "LOW": {
        "name": "LOW",
        "kem": "ML-KEM-512",
        "signature": "ML-DSA-44",
        "description": "Resource-conscious quantum-resistant policy for normal door-lock operation.",
    },
    "MEDIUM": {
        "name": "STANDARD",
        "kem": "ML-KEM-768",
        "signature": "ML-DSA-65",
        "description": "Balanced quantum-resistant policy for suspicious conditions.",
    },
    "HIGH": {
        "name": "HIGH",
        "kem": "ML-KEM-1024",
        "signature": "ML-DSA-87",
        "description": "Stronger quantum-resistant policy for active attack conditions.",
    },
}

def profile_for_risk(risk: str):
    return PROFILES[risk].copy()
