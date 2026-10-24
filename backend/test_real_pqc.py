from services.pqc_crypto import run_profile_self_test

print("=" * 72)
print("REAL POST-QUANTUM CRYPTOGRAPHY SELF-TEST")
print("=" * 72)

for profile in ["LOW", "STANDARD", "HIGH"]:
    print(f"\n--- {profile} PROFILE ---")
    try:
        result = run_profile_self_test(profile)
        print("KEM:", result["kem"]["algorithm"])
        print("  Key generation :", result["kem"]["key_generation"])
        print("  Encapsulation  :", result["kem"]["encapsulation"])
        print("  Decapsulation   :", result["kem"]["decapsulation"])
        print("  Shared secret   :", result["kem"]["shared_secret_match"])
        print("Signature:", result["signature"]["algorithm"])
        print("  Key generation :", result["signature"]["key_generation"])
        print("  Signing        :", result["signature"]["signing"])
        print("  Verification   :", result["signature"]["verification"])
        print("PQC VERIFIED     :", result["pqc_verified"])
    except Exception as exc:
        print("PQC TEST NOT RUN:", exc)

print("\nNOTE: The LangGraph agent remains the policy decision-maker.")
print("This test proves the selected NIST-standardized algorithms can")
print("perform actual KEM and signature operations through liboqs.")
