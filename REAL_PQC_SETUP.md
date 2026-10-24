# Real PQC setup — beginner version

You do NOT need to change your LangGraph architecture.

The project now has two separate layers:

1. **LangGraph** decides LOW / STANDARD / HIGH.
2. **liboqs** performs the actual ML-KEM and ML-DSA cryptographic operations.

NIST standardized ML-KEM in FIPS 203 and ML-DSA in FIPS 204.
Open Quantum Safe's liboqs supports the standardized ML-KEM and ML-DSA variants.

## Recommended order

### 1. First run the existing application

```powershell
cd backend
.venv\Scriptsctivate
python app.py
```

Open:

`http://127.0.0.1:5000`

### 2. Install/build liboqs

On Windows, use the official Open Quantum Safe liboqs Windows build instructions:
https://openquantumsafe.org/liboqs/ (see Windows Quickstart)

Then install the Python wrapper in the same virtual environment:

```powershell
pip install liboqs-python
```

If the wrapper asks for a liboqs shared library, follow the liboqs Windows
instructions and make sure the resulting DLL is discoverable by Windows.

### 3. Run the real PQC self-test

```powershell
python test_real_pqc.py
```

You want to see:

`Shared secret   : True`

and

`Verification   : True`

for LOW, STANDARD and HIGH.

### 4. Browser/API test

With Flask running, open:

`http://127.0.0.1:5000/pqc-test`

The endpoint reports the actual ML-KEM encapsulation/decapsulation and
ML-DSA signing/verification results.

## Important project wording

Say:

"The Agentic AI dynamically selects a NIST-standardized PQC security
profile, and the selected ML-KEM/ML-DSA algorithms are executed through
Open Quantum Safe liboqs."

Do NOT claim that this prototype is a FIPS-validated cryptographic module
merely because it uses liboqs.

## What the Agent does

LOW:
  ML-KEM-512 + ML-DSA-44

MEDIUM:
  ML-KEM-768 + ML-DSA-65

HIGH:
  ML-KEM-1024 + ML-DSA-87

The Agent remains the decision-maker. The crypto layer is the enforcement
mechanism.

## Physical door later

After the laptop prototype is stable, connect the authenticated command
channel to a Raspberry Pi or another suitable controller and drive the
physical lock/servo from that controller.

Do not put the LangGraph/RF Python stack directly on a small MCU.
