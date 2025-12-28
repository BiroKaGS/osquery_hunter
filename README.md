# osquery_hunter

Windows process and network triage helper for security professionals.

This tool is **not a replacement for AV/EDR**.  
It is designed for **manual, analyst-driven triage** in environments where full endpoint protection is unavailable, limited, or during incident response.

The objective is to quickly surface:
- Unsigned or suspicious binaries
- Potential LOLBIN usage
- Suspicious parent/child process relationships
- Network connections of interest
- Optional reputation intelligence (VirusTotal, AbuseIPDB)
- Detailed Authenticode signature metadata (subject, issuer, validity, thumbprint)

Basic IT and Windows internals knowledge is assumed.

The **entire source code is included** and may be freely modified to suit your environment or workflow.

---

## Disclaimer (Important)

This tool is intended **only for defensive security analysis** on systems you own or are explicitly authorized to assess.

It performs **local system inspection** using:
- `osquery`
- Windows PowerShell (for Authenticode signature inspection)

Optional reputation lookups (VirusTotal, AbuseIPDB) are performed **only if the user provides API keys**.

The author(s) assume **no responsibility for misuse**, unauthorized scanning, or violations of local laws or organizational policies.

---

## Requirements

- **Operating System:** Windows 10 / Windows 11 (x64)
- **Python:** 3.10 or newer (tested on 3.11)
- **osquery:** Windows x64 version **5.19.0**

---

## osquery Installation & Verification

Download osquery from the official site:

https://osquery.io/downloads/

After downloading, **verify the SHA-256 hash** of the executable you intend to run  
(example for `osqueryi.exe`):

```powershell
Get-FileHash "C:\Program Files\osquery\osqueryi.exe" -Algorithm SHA256
```
Expected SHA-256 (osquery 5.19.0 Windows x64):
    EDA5AC01F705F976957ABD8C9D14BBD355616EBEF6C5B45F28A2AE44F53E207D

    *(This value reflects the user's verified `osqueryi.exe`. If your build differs, recompute and update.)*
  - Ensure `osqueryi.exe` is on your PATH or installed in the default location  
    `C:\Program Files\osquery\osqueryi.exe`.

---

##Installation
# Clone the repository
git clone https://github.com/BiroKaGS/osquery_hunter.git
cd osquery_hunter

# Create and activate a virtual environment (recommended)
python -m venv .venv
. .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

## Usage

```powershell
python .\osquery_hunter_enriched_signature.py

```

If `osqueryi.exe` is not on PATH, you can point to it explicitly:
```powershell
$env:OSQUERYI_PATH = "C:\Program Files\osquery\osqueryi.exe"
```

---

## Notes
Runtime Expectations
-This tool may take several minutes to complete, depending on:
Number of running processes
Number of active network connections
Whether VirusTotal and AbuseIPDB enrichment is enabled
API rate limits
Typical runtimes:
Without external lookups: ~30–90 seconds
With VirusTotal / AbuseIPDB enabled: several minutes
This is expected behavior and not a hang.
- The tool lists running processes whose executables are **not simultaneously trusted in the Windows trust store and signed by Microsoft**.
- It helps analysts quickly highlight unsigned/third‑party binaries, potential LOLBIN usage, and network connections of interest.
- Vendor binaries (like *osquery*) are **not included** in this repository. Always verify hashes before use.
- Modify and extend freely for your own environment or use cases.

---

## License
MIT License — see `LICENSE`.
