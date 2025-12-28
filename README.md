# osquery_hunter

Windows process and network triage helper for security professionals.

### Enhancements in this fork

This fork builds on the original `osquery_hunter` by ItsmeGSG and extends it with additional
context and enrichment to support deeper manual triage.

Key additions include:
- Detailed Authenticode signature extraction (certificate subject, issuer, validity period, thumbprint, serial)
- Optional file reputation checks using VirusTotal
- Optional remote IP reputation checks using AbuseIPDB
- Correlation of running processes with active network connections
- Structured JSON output and a human-readable HTML dashboard
- Improved documentation, integrity verification, and safety controls for open-source use

These enhancements are intended to provide analysts with more context and reduce time spent
pivoting between tools during investigation.

**##OPTIONAL THREAT-INTELLIGENCE API INTEGRATION**

This fork supports optional enrichment using third-party threat-intelligence services.
These integrations are disabled by default and are only activated when API keys are supplied by the user.

**VIRUSTOTAL (FILE REPUTATION)**

VirusTotal is used to check SHA-256 hashes of executables against multiple antivirus engines.

How it is used:

File hashes are calculated locally on the system

Only the SHA-256 hash is queried; files are never uploaded

Results are used only for contextual analysis during triage

How to enable VirusTotal integration:

Create a VirusTotal API key from:
https://www.virustotal.com/

Set the API key as an environment variable.

Windows (PowerShell):
setx VT_API_KEY "your_virustotal_api_key"

Restart the terminal and run the tool:
python osquery_hunter_enriched_signature.py

If the API key is not set, VirusTotal checks are skipped automatically.

**ABUSEIPDB (IP REPUTATION)**

AbuseIPDB is used to assess the reputation of public remote IP addresses observed in active network connections.

How it is used:

Only public IP addresses are queried

Private, loopback, and reserved IPs are ignored

Abuse confidence scores and report counts are used for contextual risk assessment

How to enable AbuseIPDB integration:

Create an AbuseIPDB API key from:
https://www.abuseipdb.com/

Set the API key as an environment variable.

Windows (PowerShell):
setx ABUSEIPDB_KEY "your_abuseipdb_api_key"

Restart the terminal and run the tool:
python osquery_hunter_enriched_signature.py

If the API key is not set, AbuseIPDB checks are skipped automatically.

API USAGE NOTES AND SAFETY

API keys are never hardcoded and must not be committed to source control

Free API tiers are rate-limited; scans may take longer when enrichment is enabled

Reputation services may generate false positives, especially for cloud provider IPs

API usage must comply with the respective service’s terms of service

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
-Number of running processes
-Number of active network connections
-Whether VirusTotal and AbuseIPDB enrichment is enabled
-API rate limits
-Typical runtimes:
--Without external lookups: ~30–90 seconds
--With VirusTotal / AbuseIPDB enabled: several minutes
-This is expected behavior and not a hang.
- The tool lists running processes whose executables are **not simultaneously trusted in the Windows trust store and signed by Microsoft**.
- It helps analysts quickly highlight unsigned/third‑party binaries, potential LOLBIN usage, and network connections of interest.
- Vendor binaries (like *osquery*) are **not included** in this repository. Always verify hashes before use.
- Modify and extend freely for your own environment or use cases.

---

## License
MIT License — see `LICENSE`.
