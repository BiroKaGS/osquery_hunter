# osquery_hunter

Windows process + network triage helper for security professionals.  
This is **not** a replacement for AV/EDR—it’s designed for quick, manual triage in environments without those tools.  
Basic IT knowledge is assumed for installation and interpreting results.

The entire source code is included. You are free to modify it to suit your environment or workflow.

---

## Requirements

- **Python:** 3.10 or newer (tested on 3.11)
- **osquery:** Windows x64 version **5.19.0**
  - Download from the official site: https://osquery.io/downloads/
  - Verify SHA256 of the executable you intend to run, e.g. `osqueryi.exe`:
    ```
    EDA5AC01F705F976957ABD8C9D14BBD355616EBEF6C5B45F28A2AE44F53E207D
    ```
    *(This value reflects the user's verified `osqueryi.exe`. If your build differs, recompute and update.)*
  - Ensure `osqueryi.exe` is on your PATH or installed in the default location  
    `C:\Program Files\osquery\osqueryi.exe`.

---

## Usage

```powershell
# 1) Create and activate a virtual environment (optional but recommended)
python -m venv .venv
. .\.venv\Scripts\Activate.ps1

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run the tool
python .\src\list_processes.py
```

If `osqueryi.exe` is not on PATH, you can point to it explicitly:
```powershell
$env:OSQUERYI_PATH = "C:\Program Files\osquery\osqueryi.exe"
```

---

## Notes

- The tool lists running processes whose executables are **not simultaneously trusted in the Windows trust store and signed by Microsoft**.
- It helps analysts quickly highlight unsigned/third‑party binaries, potential LOLBIN usage, and network connections of interest.
- Vendor binaries (like *osquery*) are **not included** in this repository. Always verify hashes before use.
- Modify and extend freely for your own environment or use cases.

---

## License
MIT License — see `LICENSE`.
