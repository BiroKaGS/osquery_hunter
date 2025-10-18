import subprocess, json, shutil

# Use osqueryi from PATH; you should have installed it already. Modify the path as per your installation.
OSQUERYI = shutil.which("osqueryi") or r"C:\Program Files\osquery\osqueryi.exe"

QUERY = """
SELECT
  p.pid, p.name, p.path, p.parent, p.start_time,
  a.subject_name AS signer, a.issuer_name AS issuer, a.result AS sig_result
FROM processes p
LEFT JOIN authenticode a ON a.path = p.path
WHERE NOT (
  LOWER(a.result) IN ('trusted','valid')
  AND (
    LOWER(a.subject_name) LIKE '%microsoft%'
    OR LOWER(a.issuer_name)  LIKE '%microsoft%'
  )
)
ORDER BY p.pid;
"""
SOCKETS_QUERY = """
SELECT pid, remote_address, remote_port, protocol, state
FROM process_open_sockets
WHERE remote_address != ''
ORDER BY pid, remote_address, remote_port;
"""

SUSP_PATHS = (
    "\\Users\\", "\\AppData\\", "\\Temp\\", "\\ProgramData\\", "\\Windows\\Temp\\"
)

LOLBIN_NAMES = {
    "rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe",
    "powershell.exe","pwsh.exe","cmd.exe","certutil.exe","bitsadmin.exe",
    "installutil.exe","msiexec.exe","odbcconf.exe","fodhelper.exe",
    "dllhost.exe","scriptrunner.exe","addinutil.exe"
}

SUSP_PARENTS = {
    "chrome.exe","msedge.exe","firefox.exe",
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe"
}

def is_zero(x):
    # treat None/0/"0"/"0.0.0.0"/"::" as empty/zero
    return x in (None, 0, "0", "0.0.0.0", "::")

def _proto_name(v):
    try:
        n = int(v)
        return {6: "TCP", 17: "UDP"}.get(n, str(v))
    except Exception:
        return v or ""
    
def run_osquery(sql: str):
    if not OSQUERYI:
        raise SystemExit("osqueryi not found. Is it installed and on PATH?")
    proc = subprocess.run(
        [OSQUERYI, "--json", sql],
        capture_output=True, text=True, encoding="utf-8", errors="ignore"
    )
    if proc.returncode != 0:
        raise SystemExit(f"osqueryi failed: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise SystemExit(f"Failed to parse osquery JSON: {e}")

def main():
    rows = run_osquery(QUERY)
    if not rows:
        print("No processes returned.")
        return
    
    from collections import defaultdict

    sock_rows = run_osquery(SOCKETS_QUERY)
    sockets_by_pid = defaultdict(list)
    for s in sock_rows:
        # normalize pid as string to match osquery output type
        pid_key = str(s.get("pid"))
        sockets_by_pid[pid_key].append(s)

    for i, r in enumerate(rows, 1):
        pid   = r.get("pid")
        name  = r.get("name", "")
        path  = r.get("path", "")
        exe_path = r.get("path", "") 
        ppid  = r.get("parent")
        start = r.get("start_time", "")
        pid   = str(r.get("pid"))
        lower_name = (name or "").lower()
        lower_path = (exe_path or "").lower()
        conns = sockets_by_pid.get(pid, [])
        print(f"{i:4d}. pid={pid:<6} ppid={ppid:<6} name={name}")
        if path:
            print(f"      path: {path}")
        if start:
            print(f"      start_time: {start}")
        if conns:
             # summary
            distinct_ips = {c.get("remote_address") for c in conns if c.get("remote_address")}
            established = sum(1 for c in conns if (c.get("state") or "").upper() == "ESTABLISHED" or not c.get("state"))
            print(f"      net: sockets={len(conns)} established={established} peers={len(distinct_ips)}")

            # list ALL remote endpoints (ip:port proto state)

        # 1) Path anomalies (writable/user dirs)
        is_weird_path = any(p.lower() in lower_path for p in SUSP_PATHS)
        if is_weird_path:
            print("      ⚠ writable/user path — verify why this binary lives here")

        # 2) LOLBINs
        if lower_name in LOLBIN_NAMES:
            print("      ⚠ LOLBIN — review full command line and parent process")

        # 3) Suspicious parent → child combo (browser/Office spawning a LOLBIN)
        if ppid and (ppid.lower() in SUSP_PARENTS) and (lower_name in LOLBIN_NAMES):
            print(f"      ⚠ Suspicious parent→child chain: {ppid_name} → {name}")

        shown = 0        
        
        for c in (conns or []):
            ra = c.get("remote_address")
            rp = c.get("remote_port")
            proto = _proto_name(c.get("protocol"))
            state = (c.get("state") or "").upper()

            if proto == "UDP" and (is_zero(ra) or is_zero(rp)):
                continue

            if is_zero(ra) or is_zero(rp):
                continue

            print(f"        -> {ra}:{rp}  {proto} {state}")
            shown+= 1

        if shown == 0:
            print("      net: no outbound sockets observed")
            # spacer line for readability
            # print()

if __name__ == "__main__":
    main()
print ("This list shows processes whose executable is not simultaneously (a) trusted/valid in the local Windows trust store and (b) signed by Microsoft.")
print("Final checks:")
print("  • Path sanity: compare actual path vs usual vendor path (e.g., Chrome → C:\\Program Files\\Google\\...).")
print("  • Unusual/writable paths: flag %TEMP%, %APPDATA%, Downloads, Desktop, C:\\Users\\* and C:\\ProgramData\\*.")
print("  • Parent/child: odd parents (browser/Office launching LOLBINs like rundll32, regsvr32, mshta, wscript, powershell).")
print("  • Network: review public IPs; look up suspicious ones in AbuseIPDB/VirusTotal manually; note RFC1918 vs public, ASN/CDN.")
print("  • Signing: unsigned or self-signed binaries/DLLs, mismatched company name vs folder owner (e.g., ‘Microsoft’ under Google path).")
