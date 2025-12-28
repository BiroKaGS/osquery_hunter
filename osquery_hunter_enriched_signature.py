#!/usr/bin/env python3
"""
osquery_hunter_enriched_signature.py
- Runs osquery (process + sockets)
- Adds full Authenticode certificate info (subject, issuer, valid-from, valid-to, thumbprint, serial)
- Optionally still supports VirusTotal / AbuseIPDB enrichment (API keys optional)
- Produces JSON + HTML dashboard
"""

import os
import subprocess
import json
import shutil
import hashlib
import time
import ipaddress
from collections import defaultdict
from datetime import datetime
import html as html_mod
import requests
import sys

# ----------------- CONFIG -----------------
VT_API_KEY = ""      # write your virus total api key here
ABUSEIPDB_KEY = ""   # write your abuseipdb key here 
#both the keys can be found on their official website 
# Rate limiting - only used if VT/Abuse are enabled
VT_DELAY_SECONDS = 15
ABUSE_DELAY_SECONDS = 1

# caps
MAX_VT_QUERIES_PER_RUN = 200
MAX_ABUSE_QUERIES_PER_RUN = 1000

# osqueryi path (use PATH or set full path)
OSQUERYI = shutil.which("osqueryi") or r"C:\Program Files\osquery\osqueryi.exe"

# suspicious locations / LOLBINs / suspicious parents
SUSP_PATHS = ("\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\", "\\windows\\temp\\")
LOLBIN_NAMES = {"rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe",
               "powershell.exe","pwsh.exe","cmd.exe","certutil.exe","bitsadmin.exe",
               "installutil.exe","msiexec.exe","odbcconf.exe","fodhelper.exe","dllhost.exe"}
SUSP_PARENTS = {"chrome.exe","msedge.exe","firefox.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe"}

# ----------------- QUERIES -----------------
QUERY = """
SELECT
  p.pid, p.name, p.path, p.parent, p.start_time
FROM processes p
ORDER BY p.pid;
"""

SOCKETS_QUERY = """
SELECT pid, remote_address, remote_port, protocol, state
FROM process_open_sockets
WHERE remote_address != ''
ORDER BY pid, remote_address, remote_port;
"""

# ----------------- Helpers -----------------
def run_osquery(sql: str):
    if not OSQUERYI or not os.path.exists(OSQUERYI):
        raise SystemExit("osqueryi not found. Install osquery and ensure osqueryi is on PATH or update OSQUERYI variable.")
    proc = subprocess.run([OSQUERYI, "--json", sql], capture_output=True, text=True, encoding="utf-8", errors="ignore")
    if proc.returncode != 0:
        raise SystemExit(f"osqueryi failed: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout or "[]")
    except Exception as e:
        raise SystemExit(f"Failed to parse osquery JSON: {e}")

def sha256_of_file(path):
    try:
        with open(path, "rb") as f:
            h = hashlib.sha256()
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def is_private_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_reserved or a.is_multicast
    except Exception:
        return True

# ----------------- VirusTotal (optional) -----------------
vt_cache = {}
vt_queries = 0
def vt_lookup_hash(sha256):
    global vt_queries
    if not sha256:
        return {"status":"no_hash"}
    if sha256 in vt_cache:
        return vt_cache[sha256]
    if not VT_API_KEY or VT_API_KEY.startswith("PASTE_") or VT_API_KEY == "":
        res = {"status":"no_api_key"}
        vt_cache[sha256] = res
        return res
    if vt_queries >= MAX_VT_QUERIES_PER_RUN:
        return {"status":"vt_limit_reached"}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        vt_queries += 1
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            vt_res = {"status":"ok", "stats": stats}
        elif r.status_code == 404:
            vt_res = {"status":"not_found"}
        else:
            vt_res = {"status":"error", "http_status": r.status_code, "text": r.text[:400]}
    except Exception as e:
        vt_res = {"status":"error", "exception": str(e)}
    vt_cache[sha256] = vt_res
    time.sleep(VT_DELAY_SECONDS)
    return vt_res

# ----------------- AbuseIPDB (optional) -----------------
abuse_cache = {}
abuse_queries = 0
def abuseipdb_check(ip, maxAgeInDays=90):
    global abuse_queries
    if not ip:
        return {"status":"no_ip"}
    if ip in abuse_cache:
        return abuse_cache[ip]
    if not ABUSEIPDB_KEY or ABUSEIPDB_KEY.startswith("PASTE_") or ABUSEIPDB_KEY == "":
        res = {"status":"no_api_key"}
        abuse_cache[ip] = res
        return res
    if is_private_ip(ip):
        res = {"status":"private_ip"}
        abuse_cache[ip] = res
        return res
    if abuse_queries >= MAX_ABUSE_QUERIES_PER_RUN:
        return {"status":"abuse_limit_reached"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept":"application/json","Key": ABUSEIPDB_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": maxAgeInDays}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
        abuse_queries += 1
        if r.status_code == 200:
            data = r.json()
            res = {"status":"ok","data": data.get("data",{})}
        elif r.status_code == 429:
            res = {"status":"rate_limited"}
        else:
            res = {"status":"error","http_status": r.status_code, "text": r.text[:400]}
    except Exception as e:
        res = {"status":"error","exception": str(e)}
    abuse_cache[ip] = res
    time.sleep(ABUSE_DELAY_SECONDS)
    return res

# ----------------- Signature retrieval (full cert info) -----------------
def get_signature_info(path):
    """
    Returns detailed signature info dict or None:
    { subject, issuer, not_before, not_after, thumbprint, serial }
    Uses PowerShell Get-AuthenticodeSignature and returns SignerCertificate fields via ConvertTo-Json.
    """
    if not path or not os.path.exists(path):
        return None
    # Build a PowerShell command that returns JSON with chosen fields (use -Compress for single-line)
    ps_cmd = (
        r"$c = (Get-AuthenticodeSignature '%s').SignerCertificate; "
        r"if ($c -ne $null) { "
        r"  [PSCustomObject]@{ Subject = $c.Subject; Issuer = $c.Issuer; NotBefore = $c.NotBefore.ToString('o'); NotAfter = $c.NotAfter.ToString('o'); Thumbprint = $c.Thumbprint; Serial = $c.SerialNumber } | ConvertTo-Json -Compress "
        r"} else { '' }"
    ) % path.replace("'", "''")  # escape single quotes in path

    try:
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                              capture_output=True, text=True, timeout=6)
        out = proc.stdout.strip()
        if not out:
            return None
        # Parse JSON output
        try:
            j = json.loads(out)
            # Normalize keys to strings
            return {
                "subject": j.get("Subject"),
                "issuer": j.get("Issuer"),
                "not_before": j.get("NotBefore"),
                "not_after": j.get("NotAfter"),
                "thumbprint": j.get("Thumbprint"),
                "serial": j.get("Serial")
            }
        except Exception:
            return None
    except Exception:
        return None

# ----------------- Main -----------------
def main():
    print("Starting enriched osquery hunter (signature detail mode)...")
    procs = run_osquery(QUERY)
    socks = run_osquery(SOCKETS_QUERY)
    socks_by_pid = defaultdict(list)
    for s in socks:
        pid_key = str(s.get("pid"))
        socks_by_pid[pid_key].append(s)

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "osqueryi": OSQUERYI,
        "processes": []
    }

    malicious_entries = []

    for idx, r in enumerate(procs, start=1):
        pid = str(r.get("pid",""))
        name = r.get("name","")
        path = r.get("path") or ""
        ppid = r.get("parent")
        start_time = r.get("start_time")
        lowername = (name or "").lower()
        lowerpath = (path or "").lower()
        conns = socks_by_pid.get(pid, [])

        entry = {
            "index": idx,
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "path": path,
            "start_time": start_time,
            "connections": conns,
            "flags": [],
            "sha256": None,
            "vt": None,
            "signature": None,
            "remote_ip_reputation": {}
        }

        # path anomalies
        if any(p in lowerpath for p in SUSP_PATHS):
            entry["flags"].append("writable/user path")
        if lowername in LOLBIN_NAMES:
            entry["flags"].append("lollbin")
        if ppid and str(ppid).lower() in SUSP_PARENTS:
            entry["flags"].append("suspicious parent")

        # signature (full cert info)
        sig = get_signature_info(path)
        if sig:
            entry["signature"] = sig
        else:
            # mark unsigned only if file exists and no signer
            if path and os.path.exists(path):
                entry["signature"] = {"subject": None, "issuer": None, "not_before": None, "not_after": None, "thumbprint": None, "serial": None}
                entry["flags"].append("unsigned")
            else:
                if path:
                    entry["flags"].append("path_missing")

        # file hash + VT (optional)
        if path and os.path.exists(path):
            sha = sha256_of_file(path)
            entry["sha256"] = sha
            if sha:
                vt = vt_lookup_hash(sha)
                entry["vt"] = vt
                if isinstance(vt, dict) and vt.get("status") == "ok":
                    stats = vt.get("stats",{})
                    if stats.get("malicious",0) > 0 or stats.get("suspicious",0) > 0:
                        entry["flags"].append("virus_total_positive")

        # network IP checks (optional)
        distinct_ips = set()
        for c in conns:
            ra = c.get("remote_address")
            if not ra:
                continue
            distinct_ips.add(ra)
            if is_private_ip(ra):
                entry["remote_ip_reputation"][ra] = {"status":"private_or_local"}
            else:
                abuse = abuseipdb_check(ra)
                entry["remote_ip_reputation"][ra] = abuse
                if isinstance(abuse, dict) and abuse.get("status") == "ok":
                    abusedata = abuse.get("data",{})
                    if abusedata.get("abuseConfidenceScore",0) >= 50 or abusedata.get("totalReports",0) > 0:
                        entry["flags"].append("abuseipdb_positive")

        entry["net_summary"] = {
            "sockets": len(conns),
            "established": sum(1 for c in conns if (c.get("state") or "").upper() == "ESTABLISHED" or not c.get("state")),
            "peers": len(distinct_ips)
        }

        report["processes"].append(entry)
        if entry["flags"]:
            malicious_entries.append(entry)

    # save JSON
    out_json = "osquery_hunter_enriched.json"
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"Full JSON report written to {out_json}")

    # generate HTML
    out_html = "osquery_hunter_enriched_dashboard.html"
    generate_html(report, malicious_entries, out_html)
    print(f"HTML dashboard written to {out_html}")

    # final console message
    if malicious_entries:
        print("\nMalicious/suspicious items found:")
        for e in malicious_entries:
            print(f" - pid={e['pid']} name={e['name']} path={e['path']} flags={e['flags']}")
        print("\nOpen the HTML dashboard to review details.")
    else:
        print("\nNo malicious or suspicious results found. Your computer is safe (based on this scan).")

# ----------------- HTML generation -----------------
def generate_html(report, malicious_entries, outfile):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    head = f"""
    <html><head><meta charset="utf-8"><title>osquery_hunter Enriched Dashboard (Signatures)</title>
    <style>
      body{{font-family:Arial,Helvetica,sans-serif;background:#f6f8fa;padding:20px}}
      h1{{color:#0b5ed7}}
      table{{width:100%;border-collapse:collapse;margin-top:16px}}
      th,td{{border:1px solid #ddd;padding:8px;text-align:left;font-size:13px;vertical-align:top}}
      th{{background:#0b5ed7;color:#fff}}
      tr.alt{{background:#f2f4f7}}
      .flag{{background:#fff4e5;color:#7a4b00;padding:4px 6px;border-radius:4px;font-weight:600}}
      pre{{background:#fff;padding:12px;border:1px solid #eee;overflow:auto}}
      .sigbox{{font-family:monospace;font-size:12px;background:#fff;padding:8px;border:1px solid #eee}}
      .summary{{margin-top:12px;padding:12px;background:#ffffff;border:1px solid #e6eef8}}
    </style>
    </head><body>
    <h1>osquery_hunter — Enriched Dashboard (Signatures)</h1>
    <p>Generated: {now}</p>
    """

    if not malicious_entries:
        body = f"""
        <div class="summary">
          <h2>Your computer is safe ✅</h2>
          <p>No suspicious file signatures, VirusTotal positives, or abusive remote IPs were found by this scan.</p>
          <p>Full JSON log: <code>osquery_hunter_enriched.json</code></p>
        </div>
        """
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(head + body + "</body></html>")
        return

    table_header = """
    <div class="summary"><h2>Malicious / Suspicious Findings</h2>
    <p>Rows below show items flagged by path, signers, VirusTotal or AbuseIPDB.</p></div>
    <table>
    <tr>
      <th>#</th><th>PID</th><th>Name</th><th>Path</th><th>Flags</th><th>Signature (subject / issuer / validity / thumbprint)</th><th>SHA256 (VT)</th><th>VT (M|S|U)</th><th>Remote IPs & Abuse</th>
    </tr>
    """

    rows_html = ""
    for i, e in enumerate(malicious_entries, 1):
        # VT cell formatting
        vtcell = ""
        if isinstance(e.get("vt"), dict):
            if e["vt"].get("status") == "ok":
                stats = e["vt"]["stats"]
                vtcell = f"M:{stats.get('malicious',0)} S:{stats.get('suspicious',0)} U:{stats.get('undetected',0)}"
            else:
                vtcell = html_mod.escape(str(e["vt"]))
        else:
            vtcell = html_mod.escape(str(e.get("vt","N/A")))

        # signature display
        sig = e.get("signature") or {}
        sig_display = "Unsigned"
        if isinstance(sig, dict) and sig.get("subject"):
            sig_display = (
                f"Subject: {sig.get('subject')}<br>"
                f"Issuer: {sig.get('issuer')}<br>"
                f"Valid: {sig.get('not_before')} → {sig.get('not_after')}<br>"
                f"Thumbprint: {sig.get('thumbprint')}<br>"
                f"Serial: {sig.get('serial')}"
            )

        # remote IPs summary
        remote_summary = []
        for ip, info in (e.get("remote_ip_reputation") or {}).items():
            if isinstance(info, dict) and info.get("status") == "ok":
                data = info.get("data",{})
                score = data.get("abuseConfidenceScore","?")
                reports = data.get("totalReports","?")
                remote_summary.append(f"{ip} (score={score},reports={reports})")
            else:
                remote_summary.append(f"{ip} ({html_mod.escape(str(info.get('status') if isinstance(info,dict) else info))})")
        remote_html = "<br>".join(remote_summary) if remote_summary else "—"

        flags_html = ", ".join(e.get("flags") or []) if isinstance(e.get("flags"), list) else (e.get("flags") or "")

        rows_html += f"""
        <tr class="{ 'alt' if i%2==0 else '' }">
          <td>{i}</td>
          <td>{html_mod.escape(e.get('pid',''))}</td>
          <td>{html_mod.escape(e.get('name',''))}</td>
          <td><small>{html_mod.escape(e.get('path',''))}</small></td>
          <td><span class="flag">{html_mod.escape(flags_html)}</span></td>
          <td class="sigbox">{sig_display}</td>
          <td style="font-family:monospace">{html_mod.escape(e.get('sha256') or '')}</td>
          <td>{html_mod.escape(vtcell)}</td>
          <td style="font-size:12px">{remote_html}</td>
        </tr>
        """

    tail = "</table></body></html>"
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(head + table_header + rows_html + tail)

# ----------------- Entry -----------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)
