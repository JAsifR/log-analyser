# Advanced Security Log Analyser

A cybersecurity log analysis tool that parses web server logs to detect attacks, suspicious IPs and malicious activity. Generates professional HTML and CSV security reports.

## Features
- Detects SQL injection, XSS, directory traversal, command injection, Log4Shell, Shellshock and brute force attacks
- Identifies malicious user agents (sqlmap, nikto, nmap, metasploit and more)
- Risk scores each IP from 0-100 based on behaviour
- Geolocates suspicious IPs with VPN/proxy detection
- Brute force detection with threshold alerts
- Supports real log files or built-in sample logs
- Generates dark-themed HTML security report viewable in browser
- Exports CSV for further analysis

## Technologies
- Python 3
- re, collections, csv, datetime
- requests (geolocation)

## Usage
```bash
pip install requests
python logs.py
```

## Skills Demonstrated
- Cybersecurity threat detection and log analysis
- Pattern matching with regex
- Risk scoring and threat intelligence
- Professional report generation (HTML/CSS)
- SOC analyst skills
