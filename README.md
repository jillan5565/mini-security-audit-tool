# Mini Security Audit Tool

A lightweight, portable Python-based security auditing utility designed to assess local host configuration, Windows Firewall status, and common sensitive open ports.

## Features
- **Host Reconnaissance**: Gathers OS metadata, kernel build, and machine hostname.
- **Firewall Audit**: Inspects active Windows Firewall state across all profiles via `netsh`.
- **Local Port Assessment**: Scans critical local network ports (FTP, SSH, Telnet, HTTP, RPC, SMB, RDP) for open listeners using TCP socket handshakes.
- **Automated Reporting**: Generates a clean, timestamped text report (`security_audit_report.txt`) summarizing findings.

## Requirements
- Windows OS
- Python 3.8+ (Uses standard libraries: `socket`, `subprocess`, `platform`)

## Usage
Run the script using Python:
```bash
python audit_tool.py