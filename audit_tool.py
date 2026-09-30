import os
import platform
import socket
import subprocess
from datetime import datetime

REPORT_FILE = "security_audit_report.txt"

def log_and_print(text, file_handle):
    print(text)
    file_handle.write(text + "\n")

def check_system_info(file_handle):
    log_and_print("=" * 50, file_handle)
    log_and_print("[+] 1. System Information", file_handle)
    log_and_print("=" * 50, file_handle)
    log_and_print(f"OS: {platform.system()} {platform.release()}", file_handle)
    log_and_print(f"Version: {platform.version()}", file_handle)
    log_and_print(f"Machine Hostname: {socket.gethostname()}", file_handle)
    log_and_print(f"Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", file_handle)

def check_firewall_status(file_handle):
    log_and_print("=" * 50, file_handle)
    log_and_print("[+] 2. Windows Firewall Status", file_handle)
    log_and_print("=" * 50, file_handle)
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True,
            text=True,
            check=True
        )
        log_and_print(result.stdout.strip() + "\n", file_handle)
    except Exception as e:
        log_and_print(f"[-] Could not check firewall: {e}\n", file_handle)

def check_open_ports(file_handle):
    log_and_print("=" * 50, file_handle)
    log_and_print("[+] 3. Local Common Ports Scan (Audit)", file_handle)
    log_and_print("=" * 50, file_handle)
    
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        135: "RPC",
        139: "NetBIOS",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP"
    }
    
    target_host = "127.0.0.1"
    open_ports_found = 0
    
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_host, port))
        if result == 0:
            log_and_print(f"[!] Warning: Port {port} ({service}) is OPEN on localhost.", file_handle)
            open_ports_found += 1
        sock.close()
        
    if open_ports_found == 0:
        log_and_print("[+] No sensitive common ports detected open on localhost.\n", file_handle)
    else:
        log_and_print(f"[*] Total sensitive open ports found: {open_ports_found}\n", file_handle)

def main():
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        log_and_print("##################################################", f)
        log_and_print("       MINI SECURITY AUDIT TOOL - REPORT          ", f)
        log_and_print("##################################################\n", f)
        
        check_system_info(f)
        check_firewall_status(f)
        check_open_ports(f)
        
        log_and_print("[✓] Audit completed successfully.", f)
        log_and_print(f"[✓] Full report saved to: {REPORT_FILE}", f)

if __name__ == "__main__":
    main()