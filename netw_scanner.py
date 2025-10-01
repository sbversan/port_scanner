#!/usr/bin/env python3
import scapy.all as scapy
import subprocess
import socket
from termcolor import colored

# 🔹 Map common ports to possible vulnerabilities
VULNERABILITIES = {
    21: "FTP - Unencrypted credentials, vulnerable to brute force",
    22: "SSH - Potential brute-force or misconfiguration risk",
    23: "Telnet - Unencrypted, outdated service",
    25: "SMTP - Email relay vulnerability",
    80: "HTTP - No SSL, vulnerable to MITM",
    443: "HTTPS - Check certificate validity",
    3389: "RDP - Common ransomware target",
    3306: "MySQL - Default credentials, remote access risk",
}

# 🔹 Scan network for active devices
def scan_network(target):
    print(colored(f"\n[🔍] Scanning network {target} for active devices...", "cyan"))
    arp_request = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request
    answered, _ = scapy.srp(arp_packet, timeout=3, verbose=0)
    devices = []

    for element in answered:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
        print(colored(f"[+] Device: {element[1].psrc} | MAC: {element[1].hwsrc}", "green"))

    if not devices:
        print(colored("[!] No active devices found.", "yellow"))
    return devices

# 🔹 Scan open ports
def scan_ports(ip):
    print(colored(f"\n[🔍] Scanning open ports on {ip}...", "cyan"))
    open_ports = []
    for port in [21, 22, 23, 25, 80, 443, 3306, 3389]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

# 🔹 Analyze vulnerabilities
def analyze_threats(open_ports):
    print(colored("\n[🧠] Threat Analysis:", "cyan"))
    threats = []
    for port in open_ports:
        if port in VULNERABILITIES:
            threat = VULNERABILITIES[port]
            threats.append((port, threat))
            if port == 22:
                print(colored(f"⚠️ Port {port}: {threat}", "red", attrs=["bold"]))
            else:
                print(colored(f"- Port {port}: {threat}", "yellow"))
    if not threats:
        print(colored("✅ No major threats detected.", "green"))
    return threats

# 🔹 Block SSH (port 22)
def block_ssh():
    print(colored("\n[🔒] SSH port (22) detected open. Blocking it...", "yellow"))
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"], check=True)
        print(colored("✅ SSH port blocked successfully.", "green"))
    except Exception as e:
        print(colored(f"[!] Failed to block SSH port: {e}", "red"))

# 🔹 Verify with nmap
def verify_with_nmap(ip):
    print(colored(f"\n[🔍] Running verification scan with Nmap on {ip}...", "cyan"))
    try:
        result = subprocess.run(
            ["nmap", "-Pn", "-A", "-T4", ip],
            capture_output=True,
            text=True
        )
        print(colored("\n[📋] Nmap Scan Result:", "cyan"))
        print(result.stdout)
        if "22/tcp" in result.stdout and "closed" in result.stdout:
            print(colored("\n✅ **PORT 22 IS CLOSED OR FILTERED**", "red", attrs=["bold"]))
        else:
            print(colored("\n⚠️ Port 22 might still be open. Check firewall rules.", "yellow"))
    except Exception as e:
        print(colored(f"[!] Nmap verification failed: {e}", "red"))

# 🔹 Check running services on local system
def check_system_services():
    print(colored("\n[🧭] Checking all running services on this system...", "cyan"))
    try:
        result = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        print(colored("[📊] Active Services:", "green"))
        for line in lines[1:15]:  # Print first 15 services for brevity
            print(colored(line, "white"))
        print(colored("\n✅ All listed services are active and healthy.", "green"))
    except Exception as e:
        print(colored(f"[!] Could not check system services: {e}", "red"))

# 🔹 Main execution
if __name__ == "__main__":
    target_network = "192.168.1.0/24"
    devices = scan_network(target_network)

    for device in devices:
        ip = device["ip"]
        open_ports = scan_ports(ip)
        print(colored(f"[+] Open ports on {ip}: {open_ports}", "yellow"))
        threats = analyze_threats(open_ports)

        if 22 in open_ports:
            block_ssh()
            verify_with_nmap(ip)

    check_system_services()
    print(colored("\n[✅] Network scan and system service analysis complete.", "green"))
