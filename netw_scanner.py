#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp
import socket
import subprocess
from termcolor import colored

# Common ports and their threats
PORT_THREATS = {
    22: "SSH - may allow unauthorized remote access if weak credentials are used.",
    21: "FTP - transmits data in plain text, vulnerable to sniffing and brute force.",
    23: "Telnet - insecure protocol; sends credentials unencrypted.",
    25: "SMTP - may be abused for spam or open relay attacks.",
    80: "HTTP - unencrypted web traffic; may expose sensitive data.",
    443: "HTTPS - generally safe, but can host vulnerable web apps.",
    3389: "RDP - may allow remote desktop attacks if exposed."
}

def scan_network(target):
    print(colored(f"\n[+] Scanning network: {target}", "cyan"))
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_ports(ip):
    open_ports = []
    for port in PORT_THREATS.keys():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def list_open_ports(devices):
    print(colored("\n[+] Listing all open ports and possible threats:", "yellow"))
    found_ports = set()
    for device in devices:
        for port in device.get('ports', []):
            found_ports.add(port)

    if not found_ports:
        print(colored("✅ No open ports detected across the network.", "green"))
    else:
        for port in sorted(found_ports):
            threat = PORT_THREATS.get(port, "Unknown service")
            print(colored(f"  • Port {port}: {threat}", "red"))

def analyze_threats(devices):
    print(colored("\n[+] Analyzing threats...\n", "yellow"))
    threats = []
    critical_threats = []

    for device in devices:
        ip = device['ip']
        ports = device.get('ports', [])
        print(f"Device {ip} has open ports: {ports}")

        for port in ports:
            if port == 22:
                threats.append(f"SSH (22) open on {ip} — may allow unauthorized access.")
                critical_threats.append(22)
            elif port == 23:
                threats.append(f"Telnet (23) open on {ip} — insecure protocol.")
                critical_threats.append(23)
            elif port == 3389:
                threats.append(f"RDP (3389) open on {ip} — vulnerable to remote desktop attacks.")
                critical_threats.append(3389)

    if threats:
        print("\nDetected Threats:")
        for t in threats:
            print(colored(f"  • {t}", "red"))

    if 22 in critical_threats:
        print(colored("\n⚠️  Critical: SSH port (22) is a high-risk vulnerability!", "red", attrs=["bold"]))
    return critical_threats

def block_ssh():
    print(colored("\n[+] Blocking SSH port (22)...", "yellow"))
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"], check=True)
        print(colored("✅ SSH port (22) was successfully blocked!", "green"))
    except subprocess.CalledProcessError:
        print(colored("❌ Failed to block SSH port. Run with sudo privileges.", "red"))

def verify_block(ip_address):
    print(colored(f"\n[+] Verifying SSH port block with nmap on {ip_address} ...", "cyan"))
    try:
        # Optimized Nmap scan
        result = subprocess.run(
            ["nmap", "-Pn", "-A", "-T4", "-p", "22", ip_address],
            capture_output=True,
            text=True
        )
        print(colored("\n[+] Nmap verification result:", "yellow"))
        print(result.stdout)

        if "22/tcp closed" in result.stdout or "22/tcp filtered" in result.stdout:
            print(colored("\n🔒 ✅ **PORT 22 IS NOW CLOSED OR FILTERED**", "red", attrs=["bold"]))
        else:
            print(colored("\n❌ SSH port 22 appears to still be open. Recheck firewall settings!", "red", attrs=["bold"]))
    except Exception as e:
        print(colored(f"❌ Error running nmap: {e}", "red"))

if __name__ == "__main__":
    target_network = "192.168.1.0/24"
    target_ip = "192.168.1.2/32"  # Specific host for verification

    devices = scan_network(target_network)

    print(colored(f"\n[+] Found {len(devices)} active devices:\n", "green"))
    for device in devices:
        print(f"IP: {device['ip']} \t MAC: {device['mac']}")
        ports = scan_ports(device['ip'])
        device['ports'] = ports

    # Step 1: List all open ports and their threats
    list_open_ports(devices)

    # Step 2: Analyze per-device threats
    critical_threats = analyze_threats(devices)

    # Step 3: If SSH port found, block it and verify
    if 22 in critical_threats:
        block_ssh()
        verify_block(target_ip)
    else:
        print(colored("\n✅ No SSH vulnerabilities detected. Network is safe.", "green"))
