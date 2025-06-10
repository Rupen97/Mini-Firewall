import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
import ctypes

# Packet rate threshold (packets/sec) to trigger IP blocking
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Function to check if the script is being run as administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Read IP addresses from a file and return as a set to avoid duplicates
def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file] 
    return set(ips)

# Function to detect the Nimda worm signature in HTTP GET requests
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload)
        return b"GET /scripts/root.exe" in payload  # Nimda worm signature
    return False

# Log a given event message with timestamp into a file under 'logs' folder
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

# Function to block an IP using Windows Firewall via netsh command
def block_ip_windows(ip, reason=""):
    print(f"Blocking IP: {ip} {reason}")
    os.system(f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in interface=any action=block remoteip={ip}')
    log_event(f"Blocked IP: {ip} {reason}")

# Callback function triggered for each captured packet
def packet_callback(packet):
    src_ip = packet[IP].src  # Extract source IP address

    # Skip if IP is in whitelist
    if src_ip in whitelist_ips:
        return

    # Immediately block if IP is blacklisted
    if src_ip in blacklist_ips:
        block_ip_windows(src_ip, "(blacklisted)")
        return
    
    # Block if Nimda worm signature is detected
    if is_nimda_worm(packet):
        block_ip_windows(src_ip, "(Nimda worm detected)")
        return

    # Count packets per IP to calculate traffic rate
    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    # Evaluate packet rate every second
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                block_ip_windows(ip, f"(Rate: {packet_rate:.2f} > {THRESHOLD})")
                blocked_ips.add(ip)

        # Reset counters and timer for the next interval
        packet_count.clear()
        start_time[0] = current_time

# Entry point of the script
if __name__ == "__main__":
    # Ensure script is run with administrative privileges
    if not is_admin():
        print("Please run this script as Administrator.")
        sys.exit(1)

    # Load IPs from whitelist and blacklist files
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    # Initialize data structures
    packet_count = defaultdict(int)  # Count of packets per IP
    start_time = [time.time()]       # Shared mutable timer
    blocked_ips = set()              # Track already blocked IPs

    print("Monitoring network traffic...")
    
    # Start sniffing IP packets and apply callback function
    sniff(filter="ip", prn=packet_callback)
