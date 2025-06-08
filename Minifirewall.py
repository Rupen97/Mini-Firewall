import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
import ctypes

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# checking if script is run as administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file] 
    return set(ips)  # to eliminate any duplication

def is_nimda_worm(packet):
    # checking for TCP layer and destination is 80 which is usually http
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        # extracting payload from the TCP layer
        payload = bytes(packet[TCP].payload)
        return b"GET /scripts/root.exe" in payload
    return False

def log_event(message):
    log_folder = "logs"

    # create the log folder and update if already exists
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

def block_ip_windows(ip, reason=""):
    print(f"Blocking IP: {ip} {reason}")
    os.system(f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in interface=any action=block remoteip={ip}')
    log_event(f"Blocked IP: {ip} {reason}")

def packet_callback(packet):
    src_ip = packet[IP].src

    # Check if IP is in the whitelist
    if src_ip in whitelist_ips:
        return

    # Check if IP is in the blacklist
    if src_ip in blacklist_ips:
        block_ip_windows(src_ip, "(blacklisted)")
        return
    
    # Check for Nimda worm signature
    if is_nimda_worm(packet):
        block_ip_windows(src_ip, "(Nimda worm detected)")
        return

    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                block_ip_windows(ip, f"(Rate: {packet_rate:.2f} > {THRESHOLD})")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

        

if __name__ == "__main__":
    # Windows admin check
    if not is_admin():
        print("Please run this script as Administrator.")
        sys.exit(1)

    # Import whitelist and blacklist IPs
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)
