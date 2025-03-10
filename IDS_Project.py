import logging
import time
import tkinter as tk
import threading
from tkinter import scrolledtext
from collections import defaultdict
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw, hexdump
from prettytable import PrettyTable
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

packet_log_file = "detailed_packet_log.txt"

# Configure logging for packets
logging.basicConfig(
    filename="packets.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Configure logging for detected attacks
attack_logger = logging.getLogger("attack_logger")
attack_logger.setLevel(logging.WARNING)
attack_handler = logging.FileHandler("attacks.log")
attack_formatter = logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S")
attack_handler.setFormatter(attack_formatter)
attack_logger.addHandler(attack_handler)
attack_logger.addHandler(logging.StreamHandler())
attack_logger.propagate = False  

# Track attack occurrences
syn_counter = defaultdict(list)
icmp_counter = defaultdict(list)
udp_counter = defaultdict(list)
ip_counter = defaultdict(int)  # Add this globally
last_alert_time = defaultdict(lambda: 0) 
alert_cooldown = 5

# Initialize ARP cache
arp_cache = {}

# Track packet types
packet_counter = defaultdict(int)
packet_window = []

def should_log(ip, attack_type):
    """Returns True if enough time has passed since the last alert for this IP and attack type."""
    current_time = time.time()
    if current_time - last_alert_time[(ip, attack_type)] > alert_cooldown:
        last_alert_time[(ip, attack_type)] = current_time
        return True
    return False

def log_packet(packet):
    """Logs detailed packet information to a file in a human-readable format."""
    with open(packet_log_file, "a") as log_file:
        log_file.write("=" * 80 + "\n")
        log_file.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
        
        if packet.haslayer(Ether):
            log_file.write(f"MAC Source: {packet[Ether].src} → MAC Destination: {packet[Ether].dst}\n")
        
        if packet.haslayer(IP):
            log_file.write(f"IP Source: {packet[IP].src} → IP Destination: {packet[IP].dst}\n")
            log_file.write(f"Packet Length: {len(packet)} bytes\n")
        
        if packet.haslayer(TCP):
            log_file.write("Protocol: TCP\n")
            log_file.write(f"Source Port: {packet[TCP].sport} → Destination Port: {packet[TCP].dport}\n")
            log_file.write(f"Flags: {packet[TCP].flags}\n")
        elif packet.haslayer(UDP):
            log_file.write("Protocol: UDP\n")
            log_file.write(f"Source Port: {packet[UDP].sport} → Destination Port: {packet[UDP].dport}\n")
        elif packet.haslayer(ICMP):
            log_file.write("Protocol: ICMP\n")
            log_file.write(f"ICMP Type: {packet[ICMP].type} Code: {packet[ICMP].code}\n")
        elif packet.haslayer(ARP):
            log_file.write("Protocol: ARP\n")
            log_file.write(f"Operation: {packet[ARP].op}\n")
        else:
            log_file.write("Protocol: Other\n")
        
        # Log packet payload in hex format for better readability
        if packet.haslayer(Raw):
            log_file.write("Payload (Hex Dump):\n")
            log_file.write(hexdump(packet[Raw].load, dump=True) + "\n")
        
        log_file.write("=" * 80 + "\n\n")

def update_log(text_widget, message):
    text_widget.after(0, lambda: text_widget.insert(tk.END, message + "\n"))
    text_widget.after(0, text_widget.see, tk.END)

def detect_attack(packet):
    global ip_counter
    current_time = time.time()
    packet_info = f"{packet.summary()}"
    log_packet(packet)
    update_log(packet_text, packet_info)

    # Track packet types
    packet_window.append((current_time, packet))
    packet_window[:] = [(t, p) for t, p in packet_window if t > current_time - 60]
    packet_counter.clear()
    for _, p in packet_window:
        if p.haslayer(IP):
            ip_counter[p[IP].src] += 1
        if p.haslayer(TCP):
            packet_counter["TCP"] += 1
        elif p.haslayer(UDP):
            packet_counter["UDP"] += 1
        elif p.haslayer(ICMP):
            packet_counter["ICMP"] += 1
        elif p.haslayer(ARP):
            packet_counter["ARP"] += 1
        else:
            packet_counter["Other"] += 1
    
    # Track packet sizes
    if packet.haslayer(IP):
        packet_sizes.append(len(packet))

    # Detect SYN Flood
    if packet.haslayer(TCP):
        syn_counter[packet[IP].src].append(current_time)
        syn_counter[packet[IP].src] = [t for t in syn_counter[packet[IP].src] if t > current_time - 1]
        if len(syn_counter[packet[IP].src]) > 100 and should_log(packet[IP].src, "SYN Flood"):
            attack_msg = f"Potential SYN Flood detected from {packet[IP].src}"
            attack_logger.warning(attack_msg)
            update_log(alert_text, f"\n[ALERT] {attack_msg}\n")
    
    # Detect ICMP Flood
    if packet.haslayer(ICMP):
        icmp_counter[packet[IP].src].append(current_time)
        icmp_counter[packet[IP].src] = [t for t in icmp_counter[packet[IP].src] if t > current_time - 1]
        if len(icmp_counter[packet[IP].src]) > 100 and should_log(packet[IP].src, "Ping Flood"):
            attack_msg = f"Potential Ping Flood detected from {packet[IP].src}"
            attack_logger.warning(attack_msg)
            update_log(alert_text, f"\n[ALERT] {attack_msg}\n")
    
    # Detect UDP Flood
    if packet.haslayer(UDP):
        udp_counter[packet[IP].src].append(current_time)
        udp_counter[packet[IP].src] = [t for t in udp_counter[packet[IP].src] if t > current_time - 1]
        if len(udp_counter[packet[IP].src]) > 100 and should_log(packet[IP].src, "UDP Flood"):
            attack_msg = f"Potential UDP Flood detected from {packet[IP].src}"
            attack_logger.warning(attack_msg)
            update_log(alert_text, f"\n[ALERT] {attack_msg}\n")
    
    # Detect XMAS Scan
    if packet.haslayer(TCP) and packet[TCP].flags == 0x29:
        if should_log(packet[IP].src, "XMAS Scan"):
            attack_msg = f"Potential XMAS Scan detected from {packet[IP].src}"
            attack_logger.warning(attack_msg)
            update_log(alert_text, f"\n[ALERT] {attack_msg}\n")
    
    # Detect Ping of Death
    if packet.haslayer(ICMP) and len(packet) >= 65000:
        if should_log(packet[IP].src, "Ping of Death"):
            attack_msg = f"Potential Ping of Death detected from {packet[IP].src}"
            attack_logger.warning(attack_msg)
            update_log(alert_text, f"\n[ALERT] {attack_msg}\n")
    
    # Detect Teardrop Attack
    if packet.haslayer(IP) and packet.haslayer(Raw):
        ip_layer = packet.getlayer(IP)
        raw_layer = packet.getlayer(Raw)
        if ip_layer.flags == 1 and len(raw_layer.load) < 24:
            if should_log(packet[IP].src, "Teardrop Attack"):
                attack_msg = f"Potential Teardrop Attack detected from {packet[IP].src}"
                attack_logger.warning(attack_msg)
                update_log(alert_text, f"\n[ALERT] {attack_msg}\n")
    
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if "admin" in payload.lower() and "login" not in payload.lower():
            if should_log(packet[IP].src, "Unauthorized Access"):
                attack_msg = f"Unauthorized access attempt detected from {packet[IP].src}"
                attack_logger.warning(attack_msg)
                update_log(alert_text, f"\n[ALERT] {attack_msg}\n")

    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors="ignore")
        if "Authorization: Basic" in raw_data:
            if should_log(packet[IP].src, "Unencrypted Credentials"):
                attack_msg = f"Unencrypted credentials detected from {packet[IP].src}"
                attack_logger.warning(attack_msg)
                update_log(alert_text, f"\n[ALERT] {attack_msg}\n")

    sqli_patterns = ["' OR 1=1 --", "UNION SELECT", "DROP TABLE"]
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors="ignore")
        if any(pattern in raw_data for pattern in sqli_patterns):
            attack_msg = f"SQL Injection attempt detected from {packet[IP].src}"
            attack_logger.warning(attack_msg)
            update_log(alert_text, f"\n[ALERT] {attack_msg}\n")
            
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors="ignore")
        if "Authorization:" not in raw_data and "Cookie:" not in raw_data and "session" not in raw_data:
            if should_log(packet[IP].src, "Missing Authentication Header"):
                attack_msg = f"Missing authentication header detected from {packet[IP].src}"
                attack_logger.warning(attack_msg)
                update_log(alert_text, f"\n[ALERT] {attack_msg}\n")

def start_sniffing():
    sniff(iface="lo", prn=detect_attack, store=0)

def start_sniffing_thread():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

def update_graphs():
    """Updates all graphs in the IDS dashboard."""
    global packet_counter, attack_counts, packet_sizes
    
    ax1.clear()
    ax2.clear()
    ax3.clear()
    ax4.clear()
    
    # --- Update Pie Chart (Packet Distribution) ---
    if not packet_counter:
        ax1.text(0.5, 0.5, "No Data", fontsize=14, ha='center', va='center')
    else:
        labels = list(packet_counter.keys())
        sizes = list(packet_counter.values())
        colors = ['blue', 'green', 'red', 'purple', 'orange']
        explode = [0.05] * len(labels)
        ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140,
                colors=colors, explode=explode, shadow=True, textprops={'fontsize': 12})
        ax1.set_title("Packet Distribution", fontsize=14)

    # --- Update Bar Chart (Packet Type Count) ---
    if packet_counter:
        labels = list(packet_counter.keys())
        values = list(packet_counter.values())
        ax2.bar(labels, values, color=['blue', 'green', 'red', 'purple', 'orange'])
        ax2.set_title("Packet Type Distribution")
        ax2.set_xlabel("Packet Type")
        ax2.set_ylabel("Count")
    
    # --- Update Histogram (Packet Size Distribution) ---
    if packet_sizes:
        ax3.hist(packet_sizes, bins=20, color='blue', edgecolor='black')
        ax3.set_title("Packet Size Distribution")
        ax3.set_xlabel("Packet Size (bytes)")
        ax3.set_ylabel("Frequency")

    if ip_counter:
        sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        ips, counts = zip(*sorted_ips) if sorted_ips else ([], [])
        ax4.bar(ips, counts, color='red')
        ax4.set_title("Top 5 IP Addresses")
        ax4.set_xlabel("IP Address")
        ax4.set_ylabel("Count")
        ax4.set_xticklabels(ips, rotation=45, ha="right")
    
    canvas.draw()
    root.after(1000, update_graphs)  # Refresh graphs every second


def create_ui():
    global alert_text, packet_text, ax1, ax2, ax3, ax4, canvas, root, attack_counts, packet_sizes

    root = tk.Tk()
    root.title("Intrusion Detection System (IDS) Dashboard")
    root.geometry("1200x700")  # Set window size

    # Top-Level Frame for Logs and Controls
    top_frame = tk.Frame(root, padx=10, pady=10)
    top_frame.pack(fill=tk.BOTH, expand=True)

    # --- Incoming Packets Section ---
    packet_frame = tk.LabelFrame(top_frame, text="Incoming Packets", font=("Arial", 12, "bold"), fg="blue")
    packet_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    packet_text = scrolledtext.ScrolledText(packet_frame, width=80, height=10, bg="black", fg="lime", font=("Courier", 10))
    packet_text.pack(fill=tk.BOTH, expand=True)
    
    # --- Attack Alerts Section ---
    alert_frame = tk.LabelFrame(top_frame, text="Attack Alerts", font=("Arial", 12, "bold"), fg="red")
    alert_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    alert_text = scrolledtext.ScrolledText(alert_frame, width=80, height=10, bg="black", fg="red", font=("Courier", 10))
    alert_text.pack(fill=tk.BOTH, expand=True)

    # Start Button (Bottom)
    button_frame = tk.Frame(root, pady=10)
    button_frame.pack()

    start_button = tk.Button(button_frame, text="Start IDS", font=("Arial", 12, "bold"), bg="green", fg="white", command=start_sniffing_thread)
    start_button.pack()

    # --- Graphs Layout ---
    graph_frame = tk.Frame(root, padx=10, pady=10)
    graph_frame.pack(fill=tk.BOTH, expand=True)

    fig, (ax1, ax2, ax3, ax4) = plt.subplots(1, 4, figsize=(20, 5))
    fig.tight_layout(pad=4)  # Improve spacing

    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # Data Tracking
    attack_counts = {}  # Dictionary to track attacks over time
    packet_sizes = []  # List to store packet sizes

    root.after(1000, update_graphs)
    root.mainloop()
print("Starting IDS UI...")
create_ui()