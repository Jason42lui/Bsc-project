import logging
import time
import tkinter as tk
import threading
from tkinter import scrolledtext, ttk
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
            log_file.write(f"Ethernet Type: {packet[Ether].type}\n")
        
        if packet.haslayer(IP):
            log_file.write(f"IP Source: {packet[IP].src} → IP Destination: {packet[IP].dst}\n")
            log_file.write(f"IP Version: {packet[IP].version}\n")
            log_file.write(f"IP Header Length: {packet[IP].ihl}\n")
            log_file.write(f"IP Type of Service: {packet[IP].tos}\n")
            log_file.write(f"IP Total Length: {packet[IP].len}\n")
            log_file.write(f"IP ID: {packet[IP].id}\n")
            log_file.write(f"IP Flags: {packet[IP].flags}\n")
            log_file.write(f"IP Fragment Offset: {packet[IP].frag}\n")
            log_file.write(f"IP TTL: {packet[IP].ttl}\n")
            log_file.write(f"IP Protocol: {packet[IP].proto}\n")
            log_file.write(f"IP Checksum: {packet[IP].chksum}\n")
            log_file.write(f"IP Options: {packet[IP].options}\n")
        
        if packet.haslayer(TCP):
            log_file.write("Protocol: TCP\n")
            log_file.write(f"Source Port: {packet[TCP].sport} → Destination Port: {packet[TCP].dport}\n")
            log_file.write(f"Sequence Number: {packet[TCP].seq}\n")
            log_file.write(f"Acknowledgment Number: {packet[TCP].ack}\n")
            log_file.write(f"Data Offset: {packet[TCP].dataofs}\n")
            log_file.write(f"Reserved: {packet[TCP].reserved}\n")
            log_file.write(f"Flags: {packet[TCP].flags}\n")
            log_file.write(f"Window Size: {packet[TCP].window}\n")
            log_file.write(f"Checksum: {packet[TCP].chksum}\n")
            log_file.write(f"Urgent Pointer: {packet[TCP].urgptr}\n")
            log_file.write(f"Options: {packet[TCP].options}\n")
        elif packet.haslayer(UDP):
            log_file.write("Protocol: UDP\n")
            log_file.write(f"Source Port: {packet[UDP].sport} → Destination Port: {packet[UDP].dport}\n")
            log_file.write(f"Length: {packet[UDP].len}\n")
            log_file.write(f"Checksum: {packet[UDP].chksum}\n")
        elif packet.haslayer(ICMP):
            log_file.write("Protocol: ICMP\n")
            log_file.write(f"ICMP Type: {packet[ICMP].type} Code: {packet[ICMP].code}\n")
            log_file.write(f"Checksum: {packet[ICMP].chksum}\n")
            if packet[ICMP].type == 0 or packet[ICMP].type == 8:  # Echo reply or request
                log_file.write(f"ID: {packet[ICMP].id}\n")
                log_file.write(f"Sequence: {packet[ICMP].seq}\n")
        elif packet.haslayer(ARP):
            log_file.write("Protocol: ARP\n")
            log_file.write(f"Hardware Type: {packet[ARP].hwtype}\n")
            log_file.write(f"Protocol Type: {packet[ARP].ptype}\n")
            log_file.write(f"Hardware Size: {packet[ARP].hwlen}\n")
            log_file.write(f"Protocol Size: {packet[ARP].plen}\n")
            log_file.write(f"Operation: {packet[ARP].op}\n")
            log_file.write(f"Sender MAC: {packet[ARP].hwsrc}\n")
            log_file.write(f"Sender IP: {packet[ARP].psrc}\n")
            log_file.write(f"Target MAC: {packet[ARP].hwdst}\n")
            log_file.write(f"Target IP: {packet[ARP].pdst}\n")
        else:
            log_file.write("Protocol: Other\n")
        
        # Log packet payload in hex format for better readability
        if packet.haslayer(Raw):
            log_file.write("Payload (Hex Dump):\n")

def update_log(text_widget, message):
    text_widget.after(0, lambda: text_widget.insert(tk.END, message + "\n"))
    text_widget.after(0, text_widget.see, tk.END)

def detect_attack(packet):
    global ip_counter, packet_tree
    global ip_counter
    current_time = time.time()
    packet_info = f"{packet.summary()}"
    log_packet(packet)
    add_packet_to_tree(packet)
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
        colors = plt.cm.Paired(np.linspace(0, 1, len(labels)))
        explode = [0.05] * len(labels)
        ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140,
                colors=colors, explode=explode, shadow=True, textprops={'fontsize': 12})
        ax1.set_title("Packet Distribution", fontsize=14)

    # --- Update Bar Chart (Packet Type Count) ---
    if not packet_counter:
        ax2.text(0.5, 0.5, "No Data", fontsize=14, ha='center', va='center')
    else:
        labels = list(packet_counter.keys())
        values = list(packet_counter.values())
        colors = plt.cm.Paired(np.linspace(0, 1, len(labels)))
        ax2.bar(labels, values, color=colors)
        ax2.set_title("Packet Type Distribution", fontsize=14)
        ax2.set_xlabel("Packet Type", fontsize=12)
        ax2.set_ylabel("Count", fontsize=12)
        ax2.tick_params(axis='x', rotation=45)

    # --- Update Histogram (Packet Size Distribution) ---
    if not packet_sizes:
        ax3.text(0.5, 0.5, "No Data", fontsize=14, ha='center', va='center')
    else:
        ax3.hist(packet_sizes, bins=20, color='blue', edgecolor='black')
        ax3.set_title("Packet Size Distribution", fontsize=14)
        ax3.set_xlabel("Packet Size (bytes)", fontsize=12)
        ax3.set_ylabel("Frequency", fontsize=12)

    # --- Update Bar Chart (Top 5 IP Addresses) ---
    if not ip_counter:
        ax4.text(0.5, 0.5, "No Data", fontsize=14, ha='center', va='center')
    else:
        sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        ips, counts = zip(*sorted_ips) if sorted_ips else ([], [])
        colors = plt.cm.Paired(np.linspace(0, 1, len(ips)))
        ax4.bar(ips, counts, color=colors)
        ax4.set_title("Top 5 IP Addresses", fontsize=14)
        ax4.set_xlabel("IP Address", fontsize=12)
        ax4.set_ylabel("Count", fontsize=12)
        ax4.set_xticklabels(ips, rotation=45, ha="right")
    canvas.draw()
    root.after(1000, update_graphs)


def create_ui():
    global alert_text, packet_text, ax1, ax2, ax3, ax4, canvas, root, attack_counts, packet_sizes, packet_tree, packet_details_text

    root = tk.Tk()
    root.title("Intrusion Detection System (IDS) Dashboard")
    root.geometry("1200x1000") 
    
    # Create a Notebook (tabbed interface)
    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both")

    # Create Frames for tabs
    tab1 = ttk.Frame(notebook)
    tab2 = ttk.Frame(notebook)
    
    # Top-Level Frame for Logs and Controls
    top_frame = tk.Frame(root, padx=10, pady=10)
    top_frame.pack(fill=tk.BOTH, expand=True)

    # --- Incoming Packets and Attack Alerts Section ---
    log_frame = tk.Frame(tab1, padx=10, pady=10)
    log_frame.pack(fill=tk.BOTH, expand=True)

    packet_frame = tk.LabelFrame(log_frame, text="Incoming Packets", font=("Arial", 12, "bold"), fg="blue")
    packet_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    packet_text = scrolledtext.ScrolledText(packet_frame, width=80, height=10, bg="black", fg="lime", font=("Courier", 10))
    packet_text.pack(fill=tk.BOTH, expand=True)
    
    alert_frame = tk.LabelFrame(log_frame, text="Attack Alerts", font=("Arial", 12, "bold"), fg="red")
    alert_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    alert_text = scrolledtext.ScrolledText(alert_frame, width=80, height=10, bg="black", fg="red", font=("Courier", 10))
    alert_text.pack(fill=tk.BOTH, expand=True)

    # Start Button (Bottom)
    button_frame = tk.Frame(tab1, pady=10)
    button_frame.pack()

    start_button = tk.Button(button_frame, text="Start IDS", font=("Arial", 12, "bold"), bg="green", fg="white", command=start_sniffing_thread)
    start_button.pack()

    # --- Graphs Layout ---
    graph_frame = tk.Frame(tab1, padx=10, pady=10, bg="#d3d3d3")
    graph_frame.pack(fill=tk.BOTH, expand=True)

    fig, (ax1, ax2, ax3, ax4) = plt.subplots(1, 4, figsize=(20, 5))
    fig.patch.set_facecolor('#d3d3d3') 
    fig.tight_layout(pad=4) 

    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # Data Tracking
    attack_counts = {}  # Dictionary to track attacks over time
    packet_sizes = []  # List to store packet sizes

    root.after(1000, update_graphs)

    # Add tabs to the notebook
    notebook.add(tab1, text="Dashboard")
    notebook.add(tab2, text="Packet List")

    # --- Packet List Layout ---
    packet_list_frame = tk.Frame(tab2, padx=10, pady=10)
    packet_list_frame.pack(fill=tk.BOTH, expand=True)

    # Left Panel - Treeview for Packet List
    packet_tree_frame = tk.Frame(packet_list_frame)
    packet_tree_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    packet_tree = ttk.Treeview(packet_tree_frame, columns=("Timestamp", "Source IP", "Destination IP", "Protocol", "Size", "Status"), show="headings")
    packet_tree.heading("Timestamp", text="Timestamp")
    packet_tree.heading("Source IP", text="Source IP")
    packet_tree.heading("Destination IP", text="Destination IP")
    packet_tree.heading("Protocol", text="Protocol")
    packet_tree.heading("Size", text="Size")
    packet_tree.heading("Status", text="Status")
    packet_tree.pack(fill=tk.BOTH, expand=True)

    packet_tree_scroll = ttk.Scrollbar(packet_tree_frame, orient="vertical", command=packet_tree.yview)
    packet_tree.configure(yscroll=packet_tree_scroll.set)
    packet_tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # Right Panel - Text Widget for Packet Details
    packet_details_frame = tk.Frame(packet_list_frame)
    packet_details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    packet_details_text = scrolledtext.ScrolledText(packet_details_frame, width=80, height=40, bg="black", fg="white", font=("Courier", 10))
    packet_details_text.pack(fill=tk.BOTH, expand=True)

    # Bind Treeview selection event
    packet_tree.bind("<<TreeviewSelect>>", on_packet_select)

    root.mainloop()

def on_packet_select(event):
    selected_item = packet_tree.selection()[0]
    packet_details = packet_tree.item(selected_item, "values")
    packet_details_text.delete(1.0, tk.END)
    details = f"Timestamp: {packet_details[0]}\nSource IP: {packet_details[1]}\nDestination IP: {packet_details[2]}\nProtocol: {packet_details[3]}\nSize: {packet_details[4]}\nStatus: {packet_details[5]}"
    packet_details_text.insert(tk.END, details)
    
    # Retrieve the full packet details from the log file
    with open(packet_log_file, "r") as log_file:
        lines = log_file.readlines()
        start_index = None
        for i, line in enumerate(lines):
            if f"Timestamp: {packet_details[0]}" in line:
                start_index = i
                break
        if start_index is not None:
            end_index = start_index + 1
            while end_index < len(lines) and lines[end_index].strip() != "=" * 80:
                end_index += 1
            full_details = "".join(lines[start_index:end_index])
            packet_details_text.insert(tk.END, "\n\nFull Packet Details:\n" + full_details)

def add_packet_to_tree(packet):
    """Adds packet details to the packet_tree in tab 2."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
    protocol = packet[IP].proto if packet.haslayer(IP) else "N/A"
    size = len(packet)
    status = "Normal"  # Default status, can be updated based on detection logic

    # Limit the number of packets shown in the treeview
    if len(packet_tree.get_children()) >= 100:
        packet_tree.delete(packet_tree.get_children()[0])

    packet_tree.insert("", "end", values=(timestamp, src_ip, dst_ip, protocol, size, status))

print("Starting IDS UI...")
create_ui()