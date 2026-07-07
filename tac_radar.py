import asyncio
import os
import json
import struct
import time
import argparse
from datetime import datetime
import urllib.request
from bleak import BleakScanner

# Default fallback files if arguments are omitted
DEFAULT_VENDOR_DB = "mac-vendors.json"
VENDOR_DB_URL = "https://githubusercontent.com"
LOG_FILE = "perimeter_history.log"
PCAP_FILE = "bluetooth_capture.pcap"

# System registries
device_registry = {}
vendor_db = {}
whitelist = set()

def parse_arguments():
    """Configures command line flags for flexible deployment configuration."""
    parser = argparse.ArgumentParser(description="Tactical BLE Perimeter Scan Array with Device Whitelisting.")
    
    parser.add_argument("-w", "--whitelist", type=str, default=None,
                        help="Path to a text file containing MAC addresses to ignore (one per line).")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                        help="Number of unknown devices required to breach the perimeter (Default: 5).")
    parser.add_argument("-v", "--vendor-db", type=str, default=DEFAULT_VENDOR_DB,
                        help=f"Path to local vendor JSON database file (Default: {DEFAULT_VENDOR_DB}).")
    parser.add_argument("-l", "--log", type=str, default=LOG_FILE,
                        help=f"Path to output history text log file (Default: {LOG_FILE}).")
    parser.add_argument("-p", "--pcap", type=str, default=PCAP_FILE,
                        help=f"Path to output packet capture PCAP file (Default: {PCAP_FILE}).")
                        
    return parser.parse_args()

def load_whitelist(filepath):
    """Parses user-supplied whitelist targets into a clean lookup memory hash."""
    global whitelist
    if not filepath:
        print("ℹ️  No whitelist file specified. Tracking all local airspace signals.")
        return
        
    if not os.path.exists(filepath):
        print(f"⚠️  Specified whitelist file not found: {filepath}. Proceeding with no exclusions.")
        return

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                clean_mac = line.strip().replace(":", "").replace("-", "").upper()
                if clean_mac and not clean_mac.startswith("#"): # Skip empty lines and comments
                    whitelist.add(clean_mac)
        print(f"🛡️  Loaded {len(whitelist)} trusted signatures into active exclusion whitelist.")
    except Exception as e:
        print(f"⚠️  Error reading whitelist configuration file: {e}")

def check_and_download_vendor_db(filepath):
    """Loads the vendor database argument, auto-downloading from GitHub if needed."""
    global vendor_db
    if not os.path.exists(filepath):
        # Only download if using the default expected local file name
        if filepath == DEFAULT_VENDOR_DB:
            print(f"📥 Vendor file missing. Fetching master reference schema from GitHub...")
            try:
                urllib.request.urlretrieve(VENDOR_DB_URL, DEFAULT_VENDOR_DB)
                print("✅ Master vendor reference file downloaded successfully.")
            except Exception as e:
                print(f"⚠️  Failed to download vendor database: {e}. Vendor mapping disabled.")
                return
        else:
            print(f"⚠️  Specified vendor file path not found: {filepath}. Vendor mapping disabled.")
            return

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            vendor_db = json.load(f)
            print(f"📖 Loaded {len(vendor_db)} registered hardware manufacturer prefixes.")
    except Exception as e:
        print(f"⚠️  Error reading vendor JSON file: {e}. Mapping disabled.")

def get_vendor_name(mac_address):
    """Resolves OUI signature markers cleanly."""
    oui_prefix = mac_address.replace(":", "")[:6].upper()
    return vendor_db.get(oui_prefix, "Unknown Hardware Vendor")

def initialize_pcap(filename):
    """Prepares raw PCAP global structures."""
    if not os.path.exists(filename):
        global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 256)
        with open(filename, "wb") as f:
            f.write(global_header)

def write_to_pcap(filename, mac_address, rssi):
    """Appends physical trace signals straight to disk arrays."""
    try:
        mac_bytes = bytes.fromhex(mac_address.replace(":", ""))
        ble_pdu = struct.pack("<BB", 0x00, 0x06) + mac_bytes
        bt_le_phdr = struct.pack("<BBH", 37, 0x00, 0x00)
        packet_data = bt_le_phdr + ble_pdu
        
        now = time.time()
        seconds = int(now)
        microseconds = int((now - seconds) * 1000000)
        pkt_len = len(packet_data)
        
        pcap_packet_header = struct.pack("<IIII", seconds, microseconds, pkt_len, pkt_len)
        with open(filename, "ab") as f:
            f.write(pcap_packet_header + packet_data)
    except Exception:
        pass

def update_log_and_registry(mac_address, name, rssi, vendor, log_path):
    """Processes long-term threat analytics logging metrics."""
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    name_label = name if name else "Broadcast Hidden"
    
    if mac_address not in device_registry:
        device_registry[mac_address] = {"first_seen": current_time_str, "count": 1}
        first_seen_str = current_time_str
        seen_count = 1
        history_note = "[NEW PERIMETER ENTRY]"
    else:
        device_registry[mac_address]["count"] += 1
        first_seen_str = device_registry[mac_address]["first_seen"]
        seen_count = device_registry[mac_address]["count"]
        history_note = f"[RETURNING TARGET - Count: {seen_count}]"
    
    log_entry = (
        f"[{current_time_str}] MAC: {mac_address} | RSSI: {rssi:4d} dBm | "
        f"Vendor: {vendor:<25} | Name: {name_label:<20} | First Seen: {first_seen_str} {history_note}\n"
    )
    
    with open(log_path, "a", encoding="utf-8") as log_f:
        log_f.write(log_entry)
        
    return log_entry.strip()

async def main():
    args = parse_arguments()
    
    print("🛰️  Initializing Modular Perimeter Defence System...")
    load_whitelist(args.whitelist)
    check_and_download_vendor_db(args.vendor_db)
    initialize_pcap(args.pcap)
    
    print(f"📁 PCAP dump destination: {args.pcap}")
    print(f"📁 Activity logging destination: {args.log}")
    print(f"🚨 Encroachment alarm threshold set to: {args.threshold} unknown devices\n")
    
    while True:
        devices_dict = await BleakScanner.discover(timeout=5.0, return_adv=True)
        
        # Filter incoming devices against the whitelist before counting threat level
        active_threats = {}
        for address, (dev, adv) in devices_dict.items():
            clean_addr = address.replace(":", "").upper()
            if clean_addr in whitelist:
                continue # Skip tracking and alerting entirely for whitelisted targets
            active_threats[address] = (dev, adv)
            
        threat_count = len(active_threats)
        print(f"\n--- 📡 Sweep Complete: {datetime.now().strftime('%H:%M:%S')} | Untrusted Airspace Signals: {threat_count} ---")
        
        for address, (dev, adv) in active_threats.items():
            rssi_val = adv.rssi if adv.rssi is not None else -100
            vendor_name = get_vendor_name(dev.address)
            
            log_preview = update_log_and_registry(dev.address, dev.name, rssi_val, vendor_name, args.log)
            print(log_preview)
            
            write_to_pcap(args.pcap, dev.address, rssi_val)
            
        # Breach conditions evaluate only against active non-whitelisted threats
        if threat_count >= args.threshold:
            print(f"🚨 ALERT: Threat threshold breached ({threat_count}/{args.threshold})! Perimeter compromised!")
            print("\a") 
            
        await asyncio.sleep(2)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Perimeter monitoring deactivated safely.")
