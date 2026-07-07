import asyncio
import os
import json
import struct
import time
from datetime import datetime
import urllib.request
from bleak import BleakScanner

# CONFIGURATION
FORCE_THRESHOLD = 5
LOG_FILE = "perimeter_history.log"
PCAP_FILE = "bluetooth_capture.pcap"
VENDOR_DB_FILE = "mac-vendors.json"
VENDOR_DB_URL = "https://githubusercontent.com"

# Internal tracking database: { mac_address: (first_seen_time, total_count) }
device_registry = {}
vendor_db = {}

def check_and_download_vendor_db():
    """Checks for the local vendor JSON file. Downloads it from GitHub if missing."""
    global vendor_db
    if not os.path.exists(VENDOR_DB_FILE):
        print(f"📥 Vendor database missing. Fetching master reference file from GitHub...")
        try:
            urllib.request.urlretrieve(VENDOR_DB_URL, VENDOR_DB_FILE)
            print("✅ Vendor reference database downloaded successfully.")
        except Exception as e:
            print(f"⚠️ Failed to download vendor database: {e}. Proceeding with 'Unknown' vendor fallbacks.")
            vendor_db = {}
            return

    try:
        with open(VENDOR_DB_FILE, "r", encoding="utf-8") as f:
            vendor_db = json.load(f)
            print(f"📖 Loaded {len(vendor_db)} registered hardware manufacturer prefixes.")
    except Exception as e:
        print(f"⚠️ Error reading vendor JSON file: {e}. Vendor mapping disabled.")
        vendor_db = {}

def get_vendor_name(mac_address):
    """Extracts the OUI prefix (first 6 hex chars) and resolves the vendor name."""
    # Convert "AA:BB:CC:DD:EE:FF" -> "AABBCC"
    oui_prefix = mac_address.replace(":", "")[:6].upper()
    # Look up prefix in the dictionary database
    return vendor_db.get(oui_prefix, "Unknown Hardware Vendor")

def initialize_pcap(filename):
    """Writes a standard PCAP global header (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256)"""
    if not os.path.exists(filename):
        global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 256)
        with open(filename, "wb") as f:
            f.write(global_header)

def write_to_pcap(filename, mac_address, rssi):
    """Constructs a custom pseudopacket with standard radio metadata and appends it to the PCAP file."""
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
        pass # Catch anomalies caused by randomized or malformed local MAC addresses

def update_log_and_registry(mac_address, name, rssi, vendor):
    """Handles logic for registry lookups, metrics counts, and log writing."""
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    name_label = name if name else "Broadcast Hidden"
    
    if mac_address not in device_registry:
        device_registry[mac_address] = {
            "first_seen": current_time_str,
            "count": 1
        }
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
    
    with open(LOG_FILE, "a", encoding="utf-8") as log_f:
        log_f.write(log_entry)
        
    return log_entry.strip()

async def main():
    print("🛰️  Initializing Enhanced Perimeter Defense Network Array...")
    check_and_download_vendor_db()
    initialize_pcap(PCAP_FILE)
    
    print(f"📁 PCAP stream mapping to: {PCAP_FILE}")
    print(f"📁 Activity logging mapping to: {LOG_FILE}\n")
    
    while True:
        # Initiate a 5-second radio sweep extracting active advertisement packages
        devices_dict = await BleakScanner.discover(timeout=5.0, return_adv=True)
        device_count = len(devices_dict)
        
        print(f"\n--- 📡 Sweep Complete: {datetime.now().strftime('%H:%M:%S')} | Airspace Signals: {device_count} ---")
        
        for address, (dev, adv) in devices_dict.items():
            # Extract corrected signal strength from advertising payload metadata
            rssi_val = adv.rssi if adv.rssi is not None else -100
            
            # Cross-reference hardware signature with vendor database definitions
            vendor_name = get_vendor_name(dev.address)
            
            # Append track history metrics and output live trace telemetry
            log_preview = update_log_and_registry(dev.address, dev.name, rssi_val, vendor_name)
            print(log_preview)
            
            # Commit raw packet tracking structures to the PCAP buffer
            write_to_pcap(PCAP_FILE, dev.address, rssi_val)
            
        # Threat evaluation validation matrix
        if device_count >= FORCE_THRESHOLD:
            print(f"🚨 ALERT: Force threshold breached ({device_count}/{FORCE_THRESHOLD} devices near)! Perimeter compromised!")
            print("\a") # Sound a physical system terminal alert ping
            
        await asyncio.sleep(2)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Perimeter monitoring deactivated safely.")
