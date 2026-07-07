import asyncio
import os
import struct
import time
from datetime import datetime
from bleak import BleakScanner

# CONFIGURATION
FORCE_THRESHOLD = 5
LOG_FILE = "perimeter_history.log"
PCAP_FILE = "bluetooth_capture.pcap"

# Internal tracking database: { mac_address: (first_seen_time, total_count) }
device_registry = {}

def initialize_pcap(filename):
    """Writes a standard PCAP global header (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256)"""
    if not os.path.exists(filename):
        # Global Header format: Magic Number (4B), Version Major (2B), Version Minor (2B),
        # Gmt to local correction (4B), Accuracy of timestamps (4B), Max length of captured packets (4B),
        # Data Link Type (4B: 256 for BLE Link Layer packets)
        global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 256)
        with open(filename, "wb") as f:
            f.write(global_header)

def write_to_pcap(filename, mac_address, rssi):
    """Constructs a custom pseudopacket with standard radio metadata and appends it to the PCAP file."""
    # Convert MAC address string "AA:BB:CC:DD:EE:FF" to 6-byte raw data array
    mac_bytes = bytes.fromhex(mac_address.replace(":", ""))
    
    # Fake a basic Bluetooth LE Advertising PDU channel body payload
    # PDU Header: Type 0 (ADV_IND), Length 6 bytes (just the MAC address)
    ble_pdu = struct.pack("<BB", 0x00, 0x06) + mac_bytes
    
    # Link-Layer Packet Packet Header wrapper expected by Wireshark
    # RF Channel (1 byte, e.g. Ch 37), Flags (1 byte), Event Counter (2 bytes)
    bt_le_phdr = struct.pack("<BBH", 37, 0x00, 0x00)
    packet_data = bt_le_phdr + ble_pdu
    
    # Calculate packet timestamps
    now = time.time()
    seconds = int(now)
    microseconds = int((now - seconds) * 1000000)
    pkt_len = len(packet_data)
    
    # Per-Packet Header: Timestamp seconds (4B), Microseconds (4B), Saved Length (4B), Original Length (4B)
    pcap_packet_header = struct.pack("<IIII", seconds, microseconds, pkt_len, pkt_len)
    
    with open(filename, "ab") as f:
        f.write(pcap_packet_header + packet_data)

def update_log_and_registry(mac_address, name, rssi):
    """Handles logic for registry lookups, metrics counts, and log writing."""
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    name_label = name if name else "Unknown Device"
    
    # If it's a completely new signature, initialize tracking markers
    if mac_address not in device_registry:
        device_registry[mac_address] = {
            "first_seen": current_time_str,
            "count": 1
        }
        first_seen_str = current_time_str
        seen_count = 1
        history_note = "[NEW ENTRY UNLOCKED]"
    else:
        # Otherwise, increment encounter counts and maintain historical origins
        device_registry[mac_address]["count"] += 1
        first_seen_str = device_registry[mac_address]["first_seen"]
        seen_count = device_registry[mac_address]["count"]
        history_note = f"[RETURNING TARGET - Seen {seen_count}x since {first_seen_str}]"
    
    # Build a clean log line item
    log_entry = (
        f"[{current_time_str}] MAC: {mac_address} | RSSI: {rssi:4d} dBm | "
        f"Name: {name_label:<20} | First Seen: {first_seen_str} | Total Encounters: {seen_count} {history_note}\n"
    )
    
    with open(LOG_FILE, "a") as log_f:
        log_f.write(log_entry)
        
    return log_entry.strip()

async def main():
    print("🛰️  Initializing Perimeter Defense Network Array...")
    initialize_pcap(PCAP_FILE)
    print(f"📁 PCAP dump routing to: {PCAP_FILE}")
    print(f"📁 Activity logging routing to: {LOG_FILE}\n")
    
    while True:
        # Initiate a 5-second radio sweep
                # Initiate a 5-second radio sweep
        # we use return_adv=True to get the advertisement data containing the RSSI
        devices_dict = await BleakScanner.discover(timeout=5.0, return_adv=True)
        device_count = len(devices_dict)
        
        print(f"\n--- 📡 Sweep Complete: {datetime.now().strftime('%H:%M:%S')} | Detected: {device_count} Signals ---")
        
        # devices_dict contains { mac_address: (BLEDevice, AdvertisementData) }
        for address, (dev, adv) in devices_dict.items():
            # Safely grab the RSSI from advertisement data
            rssi_val = adv.rssi if adv.rssi is not None else -100
            
            # Process logging metrics using the new rssi_val
            log_preview = update_log_and_registry(dev.address, dev.name, rssi_val)
            print(log_preview)
            
            # Commit tracking parameters to the raw PCAP file
            write_to_pcap(PCAP_FILE, dev.address, rssi_val)

            
        # Threat evaluation matrix assessment
        if device_count >= FORCE_THRESHOLD:
            print(f"🚨 ALERT: Force threshold breached ({device_count}/{FORCE_THRESHOLD} devices near)! Perimeter compromised!")
            print("\a")  # System audio alert ping
            
        await asyncio.sleep(2)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Perimeter monitoring deactivated safely.")
