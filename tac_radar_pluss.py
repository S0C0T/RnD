import asyncio
import os
import json
import struct
import time
import argparse
import subprocess
from datetime import datetime
import urllib.request
from bleak import BleakScanner

# FALLBACK DEFAULTS
DEFAULT_VENDOR_DB = "mac-vendors.json"
VENDOR_DB_URL = "https://githubusercontent.com"
LOG_FILE = "perimeter_history.log"
PCAP_FILE = "bluetooth_capture.pcap"

device_registry = {}
vendor_db = {}
whitelist = set()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Unified Alpha Node: Dynamic HackRF Spike Detector & Ubertooth Harvester.")
    parser.add_argument("-w", "--whitelist", type=str, default=None, help="Path to text file containing MACs to ignore.")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Bluetooth device anomaly threshold (Default: 5).")
    parser.add_argument("-v", "--vendor-db", type=str, default=DEFAULT_VENDOR_DB, help="Path to vendor JSON file.")
    parser.add_argument("-l", "--log", type=str, default=LOG_FILE, help="Path to output text log.")
    parser.add_argument("-p", "--pcap", type=str, default=PCAP_FILE, help="Path to output packet capture PCAP.")
    
    # New HackRF explicit arguments
    parser.add_argument("--rf-threshold", type=float, default=-50.0, help="HackRF signal power limit in dBm (Default: -50.0).")
    parser.add_argument("--freq-range", type=str, default="2400:2485", help="HackRF sweeping frequencies (Default: 2400:2485 for BT/Wi-Fi).")
    return parser.parse_args()

# --- BLUETOOTH SYSTEMS ---
def load_whitelist(filepath):
    global whitelist
    if not filepath or not os.path.exists(filepath): return
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            clean_mac = line.strip().replace(":", "").replace("-", "").upper()
            if clean_mac and not clean_mac.startswith("#"): whitelist.add(clean_mac)

def check_vendor_db(filepath):
    global vendor_db
    if not os.path.exists(filepath) and filepath == DEFAULT_VENDOR_DB:
        try: urllib.request.urlretrieve(VENDOR_DB_URL, DEFAULT_VENDOR_DB)
        except Exception: return
    try:
        with open(filepath, "r", encoding="utf-8") as f: vendor_db = json.load(f)
    except Exception: pass

def update_log(mac_address, name, rssi, vendor, log_path, note=""):
    curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lbl = name if name else "Broadcast Hidden"
    if mac_address not in device_registry:
        device_registry[mac_address] = {"first": curr_time, "count": 1}
        hist = f"[NEW ENTRY] {note}"
    else:
        device_registry[mac_address]["count"] += 1
        hist = f"[RETURNING - Count: {device_registry[mac_address]['count']}] {note}"
    
    entry = f"[{curr_time}] MAC: {mac_address} | RSSI: {rssi:4d} dBm | Vendor: {vendor:<25} | Name: {lbl:<20} | {hist}\n"
    with open(log_path, "a", encoding="utf-8") as f: f.write(entry)
    return entry.strip()

async def bluetooth_harvester_loop(args):
    """Asynchronous background loop managing your BLE/Ubertooth data harvesting."""
    print("📡 Bluetooth Harvest Engine initialized.")
    while True:
        try:
            devices_dict = await BleakScanner.discover(timeout=5.0, return_adv=True)
            active_threats = {}
            for address, (dev, adv) in devices_dict.items():
                if address.replace(":", "").upper() in whitelist: continue
                active_threats[address] = (dev, adv)
            
            if len(active_threats) >= args.threshold:
                print(f"🚨 [BT ALERT] Perimeter breach! Count: {len(active_threats)}")
                print("\a")
                
            for address, (dev, adv) in active_threats.items():
                rssi = adv.rssi if adv.rssi is not None else -100
                v_name = vendor_db.get(address.replace(":", "")[:6].upper(), "Unknown Vendor")
                print(update_log(dev.address, dev.name, rssi, v_name, args.log))
                
        except Exception as e:
            print(f"⚠️ Bluetooth error: {e}")
        await asyncio.sleep(2)

# --- HACKRF ENGINE ---
def run_hackrf_worker(args):
    """Synchronous subprocess reader handling rapid RF environment testing."""
    print(f"🛰️ HackRF Spectrum Guard active. Target: {args.freq_range} MHz")
    cmd = ["hackrf_sweep", "-f", args.freq_range, "-r", "-"]
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            parts = line.strip().split(', ')
            if len(parts) < 7: continue
            try:
                power_levels = [float(x) for x in parts[6:]]
                max_p = max(power_levels)
                
                if max_p > args.rf_threshold:
                    f_start, f_end = parts[2], parts[3]
                    curr_t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alert_msg = f"🚨 [RF BURST ALERT] Significant energy anomaly at {f_start}MHz ({max_p} dBm)!"
                    print(alert_msg)
                    
                    # Log raw RF breaches directly into your primary file
                    with open(args.log, "a", encoding="utf-8") as f:
                        f.write(f"[{curr_t}] [RF COMPROMISE] Spiked to {max_p} dBm near {f_start}MHz\n")
                    print("\a")
                    time.sleep(1) # Prevent signal spamming
            except ValueError:
                continue
    except FileNotFoundError:
        print("❌ System Error: 'hackrf_sweep' binary is missing. Install via 'sudo apt install hackrf'")

async def main():
    args = parse_arguments()
    load_whitelist(args.whitelist)
    check_vendor_db(args.vendor_db)
    
    print("🔒 Operational Perimeter Configuration finalized.")
    print(f"📝 Logging consolidated history to: {args.log}")
    
    # Launch the Bluetooth loop as an async task, run HackRF in an isolated thread executor
    loop = asyncio.get_running_loop()
    bt_task = asyncio.create_task(bluetooth_harvester_loop(args))
    
    # Run the continuous blocking HackRF read loop in the background thread pool
    await loop.run_in_executor(None, run_hackrf_worker, args)
    await bt_task

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\n🛑 Defensive Node deactivated cleanly.")
