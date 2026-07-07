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
    """Configures command line flags for flexible, site-specific deployment configurations."""
    parser = argparse.ArgumentParser(description="Unified Alpha Node: Dynamic HackRF Spike Detector & Ubertooth Harvester.")
    parser.add_argument("-w", "--whitelist", type=str, default=None, 
                        help="Path to text file containing MACs to ignore (one per line).")
    
    # Explicitly updated parameter switch to avoid device vs RF threshold ambiguity
    parser.add_argument("-b", "--ble-dev-threshold", type=int, default=5, 
                        help="Number of unknown Bluetooth devices required to breach perimeter (Default: 5).")
    
    parser.add_argument("-v", "--vendor-db", type=str, default=DEFAULT_VENDOR_DB, 
                        help=f"Path to local vendor JSON database file (Default: {DEFAULT_VENDOR_DB}).")
    parser.add_argument("-l", "--log", type=str, default=LOG_FILE, 
                        help=f"Path to output history text log file (Default: {LOG_FILE}).")
    parser.add_argument("-p", "--pcap", type=str, default=PCAP_FILE, 
                        help=f"Path to output packet capture PCAP file (Default: {PCAP_FILE}).")
    
    # HackRF Specific configuration arguments
    parser.add_argument("--rf-threshold", type=float, default=-50.0, 
                        help="HackRF signal power limit in dBm (Default: -50.0).")
    parser.add_argument("--freq-range", type=str, default="2400:2485", 
                        help="HackRF sweeping frequencies (Default: 2400:2485 for BT/Wi-Fi).")
    
    # Tailscale Remote Interface configuration
    parser.add_argument("--pi-ip", type=str, default="100.115.22.45",
                        help="Your Raspberry Pi's Tailscale IP address for remote OpenWebRX viewing.")
    return parser.parse_args()

# --- BLUETOOTH HARVESTING LAYER ---
def load_whitelist(filepath):
    """Parses user-supplied whitelist targets into a clean lookup memory hash."""
    global whitelist
    if not filepath or not os.path.exists(filepath): return
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            clean_mac = line.strip().replace(":", "").replace("-", "").upper()
            if clean_mac and not clean_mac.startswith("#"): 
                whitelist.add(clean_mac)

def check_vendor_db(filepath):
    """Loads the vendor database argument, auto-downloading from GitHub if needed."""
    global vendor_db
    if not os.path.exists(filepath) and filepath == DEFAULT_VENDOR_DB:
        try: 
            urllib.request.urlretrieve(VENDOR_DB_URL, DEFAULT_VENDOR_DB)
        except Exception: 
            return
    try:
        with open(filepath, "r", encoding="utf-8") as f: 
            vendor_db = json.load(f)
    except Exception: 
        pass

def update_log(mac_address, name, rssi, vendor, log_path, note=""):
    """Processes long-term threat analytics logging metrics."""
    curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lbl = name if name else "Broadcast Hidden"
    if mac_address not in device_registry:
        device_registry[mac_address] = {"first": curr_time, "count": 1}
        hist = f"[NEW ENTRY] {note}"
    else:
        device_registry[mac_address]["count"] += 1
        hist = f"[RETURNING - Count: {device_registry[mac_address]['count']}] {note}"
    
    entry = f"[{curr_time}] MAC: {mac_address} | RSSI: {rssi:4d} dBm | Vendor: {vendor:<25} | Name: {lbl:<20} | {hist}\n"
    with open(log_path, "a", encoding="utf-8") as f: 
        f.write(entry)
    return entry.strip()

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

async def bluetooth_harvester_loop(args):
    """Asynchronous background loop managing your BLE/Ubertooth data harvesting."""
    print("📡 Bluetooth Harvest Engine initialized.")
    while True:
        try:
            # We use return_adv=True to securely parse modern Bleak RSSI structures
            devices_dict = await BleakScanner.discover(timeout=5.0, return_adv=True)
            active_threats = {}
            for address, (dev, adv) in devices_dict.items():
                if address.replace(":", "").upper() in whitelist: 
                    continue
                active_threats[address] = (dev, adv)
            
            # Breach logic evaluated explicitly against the updated argument definition
            if len(active_threats) >= args.ble_dev_threshold:
                print(f"🚨 [BT ALERT] Perimeter breach! Count: {len(active_threats)} (Limit: {args.ble_dev_threshold})")
                print("\a")
                
            for address, (dev, adv) in active_threats.items():
                rssi = adv.rssi if adv.rssi is not None else -100
                v_name = vendor_db.get(address.replace(":", "")[:6].upper(), "Unknown Vendor")
                print(update_log(dev.address, dev.name, rssi, v_name, args.log))
                write_to_pcap(args.pcap, dev.address, rssi)
                
        except Exception as e:
            print(f"⚠️ Bluetooth error: {e}")
        await asyncio.sleep(2)

# --- PHYSICAL RF LAYER (HACKRF) WITH AUTONOMOUS PORT RELEASE ---
def run_hackrf_worker(args):
    """Synchronous subprocess reader handling rapid RF spectrum analysis sweeps with release protocol."""
    print(f"🛰️ HackRF Spectrum Guard active. Scanning Band: {args.freq_range} MHz")
    
    REMOTE_SDR_URL = f"http://{args.pi_ip}:8073"
    
    while True:
        cmd = ["hackrf_sweep", "-f", args.freq_range, "-r", "-"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        
        breach_detected = False
        
        for line in proc.stdout:
            parts = line.strip().split(', ')
            if len(parts) < 7: continue
            try:
                power_levels = [float(x) for x in parts[6:]]
                max_p = max(power_levels)
                
                # Check raw physical RF energy surges against profile limits
                if max_p > args.rf_threshold:
                    f_start = parts[1] # Extract the frequency region where the energy peaked
                    curr_t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    alert_msg = f"\n🚨 [RF BURST ALERT] Significant energy anomaly at {f_start} MHz ({max_p} dBm)!"
                    print(alert_msg)
                    print(f"🔗 INVESTIGATE LIVE WATERFALL IMMEDIATELY: {REMOTE_SDR_URL}")
                    
                    # Force energy logs directly into the consolidated trace file
                    with open(args.log, "a", encoding="utf-8") as f:
                        f.write(f"[{curr_t}] [RF COMPROMISE] Spiked to {max_p} dBm near {f_start} MHz\n")
                    
                    print("\a")
                    breach_detected = True
                    break # Break out of the file reader stream to terminate process execution
            except ValueError:
                continue
        
        # Kill the sweep tool process cleanly to completely release the hardware USB controller channel
        proc.terminate()
        proc.wait()
        
        if breach_detected:
            # Stand down scanning for 3 minutes to allow OpenWebRX Docker container to use the hardware
            print("⏳ Releasing HackRF hardware control to remote web interface for 180 seconds...")
            time.sleep(180)
            print("🔄 Stand-down window elapsed. Re-engaging automated spectrum guard...")

async def main():
    args = parse_arguments()
    load_whitelist(args.whitelist)
    check_vendor_db(args.vendor_db)
    initialize_pcap(args.pcap)
    
    print("🔒 Operational Perimeter Configuration finalized.")
    print(f"📝 Logging consolidated trace mapping to: {args.log}")
    print(f"📝 Bluetooth packet capture routing to: {args.pcap}")
    print(f"🚨 Target Constraints: {args.ble_dev_threshold} Device Limit | {args.rf_threshold} dBm RF Ceiling\n")
    
    # Spawn background executors concurrently
    loop = asyncio.get_running_loop()
    bt_task = asyncio.create_task(bluetooth_harvester_loop(args))
    
    # Run continuous blocking HackRF spectrum sweeps inside a background thread pool executor
    await loop.run_in_executor(None, run_hackrf_worker, args)
    await bt_task

if __name__ == "__main__":
    try: 
        asyncio.run(main())
    except KeyboardInterrupt: 
        print("\n🛑 Tactical Perimeter deactivated cleanly.")
