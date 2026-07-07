import subprocess
import re
import sys
import os
import time

# --- CONFIGURATION ---
# Scan the standard 2.4GHz ISM band where phones, Bluetooth, and Wi-Fi live
FREQ_MIN = 2400 
FREQ_MAX = 2485

# TRIGGER THRESHOLD (in dB). 
# At a quiet night location, background noise might sit around -70 to -80 dB.
# A phone transmitting close by will spike this to -40 or -30 dB.
POWER_THRESHOLD = -50.0 

print(f"🛰️  HackRF RF Perimeter Watch Active... Monitoring {FREQ_MIN}MHz - {FREQ_MAX}MHz")
print("🔒 Calibrating to quiet night baseline. Watching for abnormal spikes...")

# Execute the native high-speed HackRF sweep tool
# -f sets frequency range, -r outputs raw text data to our script
cmd = ["hackrf_sweep", "-f", f"{FREQ_MIN}:{FREQ_MAX}", "-r", "-"]

try:
    # Open the process and stream the live spectrum data line by line
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    
    for line in process.stdout:
        # Expected format from hackrf_sweep: [Timestamp, Freq_Start, Freq_End, DB_Power_Levels...]
        parts = line.strip().split(', ')
        if len(parts) < 7:
            continue
            
        # Extract the signal power levels reported in this specific sweep block
        try:
            power_levels = [float(x) for x in parts[6:]]
            max_power = max(power_levels)
            
            # Catch abnormal energy spikes breaching our profile threshold
            if max_power > POWER_THRESHOLD:
                current_time = time.strftime('%H:%M:%S')
                print(f"🚨 [ALERT {current_time}] Target Close Proximity Transmission!")
                print(f"   ↳ Max Energy Detected: {max_power} dBm (Threshold: {POWER_THRESHOLD} dBm)")
                
                # Trigger system beep or execution script here
                print("\a")
                time.sleep(1) # Prevent alert spamming
                
        except ValueError:
            continue

except KeyboardInterrupt:
    print("\n🛑 RF Perimeter watch deactivated safely.")
    sys.exit(0)
except FileNotFoundError:
    print("❌ Error: 'hackrf_sweep' tool not found. Please install hackrf tools using: sudo apt install hackrf")
