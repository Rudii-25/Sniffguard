# sniffguard/core/scan_networks.py

import subprocess
import re
from utils.logger import log

def parse_iw_scan_output(output):
    """Parses the output of 'iw dev <interface> scan' to extract network details."""
    networks = {}
    current_bssid = None

    for line in output.split('\n'):
        bssid_match = re.search(r"BSS ([\da-fA-F:]{17})\(on", line)
        if bssid_match:
            current_bssid = bssid_match.group(1).upper()
            networks[current_bssid] = {"BSSID": current_bssid, "Security": "Open"} # Default to Open
            continue
            
        if current_bssid:
            signal_match = re.search(r"signal: (-?\d+\.\d+) dBm", line)
            if signal_match:
                networks[current_bssid]['Signal'] = signal_match.group(1)
            
            ssid_match = re.search(r"SSID: (.+)", line)
            if ssid_match:
                networks[current_bssid]['SSID'] = ssid_match.group(1).strip()

            channel_match = re.search(r"DS Parameter set: channel (\d+)", line)
            if channel_match:
                 networks[current_bssid]['Channel'] = channel_match.group(1)

            # More robust security detection
            if re.search(r"\s+WEP\s+", line):
                networks[current_bssid]['Security'] = "WEP"
            elif re.search(r"\s+WPA\s+", line): # Catches WPA, WPA2, WPA3 via RSN/WPA tags
                 networks[current_bssid]['Security'] = "WPA/WPA2/WPA3"
                    
    return list(networks.values())

def scan_networks(interface):
    """
    Scans for available wireless networks on the specified interface.
    
    Args:
        interface (str): The name of the interface in monitor mode.

    Returns:
        list: A list of dictionaries, each representing a detected network.
    """
    log.info(f"Starting network scan on interface '{interface}'.")
    try:
        # Using 'iw' as it is the modern standard
        result = subprocess.run(
            ['sudo', 'iw', 'dev', interface, 'scan'],
            capture_output=True, text=True, check=True
        )
        log.info("Network scan command executed successfully.")
        networks = parse_iw_scan_output(result.stdout)
        log.info(f"Scan parsed. Found {len(networks)} networks.")
        return networks
    except subprocess.CalledProcessError as e:
        log.error(f"Network scan failed on '{interface}'. Is it in monitor mode? Error: {e.stdout} {e.stderr}")
        return []
    except FileNotFoundError:
        log.error("Command 'iw' or 'sudo' not found. Please ensure wireless tools are installed.")
        return []