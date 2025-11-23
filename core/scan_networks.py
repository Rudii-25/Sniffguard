# sniffguard/core/scan_networks.py

import subprocess
import re
from utils.logger import log

def parse_iw_scan_output(output):
    """Parses the output of the modern 'iw' command."""
    networks = {}
    current_bssid = None
    bssid_re = re.compile(r"^BSS ([\da-fA-F:]{17})")
    signal_re = re.compile(r"\s+signal: (-?\d+\.\d+) dBm")
    ssid_re = re.compile(r"\s+SSID: (.+)")
    channel_re = re.compile(r"\s+\* primary channel: (\d+)|DS Parameter set: channel (\d+)")
    security_re = re.compile(r"(WPA|RSN) Information:")
    privacy_re = re.compile(r"\s+Privacy:\s+(on|true)")

    for line in output.split('\n'):
        bssid_match = bssid_re.search(line)
        if bssid_match:
            current_bssid = bssid_match.group(1).upper()
            networks[current_bssid] = {"BSSID": current_bssid, "Security": "Open"}
            continue
        if not current_bssid: continue
        
        # ... (rest of the parsing logic for 'iw' is the same)
        signal_match = signal_re.search(line); ssid_match = ssid_re.search(line); channel_match = channel_re.search(line)
        if signal_match: networks[current_bssid]['Signal'] = signal_match.group(1); continue
        if ssid_match: networks[current_bssid]['SSID'] = ssid_match.group(1).strip(); continue
        if channel_match:
            channel = channel_match.group(1) or channel_match.group(2)
            networks[current_bssid]['Channel'] = channel; continue
        if security_re.search(line): networks[current_bssid]['Security'] = "WPA/WPA2/WPA3"; continue
        elif privacy_re.search(line):
             if networks[current_bssid]['Security'] == "Open": networks[current_bssid]['Security'] = "WEP"

    return [net for net in networks.values() if 'SSID' in net]


def parse_iwlist_scan_output(output):
    """
    Parses the output of the fallback 'iwlist' command.
    This is for older drivers or those that don't support 'iw scan'.
    """
    log.info("Parsing output from fallback 'iwlist' command.")
    networks = {}
    # Regex for iwlist is different
    bssid_re = re.compile(r"Address: ([\da-fA-F:]{17})")
    channel_re = re.compile(r"Channel:(\d+)")
    signal_re = re.compile(r"Signal level=(-?\d+) dBm")
    ssid_re = re.compile(r'ESSID:"(.+)"')
    encryption_re = re.compile(r"Encryption key:(on|off)")
    wpa_re = re.compile(r"IE: IEEE 802.11i/WPA2 Version 1|IE: WPA Version 1")

    # Split output into blocks for each access point
    ap_blocks = output.split("Cell ")
    for block in ap_blocks[1:]: # First block is header, skip it
        bssid_match = bssid_re.search(block)
        if not bssid_match: continue

        bssid = bssid_match.group(1).upper()
        networks[bssid] = {"BSSID": bssid}

        ssid_match = ssid_re.search(block)
        if ssid_match: networks[bssid]['SSID'] = ssid_match.group(1)
        else: continue # Skip if no SSID

        channel_match = channel_re.search(block)
        if channel_match: networks[bssid]['Channel'] = channel_match.group(1)

        signal_match = signal_re.search(block)
        if signal_match: networks[bssid]['Signal'] = signal_match.group(1) # Signal is already integer dBm
        
        security = "Open"
        encryption_match = encryption_re.search(block)
        if encryption_match and encryption_match.group(1) == "on":
            security = "WEP" # Assume WEP if encryption is on but no WPA found
            if wpa_re.search(block):
                security = "WPA/WPA2" # More specific if WPA IE is present
        networks[bssid]['Security'] = security
    
    return list(networks.values())


def scan_networks(interface):
    """
    Primary scanning function that tries multiple methods:
    1. Passive monitoring using Scapy (works in monitor mode) - PRIMARY
    2. Active scanning with 'iw' (managed mode) - FALLBACK
    3. Fallback to 'iwlist' (managed mode) - LAST RESORT
    """
    log.info(f"Initiating network scan on interface '{interface}'.")
    
    # --- PRIMARY METHOD: Comprehensive Multi-Method Scanning ---
    try:
        from core.comprehensive_scanner import ComprehensiveNetworkScanner
        log.info("Using comprehensive multi-method scanning (ALL methods)...")
        
        # Try comprehensive scanning that uses ALL available methods
        scanner = ComprehensiveNetworkScanner(interface)
        networks = scanner.scan_all_networks(duration=20)
        
        if networks and len(networks) > 0:
            log.info(f"✅ Comprehensive scan succeeded! Found {len(networks)} networks.")
            # Enrich networks with vendor information
            for net in networks:
                if 'Vendor' not in net:
                    net['Vendor'] = 'Unknown'  # Will be filled by threat analysis
                # Clean up sources field for compatibility
                if 'sources' in net:
                    del net['sources']
            return networks
        else:
            log.info("Comprehensive scan completed but found no networks. Trying individual fallback methods...")
            
    except ImportError as e:
        log.warning(f"Comprehensive scanner import failed: {e}. Trying individual methods...")
    except Exception as e:
        log.warning(f"Comprehensive scan error: {e}. Trying individual methods...")
    
    # --- Secondary Method: 'iw' ---
    iw_command = ['sudo', 'iw', 'dev', interface, 'scan']
    try:
        log.info("Attempting scan with 'iw' (secondary method)...")
        result = subprocess.run(
            iw_command, capture_output=True, text=True, check=True, timeout=15
        )
        log.info("'iw' scan succeeded.")
        return parse_iw_scan_output(result.stdout)
    except FileNotFoundError:
        log.warning("'iw' command not found.")
    except subprocess.TimeoutExpired:
        log.error(f"'iw' scan on '{interface}' timed out!")
    except subprocess.CalledProcessError as e:
        if "Operation not supported" in e.stderr:
            log.warning(f"'iw dev scan' not supported by the driver for '{interface}'.")
        else:
            log.error(f"'iw' scan command failed. STDERR: {e.stderr.strip()}")
    
    # --- Fallback Method: 'iwlist' ---
    iwlist_command = ['sudo', 'iwlist', interface, 'scan']
    try:
        log.info("Attempting scan with 'iwlist' (fallback method)...")
        result = subprocess.run(
            iwlist_command, capture_output=True, text=True, check=True, timeout=20
        )
        log.info("'iwlist' fallback scan succeeded.")
        return parse_iwlist_scan_output(result.stdout)
    except FileNotFoundError:
        log.error("'iwlist' command not found. Please install 'wireless-tools'.")
    except subprocess.TimeoutExpired:
        log.error(f"'iwlist' scan on '{interface}' timed out!")
    except subprocess.CalledProcessError as e:
        log.error(f"'iwlist' scan failed. STDERR: {e.stderr.strip()}")

    # If all methods fail, return empty list
    log.error("All scanning methods failed. Interface may not be in the correct mode or lacks permissions.")
    return []
