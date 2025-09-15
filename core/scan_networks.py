# sniffguard/core/scan_networks.py

import subprocess
import re
import threading
import time
from collections import defaultdict
from utils.logger import log

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, 
        RadioTap, get_if_list
    )
    SCAPY_AVAILABLE = True
except ImportError:
    log.warning("Scapy not installed. Passive scanning will be unavailable.")
    SCAPY_AVAILABLE = False

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


class PassiveScanner:
    """Passive WiFi scanner using packet capture - works in monitor mode."""
    
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}
        self.stop_scanning = False
        self.scan_duration = 15  # seconds
        # Channel hopping config
        self.channels = [1, 6, 11, 3, 9, 13, 2, 4, 5, 7, 8, 10, 12]
        self.hop_interval = 2  # seconds per channel
        self._hopper_thread = None
        
    def _hopper(self):
        """Continuously hop channels while scanning."""
        idx = 0
        start_time = time.time()
        while time.time() - start_time < self.scan_duration and not self.stop_scanning:
            ch = self.channels[idx % len(self.channels)]
            try:
                subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(ch)],
                               check=False, capture_output=True, text=True)
            except Exception as e:
                log.debug(f"Channel hop failed on {self.interface} to {ch}: {e}")
            time.sleep(self.hop_interval)
            idx += 1
        
    def _start_hopper(self):
        self.stop_scanning = False
        self._hopper_thread = threading.Thread(target=self._hopper, daemon=True)
        self._hopper_thread.start()
        
    def _stop_hopper(self):
        self.stop_scanning = True
        if self._hopper_thread and self._hopper_thread.is_alive():
            self._hopper_thread.join(timeout=1)
        
    def packet_handler(self, pkt):
        """Process captured WiFi packets to extract network information."""
        try:
            if not pkt.haslayer(Dot11):
                return
                
            dot11 = pkt[Dot11]
            
            # Process Beacon Frames
            if pkt.haslayer(Dot11Beacon):
                self._process_beacon(pkt, dot11)
            
            # Process Probe Response Frames
            elif pkt.haslayer(Dot11ProbeResp):
                self._process_probe_response(pkt, dot11)
                
        except Exception as e:
            log.debug(f"Error processing packet: {e}")
    
    def _process_beacon(self, pkt, dot11):
        """Extract information from beacon frames."""
        bssid = dot11.addr3.upper() if dot11.addr3 else None
        if not bssid:
            return
            
        ssid = ""
        channel = None
        security = "Open"
        
        # Extract SSID and other info from Information Elements
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0 and elt.len > 0:  # SSID
                    try:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                    except:
                        ssid = "<Hidden>"
                elif elt.ID == 3:  # DS Parameter Set (Channel)
                    if elt.len == 1:
                        channel = ord(elt.info)
                elif elt.ID == 48:  # RSN (WPA2)
                    security = "WPA2"
                elif elt.ID == 221:  # Vendor Specific (WPA)
                    if elt.info[:4] == b'\x00\x50\xf2\x01':
                        security = "WPA"
                        
                # Check for Privacy bit in Capability Info
                if hasattr(pkt[Dot11Beacon], 'cap') and (pkt[Dot11Beacon].cap & 0x10):
                    if security == "Open":
                        security = "WEP"
                        
                elt = elt.payload if hasattr(elt, 'payload') and elt.payload else None
        
        # Calculate signal strength from RadioTap header
        signal = None
        if pkt.haslayer(RadioTap):
            radiotap = pkt[RadioTap]
            if hasattr(radiotap, 'dBm_AntSignal'):
                signal = str(radiotap.dBm_AntSignal)
        
        # Beacon interval (typical ~100 TU)
        beacon_interval = None
        if pkt.haslayer(Dot11Beacon):
            try:
                beacon_interval = int(pkt[Dot11Beacon].beacon_interval)
            except Exception:
                beacon_interval = None
        
        # Store network info
        if ssid:  # Only store networks with valid SSIDs
            self.networks[bssid] = {
                'BSSID': bssid,
                'SSID': ssid,
                'Channel': str(channel) if channel else "Unknown",
                'Security': security,
                'Signal': signal or "Unknown",
                'BeaconInterval': beacon_interval if beacon_interval is not None else "Unknown"
            }
    
    def _process_probe_response(self, pkt, dot11):
        """Extract information from probe response frames."""
        # Similar to beacon processing but for probe responses
        self._process_beacon(pkt, dot11)
    
    def scan(self):
        """Perform passive scan by capturing packets."""
        if not SCAPY_AVAILABLE:
            log.error("Scapy not available. Cannot perform passive scanning.")
            return []
            
        log.info(f"Starting passive scan on {self.interface} for {self.scan_duration} seconds...")
        
        try:
            # Start channel hopping in parallel with sniffing
            self._start_hopper()
            
            # Start packet capture with timeout
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                timeout=self.scan_duration,
                filter="type mgt subtype beacon or type mgt subtype probe-resp",
                store=False  # Don't store packets in memory
            )
            
            log.info(f"Passive scan completed. Found {len(self.networks)} unique networks.")
            return list(self.networks.values())
            
        except Exception as e:
            log.error(f"Passive scanning failed: {e}")
            return []
        finally:
            self._stop_hopper()

def scan_networks(interface):
    """
    Smart scanning function that tries different methods based on interface mode.
    """
    log.info(f"Initiating network scan on interface '{interface}'.")
    
    # Check if interface is in monitor mode
    is_monitor_mode = _is_monitor_mode(interface)
    
    if is_monitor_mode:
        log.info("Interface is in monitor mode. Using passive scanning...")
        scanner = PassiveScanner(interface)
        return scanner.scan()
    else:
        log.info("Interface is in managed mode. Attempting active scanning...")
        return _active_scan(interface)

def _is_monitor_mode(interface):
    """Check if interface is in monitor mode."""
    try:
        result = subprocess.run(
            ['iw', 'dev', interface, 'info'],
            capture_output=True, text=True, check=True
        )
        return "type monitor" in result.stdout
    except:
        return False

def _active_scan(interface):
    """Perform active scanning for managed mode interfaces."""
    # --- Primary Method: 'iw' ---
    iw_command = ['sudo', 'iw', 'dev', interface, 'scan']
    try:
        log.info("Attempting scan with 'iw' (primary method)...")
        result = subprocess.run(
            iw_command, capture_output=True, text=True, check=True, timeout=15
        )
        log.info("'iw' scan succeeded.")
        return parse_iw_scan_output(result.stdout)
    except FileNotFoundError:
        log.critical("'iw' command not found. Cannot perform primary scan.")
    except subprocess.TimeoutExpired:
        log.error(f"'iw' scan on '{interface}' timed out! The interface may be in a bad state.")
    except subprocess.CalledProcessError as e:
        if "Operation not supported" in e.stderr:
            log.warning(f"'iw dev scan' not supported by the driver for '{interface}'. Attempting fallback to 'iwlist'.")
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
        log.critical("'iwlist' command not found. Fallback is not possible. Please install 'wireless-tools'.")
    except subprocess.TimeoutExpired:
        log.error(f"'iwlist' scan on '{interface}' timed out!")
    except subprocess.CalledProcessError as e:
        log.error(f"'iwlist' scan failed. This indicates a more serious driver or hardware issue. STDERR: {e.stderr.strip()}")

    # If both methods fail, return empty list
    log.error("All scan methods failed.")
    return []
