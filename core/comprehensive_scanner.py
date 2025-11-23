#!/usr/bin/env python3
# comprehensive_scanner.py - Ultimate network scanner combining all methods

import subprocess
import threading
import time
import re
from collections import defaultdict
from utils.logger import log
from utils.vendor_lookup import vendor_lookup

# Try to import Scapy but don't fail if not available
try:
    from scapy.all import sniff, RadioTap, get_if_list
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class ComprehensiveNetworkScanner:
    def __init__(self, interface):
        if not interface or not isinstance(interface, str):
            raise ValueError("Interface name must be a non-empty string")
        if len(interface.strip()) == 0:
            raise ValueError("Interface name cannot be empty or whitespace")
        
        self.interface = interface.strip()
        self.networks = {}
        self.lock = threading.Lock()
        
    def scan_all_networks(self, duration=30):
        """Use multiple scanning methods to discover ALL networks"""
        log.info(f"Starting comprehensive network scan on {self.interface}")
        all_networks = {}
        
        # Check if interface is in monitor mode
        is_monitor_mode = self._is_monitor_mode()
        
        if is_monitor_mode:
            # In monitor mode - use passive scanning
            log.info("Interface in monitor mode - using passive scanning")
            
            # Enhanced Scapy scan with channel hopping
            if SCAPY_AVAILABLE:
                scapy_networks = self._scan_with_scapy_enhanced(duration)
                self._merge_networks(all_networks, scapy_networks, "scapy")
        else:
            # In managed mode - use active scanning  
            log.info("Interface in managed mode - using active scanning")
            
            # Method 1: Active iwlist scan (works in managed mode)
            iwlist_networks = self._scan_with_iwlist()
            self._merge_networks(all_networks, iwlist_networks, "iwlist")
            
            # Method 2: Active iw scan (works in managed mode)
            iw_networks = self._scan_with_iw()
            self._merge_networks(all_networks, iw_networks, "iw")
            
            # Method 3: nmcli scan (works in managed mode)
            nmcli_networks = self._scan_with_nmcli()
            self._merge_networks(all_networks, nmcli_networks, "nmcli")
            
            # Method 4: wpa_cli scan (works in managed mode)
            wpa_networks = self._scan_with_wpa_cli()
            self._merge_networks(all_networks, wpa_networks, "wpa_cli")
        
        final_networks = list(all_networks.values())
        
        # Add vendor information to all networks
        log.info("Looking up vendor information...")
        for network in final_networks:
            bssid = network.get('BSSID')
            if bssid and network.get('Vendor', 'Unknown') == 'Unknown':
                vendor = vendor_lookup.get_vendor(bssid)
                network['Vendor'] = vendor
        
        # Log detailed results for debugging
        log.info(f"Comprehensive scan complete: {len(final_networks)} unique networks found")
        if final_networks:
            for i, net in enumerate(final_networks[:5], 1):  # Log first 5 networks
                log.info(f"  {i}. {net.get('SSID', 'Hidden')} ({net.get('BSSID', 'Unknown')}) - {net.get('Security', 'Unknown')}")
        else:
            log.warning("No networks found by any scanning method!")
            
        return final_networks
    
    def _scan_with_iwlist(self):
        """Scan using iwlist command"""
        networks = []
        try:
            log.info("Scanning with iwlist...")
            
            # First ensure interface is in managed mode for iwlist
            try:
                subprocess.run(['sudo', 'iw', self.interface, 'set', 'type', 'managed'], 
                             capture_output=True, timeout=5)
                subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], 
                             capture_output=True, timeout=5)
            except:
                pass  # Continue even if mode change fails
            
            result = subprocess.run(
                ['sudo', 'iwlist', self.interface, 'scan'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                networks = self._parse_iwlist_output(result.stdout)
                log.info(f"iwlist found {len(networks)} networks")
            else:
                log.debug(f"iwlist scan failed (code {result.returncode}): {result.stderr}")
                
        except Exception as e:
            log.debug(f"iwlist scan error: {e}")
        
        return networks
    
    def _scan_with_iw(self):
        """Scan using iw command"""
        networks = []
        try:
            log.info("Scanning with iw...")
            result = subprocess.run(
                ['sudo', 'iw', 'dev', self.interface, 'scan'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                networks = self._parse_iw_output(result.stdout)
                log.info(f"iw found {len(networks)} networks")
            else:
                log.debug(f"iw scan failed: {result.stderr}")
                
        except Exception as e:
            log.debug(f"iw scan error: {e}")
        
        return networks
    
    def _scan_with_scapy(self, duration=20):
        """Scan using Scapy passive monitoring"""
        networks = []
        if not SCAPY_AVAILABLE:
            return networks
            
        try:
            log.info(f"Scanning with Scapy for {duration} seconds...")
            
            # Use a more permissive filter or no filter at all
            def packet_handler(pkt):
                try:
                    if pkt.haslayer(Dot11):
                        if pkt.haslayer(Dot11Beacon) or (pkt.type == 0 and pkt.subtype == 5):
                            network = self._extract_network_from_packet(pkt)
                            if network:
                                with self.lock:
                                    bssid = network['BSSID']
                                    if bssid not in self.networks:
                                        self.networks[bssid] = network
                except Exception as e:
                    log.debug(f"Packet processing error: {e}")
            
            # Capture without restrictive filters
            sniff(
                iface=self.interface,
                prn=packet_handler,
                timeout=duration,
                store=False
            )
            
            networks = list(self.networks.values())
            log.info(f"Scapy found {len(networks)} networks")
            
        except Exception as e:
            log.debug(f"Scapy scan error: {e}")
        
        return networks
    
    def _scan_with_nmcli(self):
        """Scan using NetworkManager CLI"""
        networks = []
        try:
            # First trigger a scan
            subprocess.run(
                ['sudo', 'nmcli', 'device', 'wifi', 'rescan'],
                capture_output=True, timeout=10
            )
            time.sleep(2)
            
            # Get results
            result = subprocess.run(
                ['nmcli', 'device', 'wifi', 'list'],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0:
                networks = self._parse_nmcli_output(result.stdout)
                log.info(f"nmcli found {len(networks)} networks")
                
        except Exception as e:
            log.debug(f"nmcli scan error: {e}")
        
        return networks
    
    def _scan_with_wpa_cli(self):
        """Scan using wpa_cli command"""
        networks = []
        try:
            # Trigger scan
            subprocess.run(
                ['sudo', 'wpa_cli', '-i', self.interface, 'scan'],
                capture_output=True, timeout=10
            )
            time.sleep(3)
            
            # Get results
            result = subprocess.run(
                ['sudo', 'wpa_cli', '-i', self.interface, 'scan_results'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                networks = self._parse_wpa_cli_output(result.stdout)
                log.info(f"wpa_cli found {len(networks)} networks")
                
        except Exception as e:
            log.debug(f"wpa_cli scan error: {e}")
        
        return networks
    
    def _parse_iwlist_output(self, output):
        """Parse iwlist scan output"""
        networks = []
        try:
            cells = output.split('Cell ')
            for cell in cells[1:]:  # Skip header
                network = {}
                
                # Extract BSSID
                bssid_match = re.search(r'Address: ([\da-fA-F:]{17})', cell)
                if bssid_match:
                    network['BSSID'] = bssid_match.group(1).upper()
                
                # Extract SSID
                ssid_match = re.search(r'ESSID:"([^"]+)"', cell)
                if ssid_match:
                    network['SSID'] = ssid_match.group(1)
                elif 'ESSID:""' in cell:
                    network['SSID'] = '<Hidden>'
                
                # Extract Signal
                signal_match = re.search(r'Signal level=(-?\d+) dBm', cell)
                if signal_match:
                    network['Signal'] = signal_match.group(1)
                
                # Extract Channel
                channel_match = re.search(r'Channel:(\d+)', cell)
                if channel_match:
                    network['Channel'] = channel_match.group(1)
                
                # Extract Security
                if 'Encryption key:on' in cell:
                    if 'WPA' in cell or 'RSN' in cell:
                        network['Security'] = 'WPA/WPA2/WPA3'
                    else:
                        network['Security'] = 'WEP'
                else:
                    network['Security'] = 'Open'
                
                if 'BSSID' in network and 'SSID' in network:
                    networks.append(network)
                    
        except Exception as e:
            log.debug(f"Error parsing iwlist output: {e}")
        
        return networks
    
    def _parse_iw_output(self, output):
        """Parse iw scan output"""
        networks = []
        try:
            current_network = {}
            
            for line in output.split('\n'):
                line = line.strip()
                
                # New BSS entry
                if line.startswith('BSS '):
                    if current_network and 'BSSID' in current_network:
                        networks.append(current_network)
                    
                    bssid_match = re.match(r'BSS ([\da-fA-F:]{17})', line)
                    current_network = {'BSSID': bssid_match.group(1).upper()} if bssid_match else {}
                
                elif 'SSID:' in line and current_network:
                    ssid = line.split('SSID:', 1)[1].strip()
                    current_network['SSID'] = ssid if ssid else '<Hidden>'
                
                elif 'signal:' in line and current_network:
                    signal_match = re.search(r'signal: (-?\d+\.\d+) dBm', line)
                    if signal_match:
                        current_network['Signal'] = str(int(float(signal_match.group(1))))
                
                elif 'primary channel:' in line and current_network:
                    channel_match = re.search(r'primary channel: (\d+)', line)
                    if channel_match:
                        current_network['Channel'] = channel_match.group(1)
                
                elif 'Privacy:' in line and current_network:
                    if 'Privacy: on' in line:
                        current_network['Security'] = 'WEP'
                    else:
                        current_network['Security'] = 'Open'
                
                elif 'RSN:' in line or 'WPA:' in line:
                    if current_network:
                        current_network['Security'] = 'WPA/WPA2/WPA3'
            
            # Add last network
            if current_network and 'BSSID' in current_network:
                networks.append(current_network)
                
        except Exception as e:
            log.debug(f"Error parsing iw output: {e}")
        
        return networks
    
    def _parse_nmcli_output(self, output):
        """Parse nmcli output - FIXED VERSION"""
        networks = []
        try:
            lines = output.strip().split('\n')
            for line in lines[1:]:  # Skip header
                if not line.strip(): continue
                
                # Extract BSSID (MAC address pattern)
                bssid_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line)
                if not bssid_match: continue
                bssid = bssid_match.group(1).upper()
                
                # Extract SSID (between BSSID and "Infra")
                ssid_match = re.search(bssid + r'\s+(.+?)\s+Infra', line)
                ssid = ssid_match.group(1).strip() if ssid_match else '<Hidden>'
                
                # Extract signal strength (number before bars)
                signal_match = re.search(r'(\d+)\s+[▁▂▃▄▅▆▇█_]+', line)
                if signal_match:
                    signal_pct = int(signal_match.group(1))
                    signal_dbm = -100 + (signal_pct * 0.7)
                    signal = f"{signal_dbm:.0f}"
                else:
                    signal = 'N/A'
                
                # Extract security
                security = 'Open'
                if 'WPA3' in line: security = 'WPA/WPA2/WPA3'
                elif 'WPA2' in line: security = 'WPA/WPA2'
                elif 'WPA1' in line: security = 'WPA/WPA2'
                elif 'WPA' in line: security = 'WPA'
                elif 'WEP' in line: security = 'WEP'
                
                network = {
                    'BSSID': bssid,
                    'SSID': ssid,
                    'Signal': signal,
                    'Security': security
                }
                networks.append(network)
                
        except Exception as e:
            log.debug(f"Error parsing nmcli output: {e}")
        
        return networks
    
    def _parse_wpa_cli_output(self, output):
        """Parse wpa_cli scan results"""
        networks = []
        try:
            lines = output.strip().split('\n')
            for line in lines[1:]:  # Skip header
                parts = line.split('\t')
                if len(parts) >= 5:
                    network = {
                        'BSSID': parts[0],
                        'Signal': parts[2],
                        'Security': 'WPA' if '[WPA' in parts[3] else 'Open',
                        'SSID': parts[4] if parts[4] else '<Hidden>'
                    }
                    networks.append(network)
        except Exception as e:
            log.debug(f"Error parsing wpa_cli output: {e}")
        
        return networks
    
    def _extract_network_from_packet(self, pkt):
        """Extract network info from Scapy packet"""
        try:
            if not pkt.haslayer(Dot11):
                return None
            
            dot11 = pkt[Dot11]
            bssid = dot11.addr2.upper() if dot11.addr2 else None
            if not bssid:
                return None
            
            network = {
                'BSSID': bssid,
                'SSID': '<Hidden>',
                'Security': 'Open',
                'Signal': 'N/A',
                'Channel': 'N/A'
            }
            
            # Extract signal
            if pkt.haslayer(RadioTap):
                rt = pkt[RadioTap]
                if hasattr(rt, 'dBm_AntSignal'):
                    network['Signal'] = str(rt.dBm_AntSignal)
            
            # Extract SSID and other info from IEs
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0 and len(elt.info) > 0:  # SSID
                        try:
                            ssid = elt.info.decode('utf-8', errors='replace').strip()
                            if ssid:
                                network['SSID'] = ssid
                        except:
                            pass
                    elif elt.ID == 3 and len(elt.info) == 1:  # Channel
                        network['Channel'] = str(elt.info[0])
                    elif elt.ID == 48:  # RSN
                        network['Security'] = 'WPA2/WPA3'
                    
                    elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            
            return network
            
        except Exception as e:
            log.debug(f"Error extracting network from packet: {e}")
            return None
    
    def _merge_networks(self, all_networks, new_networks, source):
        """Merge networks from different sources with comprehensive validation"""
        if not isinstance(all_networks, dict):
            log.error("all_networks must be a dictionary")
            return
        
        if not isinstance(new_networks, list):
            log.error("new_networks must be a list")
            return
            
        merged_count = 0
        for network in new_networks:
            try:
                if not isinstance(network, dict):
                    log.debug(f"Skipping invalid network entry: {network}")
                    continue
                    
                bssid = network.get('BSSID')
                if not bssid or not isinstance(bssid, str):
                    continue
                    
                # Clean BSSID format with validation
                bssid = bssid.upper().strip()
                # Validate MAC address format
                if len(bssid) != 17 or bssid.count(':') != 5:
                    log.debug(f"Invalid BSSID format: {bssid}")
                    continue
                
                if bssid in all_networks:
                    # Merge information, preferring non-empty values
                    existing = all_networks[bssid]
                    for key, value in network.items():
                        if value and str(value) not in ['N/A', 'Unknown', '', '<Hidden>']:
                            if key not in existing or str(existing[key]) in ['N/A', 'Unknown', '', '<Hidden>']:
                                existing[key] = value
                    
                    # Track sources
                    if 'sources' not in existing:
                        existing['sources'] = []
                    if source not in existing['sources']:
                        existing['sources'].append(source)
                else:
                    # Add new network
                    network_copy = network.copy()
                    network_copy['BSSID'] = bssid  # Ensure clean BSSID
                    network_copy['sources'] = [source]
                    
                    # Ensure required fields
                    if 'SSID' not in network_copy or not network_copy['SSID']:
                        network_copy['SSID'] = '<Hidden>'
                    if 'Security' not in network_copy:
                        network_copy['Security'] = 'Unknown'
                    if 'Signal' not in network_copy:
                        network_copy['Signal'] = 'N/A'
                    if 'Channel' not in network_copy:
                        network_copy['Channel'] = 'N/A'
                    if 'Vendor' not in network_copy:
                        network_copy['Vendor'] = 'Unknown'
                        
                    all_networks[bssid] = network_copy
                    merged_count += 1
                
            except Exception as e:
                log.debug(f"Error processing network {network.get('BSSID', 'Unknown')}: {e}")
                continue
        
        log.debug(f"Merged {merged_count} networks from {source}")
    
    def _is_monitor_mode(self):
        """Check if interface is in monitor mode"""
        try:
            result = subprocess.run(
                ['iw', 'dev', self.interface, 'info'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return 'type monitor' in result.stdout
        except Exception as e:
            log.debug(f"Error checking monitor mode: {e}")
        return False
    
    def _scan_with_scapy_enhanced(self, duration=30):
        """Enhanced Scapy scanning with channel hopping"""
        networks = []
        if not SCAPY_AVAILABLE:
            return networks
            
        try:
            log.info(f"Enhanced Scapy scan for {duration} seconds with channel hopping...")
            
            # Comprehensive WiFi channels (2.4GHz + 5GHz)
            channels_2_4ghz = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
            channels_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
            
            # Prioritize common channels first, then scan all
            priority_channels = [1, 6, 11, 36, 40, 44, 48]  # Most common
            all_channels = priority_channels + [ch for ch in channels_2_4ghz + channels_5ghz if ch not in priority_channels]
            
            channel_time = max(1, duration // len(all_channels))  # Time per channel
            
            def packet_handler(pkt):
                try:
                    if pkt.haslayer(Dot11):
                        # Accept beacon frames, probe responses, and probe requests
                        if (pkt.haslayer(Dot11Beacon) or 
                            (pkt.type == 0 and pkt.subtype == 5) or  # Probe Response 
                            (pkt.type == 0 and pkt.subtype == 8)):   # Beacon
                            
                            network = self._extract_network_from_packet(pkt)
                            if network:
                                with self.lock:
                                    bssid = network['BSSID']
                                    if bssid not in self.networks:
                                        self.networks[bssid] = network
                                        log.debug(f"Found network: {network['SSID']} ({bssid})")
                except Exception as e:
                    log.debug(f"Packet processing error: {e}")
            
            # Channel hopping scan
            for channel in all_channels:
                if duration <= 0:
                    break
                    
                try:
                    # Set channel
                    subprocess.run(
                        ['sudo', 'iw', 'dev', self.interface, 'set', 'channel', str(channel)],
                        capture_output=True, timeout=2
                    )
                    
                    # Scan on this channel
                    log.debug(f"Scanning channel {channel} for {channel_time}s")
                    sniff(
                        iface=self.interface,
                        prn=packet_handler,
                        timeout=channel_time,
                        store=False
                    )
                    
                    duration -= channel_time
                    
                except Exception as e:
                    log.debug(f"Channel {channel} scan error: {e}")
                    continue
            
            networks = list(self.networks.values())
            log.info(f"Enhanced Scapy found {len(networks)} networks")
            
        except Exception as e:
            log.debug(f"Enhanced Scapy scan error: {e}")
        
        return networks


def comprehensive_scan_networks(interface, duration=30):
    """Main function to scan networks using all available methods"""
    scanner = ComprehensiveNetworkScanner(interface)
    return scanner.scan_all_networks(duration)
