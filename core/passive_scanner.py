# This software is licensed under the MIT License: https://github.com/Rudii-25/WiFi_Penetration 
# Developer: Rudra Sharma - https://rudrasharma25.com 
# sniffguard/core/passive_scanner.py

import threading
import time
from collections import defaultdict
try:
    from scapy.all import sniff, RadioTap
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Warning: Scapy not available - {e}")
    
from utils.logger import log

class PassiveScanner:
    def __init__(self, interface):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is not available. Install with: pip3 install scapy")
            
        self.interface = interface
        self.networks = {}
        self.scanning = False
        self.scan_thread = None
        self.lock = threading.Lock()
        
    def packet_handler(self, pkt):
        """Handle captured packets and extract network information"""
        try:
            # Only process 802.11 frames
            if not pkt.haslayer(Dot11):
                return
                
            dot11 = pkt[Dot11]
            
            # Process beacon frames (from APs)
            if pkt.haslayer(Dot11Beacon):
                self._process_beacon(pkt)
            
            # Process probe response frames (from APs responding to probes)
            elif pkt.type == 0 and pkt.subtype == 5:  # Probe Response
                self._process_probe_response(pkt)
            
            # Process probe requests (from clients)
            elif pkt.haslayer(Dot11ProbeReq):
                self._process_probe_request(pkt)
                
        except Exception as e:
            log.debug(f"Error processing packet: {e}")
    
    def _process_beacon(self, pkt):
        """Extract information from beacon frames"""
        try:
            if not pkt.haslayer(Dot11) or not pkt.haslayer(Dot11Beacon):
                return
                
            dot11 = pkt[Dot11]
            beacon = pkt[Dot11Beacon]
            
            # Extract BSSID (AP MAC address) - use addr2 for transmitter
            bssid = dot11.addr2.upper() if dot11.addr2 else None
            if not bssid or bssid == "00:00:00:00:00:00":
                return
            
            current_time = time.time()
            
            # Skip if we've seen this AP very recently (avoid duplicates)
            with self.lock:
                if bssid in self.networks:
                    # Update last seen time but don't reprocess
                    self.networks[bssid]['last_seen'] = current_time
                    self.networks[bssid]['packet_count'] += 1
                    return
            
            # Extract basic network information
            network_info = {
                'BSSID': bssid,
                'Signal': self._get_signal_strength(pkt),
                'Channel': self._get_channel(pkt),
                'Security': 'Open',  # Default, will be updated
                'last_seen': current_time,
                'packet_count': 1,
                'SSID': '<Hidden>'  # Default for hidden networks
            }
            
            # Extract channel from fixed parameters if not found in RadioTap
            if network_info['Channel'] == 'N/A':
                try:
                    # Try to get channel from beacon interval field area
                    if hasattr(beacon, 'network_stats'):
                        channel_info = beacon.network_stats
                        if hasattr(channel_info, 'channel'):
                            network_info['Channel'] = str(channel_info.channel)
                except:
                    pass
            
            # Parse Information Elements (IEs)
            ssid_found = False
            current_layer = pkt
            
            # Look for Dot11Elt layers
            while current_layer:
                if current_layer.haslayer(Dot11Elt):
                    elt = current_layer[Dot11Elt]
                    break
                current_layer = current_layer.payload
            else:
                # If no Dot11Elt found, try to extract from beacon payload
                try:
                    beacon_payload = bytes(beacon.payload)
                    if len(beacon_payload) > 0:
                        self._parse_beacon_ies(beacon_payload, network_info)
                        ssid_found = 'SSID' in network_info and network_info['SSID'] != '<Hidden>'
                except:
                    pass
            
            if not ssid_found and 'elt' in locals():
                # Parse standard Information Elements
                while elt and hasattr(elt, 'ID'):
                    try:
                        # SSID (ID = 0)
                        if elt.ID == 0 and hasattr(elt, 'info') and len(elt.info) > 0:
                            try:
                                ssid = elt.info.decode('utf-8', errors='replace').strip()
                                if ssid and ssid != '\x00' and len(ssid) > 0:
                                    network_info['SSID'] = ssid
                                    ssid_found = True
                            except:
                                # Try different encoding
                                try:
                                    ssid = elt.info.decode('latin1', errors='replace').strip()
                                    if ssid and len(ssid) > 0:
                                        network_info['SSID'] = ssid
                                        ssid_found = True
                                except:
                                    network_info['SSID'] = f'<Encoded-{len(elt.info)}>'
                        
                        # DS Parameter Set (Channel) - ID = 3
                        elif elt.ID == 3 and hasattr(elt, 'info') and len(elt.info) >= 1:
                            try:
                                channel = elt.info[0] if isinstance(elt.info[0], int) else ord(elt.info[0])
                                network_info['Channel'] = str(channel)
                            except:
                                pass
                        
                        # RSN Information (WPA2/WPA3) - ID = 48
                        elif elt.ID == 48:
                            network_info['Security'] = 'WPA2/WPA3'
                        
                        # Microsoft WPA (ID = 221)
                        elif elt.ID == 221 and hasattr(elt, 'info') and len(elt.info) >= 4:
                            # Check for Microsoft OUI + WPA type
                            if elt.info[:4] == b'\x00\x50\xf2\x01':
                                network_info['Security'] = 'WPA'
                        
                        # Move to next element
                        if hasattr(elt, 'payload') and elt.payload:
                            next_elt = elt.payload
                            if hasattr(next_elt, 'getlayer'):
                                elt = next_elt.getlayer(Dot11Elt)
                            else:
                                elt = next_elt if hasattr(next_elt, 'ID') else None
                        else:
                            break
                            
                    except Exception as ie_error:
                        log.debug(f"Error parsing IE {getattr(elt, 'ID', 'unknown')}: {ie_error}")
                        break
            
            # Check privacy bit for WEP detection
            try:
                if hasattr(beacon, 'cap') and (beacon.cap & 0x0010):
                    if network_info['Security'] == 'Open':
                        network_info['Security'] = 'WEP'
            except:
                pass
            
            # Only add networks that we could extract some information from
            if ssid_found or network_info['SSID'] != '<Hidden>':
                with self.lock:
                    self.networks[bssid] = network_info
                    log.info(f"🔍 Discovered: {network_info['SSID']} ({bssid}) Ch:{network_info.get('Channel', '?')} Sec:{network_info.get('Security', '?')}")
            
        except Exception as e:
            log.debug(f"Error processing beacon frame: {e}")
    
    def _parse_beacon_ies(self, payload_bytes, network_info):
        """Parse Information Elements from raw beacon payload bytes"""
        try:
            i = 0
            while i < len(payload_bytes) - 1:
                ie_type = payload_bytes[i]
                ie_length = payload_bytes[i + 1]
                
                if i + 2 + ie_length > len(payload_bytes):
                    break
                    
                ie_data = payload_bytes[i + 2:i + 2 + ie_length]
                
                # SSID (Type 0)
                if ie_type == 0 and ie_length > 0:
                    try:
                        ssid = ie_data.decode('utf-8', errors='replace').strip()
                        if ssid and len(ssid) > 0:
                            network_info['SSID'] = ssid
                    except:
                        try:
                            ssid = ie_data.decode('latin1', errors='replace').strip()
                            if ssid and len(ssid) > 0:
                                network_info['SSID'] = ssid
                        except:
                            pass
                
                # Channel (Type 3)
                elif ie_type == 3 and ie_length == 1:
                    network_info['Channel'] = str(ie_data[0])
                
                i += 2 + ie_length
                
        except Exception as e:
            log.debug(f"Error parsing raw IEs: {e}")
    
    def _process_probe_response(self, pkt):
        """Process probe response frames - similar to beacons but from probe responses"""
        try:
            # Probe responses have the same structure as beacons for our purposes
            # Just treat them the same way but mark them as probe responses
            self._process_beacon(pkt)
        except Exception as e:
            log.debug(f"Error processing probe response: {e}")
    
    def _process_probe_request(self, pkt):
        """Process probe requests to detect client activity"""
        try:
            dot11 = pkt[Dot11]
            client_mac = dot11.addr2.upper()
            
            # Extract target SSID from probe request
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                if elt.ID == 0 and elt.len > 0:
                    try:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                        if ssid.strip():
                            log.debug(f"Client {client_mac} probing for SSID: {ssid}")
                    except:
                        pass
        
        except Exception as e:
            log.debug(f"Error processing probe request: {e}")
    
    def _get_signal_strength(self, pkt):
        """Extract signal strength from packet"""
        try:
            # Check if packet has RadioTap layer
            if pkt.haslayer(RadioTap):
                radiotap = pkt[RadioTap]
                # Signal strength is typically in dBm
                if hasattr(radiotap, 'dBm_AntSignal'):
                    return str(radiotap.dBm_AntSignal)
            return 'N/A'
        except:
            return 'N/A'
    
    def _get_channel(self, pkt):
        """Extract channel from packet"""
        try:
            if pkt.haslayer(RadioTap):
                radiotap = pkt[RadioTap]
                if hasattr(radiotap, 'Channel'):
                    return str(radiotap.Channel)
            return 'N/A'
        except:
            return 'N/A'
    
    def start_scan(self, duration=30):
        """Start passive scanning"""
        if self.scanning:
            log.warning("Scanner is already running")
            return
        
        self.scanning = True
        self.networks.clear()
        
        log.info(f"Starting passive scan on interface {self.interface} for {duration} seconds")
        
        def scan_worker():
            try:
                # Start packet capture with filter for beacon frames and probe responses
                # Filter: type 0 (management), subtype 8 (beacon) or subtype 5 (probe response)
                beacon_filter = "type mgt and (subtype beacon or subtype probe-resp)"
                
                log.info(f"Starting packet capture with filter: {beacon_filter}")
                sniff(
                    iface=self.interface,
                    prn=self.packet_handler,
                    filter=beacon_filter,
                    timeout=duration,
                    store=False  # Don't store packets in memory
                )
            except Exception as e:
                log.error(f"Scanning error: {e}")
            finally:
                self.scanning = False
                log.info(f"Passive scan completed. Found {len(self.networks)} unique networks")
        
        self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop scanning"""
        self.scanning = False
        if self.scan_thread and self.scan_thread.is_alive():
            log.info("Stopping passive scan...")
            # Note: scapy's sniff function will stop when timeout is reached
    
    def get_networks(self):
        """Get discovered networks"""
        with self.lock:
            # Filter out old networks (older than 60 seconds)
            current_time = time.time()
            active_networks = {
                bssid: info for bssid, info in self.networks.items()
                if current_time - info['last_seen'] < 60
            }
            return list(active_networks.values())
    
    def is_scanning(self):
        """Check if currently scanning"""
        return self.scanning


def passive_scan_networks(interface, duration=30):
    """Convenience function for passive scanning"""
    if not SCAPY_AVAILABLE:
        log.error("Scapy is not available for passive scanning")
        return []
    
    try:
        scanner = PassiveScanner(interface)
        scanner.start_scan(duration)
        
        # Wait for scan to complete
        scan_timeout = duration + 5  # Add 5 second buffer
        start_time = time.time()
        
        while scanner.is_scanning() and (time.time() - start_time) < scan_timeout:
            time.sleep(1)
        
        # Force stop if still scanning
        if scanner.is_scanning():
            scanner.stop_scan()
            log.warning("Passive scan timed out, stopping...")
        
        networks = scanner.get_networks()
        log.info(f"Passive scan completed: {len(networks)} networks found")
        return networks
        
    except Exception as e:
        log.error(f"Passive scanning failed: {e}")
        return []
