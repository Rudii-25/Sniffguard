# sniffguard/threads/network_monitor_thread.py

import time
import threading
from collections import defaultdict, deque
from PyQt6.QtCore import QThread, pyqtSignal

from core.scan_networks import PassiveScanner, SCAPY_AVAILABLE
from core.detect_rogue import analyze_network_threats
from utils.logger import log

class NetworkMonitorThread(QThread):
    """Continuous network monitoring thread with change detection."""
    
    # Signals
    networks_updated = pyqtSignal(list)  # All networks
    new_rogue_detected = pyqtSignal(list)  # New rogue APs
    network_disappeared = pyqtSignal(str)  # BSSID of disappeared network
    monitoring_status = pyqtSignal(str)  # Status updates
    error_occurred = pyqtSignal(str)
    
    def __init__(self, interface, scan_interval=30):
        super().__init__()
        self.interface = interface
        self.scan_interval = scan_interval  # seconds between scans
        self.stop_monitoring = False
        
        # Network tracking
        self.known_networks = {}  # BSSID -> network data
        self.known_rogues = set()  # Set of known rogue BSSIDs
        self.network_history = defaultdict(lambda: deque(maxlen=10))  # Track changes
        self.last_scan_time = 0
        
        # Scanner instance
        self.scanner = None
        
    def stop(self):
        """Stop monitoring gracefully."""
        self.stop_monitoring = True
        log.info("Network monitoring stop requested")
        
    def run(self):
        """Main monitoring loop."""
        if not SCAPY_AVAILABLE:
            self.error_occurred.emit("Scapy not available. Cannot start network monitoring.")
            return
            
        log.info(f"Starting continuous network monitoring on {self.interface}")
        self.monitoring_status.emit("Monitoring started")
        
        self.scanner = PassiveScanner(self.interface)
        # Reduce scan duration for monitoring mode
        self.scanner.scan_duration = 10
        
        while not self.stop_monitoring:
            try:
                self._perform_scan_cycle()
                
                # Wait for next scan, but check stop condition periodically
                for _ in range(self.scan_interval):
                    if self.stop_monitoring:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                log.error(f"Error in monitoring loop: {e}")
                self.error_occurred.emit(f"Monitoring error: {e}")
                time.sleep(5)  # Brief pause before retrying
                
        log.info("Network monitoring stopped")
        self.monitoring_status.emit("Monitoring stopped")
        
    def _perform_scan_cycle(self):
        """Perform one scan cycle and analyze results."""
        scan_start = time.time()
        
        # Perform passive scan
        raw_networks = self.scanner.scan()
        if not raw_networks:
            return
            
        # Analyze threats
        analyzed_networks, current_rogues = analyze_network_threats(raw_networks)
        
        # Detect changes
        self._detect_network_changes(analyzed_networks)
        self._detect_new_rogues(current_rogues)
        
        # Update tracking
        self._update_network_tracking(analyzed_networks)
        
        # Emit updates
        self.networks_updated.emit(analyzed_networks)
        
        scan_duration = time.time() - scan_start
        status_msg = f"Scan completed: {len(analyzed_networks)} networks, {len(current_rogues)} rogues ({scan_duration:.1f}s)"
        self.monitoring_status.emit(status_msg)
        log.info(status_msg)
        
    def _detect_network_changes(self, current_networks):
        """Detect networks that have appeared or disappeared."""
        current_bssids = {net['BSSID'] for net in current_networks}
        known_bssids = set(self.known_networks.keys())
        
        # Detect disappeared networks
        disappeared = known_bssids - current_bssids
        for bssid in disappeared:
            old_net = self.known_networks.get(bssid, {})
            ssid = old_net.get('SSID', 'Unknown')
            log.info(f"Network disappeared: {ssid} ({bssid})")
            self.network_disappeared.emit(bssid)
            
        # Detect new networks
        new_networks = current_bssids - known_bssids
        if new_networks:
            new_ssids = []
            for net in current_networks:
                if net['BSSID'] in new_networks:
                    new_ssids.append(net.get('SSID', 'Unknown'))
            log.info(f"New networks detected: {', '.join(new_ssids)}")
            
    def _detect_new_rogues(self, current_rogues):
        """Detect newly appeared rogue APs."""
        current_rogue_bssids = {rogue['BSSID'] for rogue in current_rogues}
        new_rogues = current_rogue_bssids - self.known_rogues
        
        if new_rogues:
            new_rogue_data = [rogue for rogue in current_rogues if rogue['BSSID'] in new_rogues]
            log.warning(f"NEW ROGUE APs DETECTED: {len(new_rogue_data)}")
            self.new_rogue_detected.emit(new_rogue_data)
            self.known_rogues.update(new_rogues)
            
    def _update_network_tracking(self, networks):
        """Update internal network tracking."""
        # Update known networks
        self.known_networks.clear()
        for net in networks:
            bssid = net['BSSID']
            self.known_networks[bssid] = net
            
            # Add to history for trend analysis
            self.network_history[bssid].append({
                'timestamp': time.time(),
                'signal': net.get('Signal', 'Unknown'),
                'threat_score': net.get('Score', 0)
            })
            
        self.last_scan_time = time.time()
        
    def get_network_stats(self):
        """Get current monitoring statistics."""
        return {
            'total_networks': len(self.known_networks),
            'known_rogues': len(self.known_rogues),
            'last_scan': self.last_scan_time,
            'monitoring_active': not self.stop_monitoring
        }
