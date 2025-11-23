# This software is licensed under the MIT License: https://github.com/Rudii-25/WiFi_Penetration 
# Developer: Rudra Sharma - https://rudrasharma25.com 
# sniffguard/core/realtime_monitor.py

import time
import threading
import json
from datetime import datetime
from collections import defaultdict, deque
from PyQt6.QtCore import QObject, pyqtSignal
from core.comprehensive_scanner import ComprehensiveNetworkScanner
from core.advanced_detection import AdvancedThreatDetector
from utils.logger import log

class RealTimeMonitor(QObject):
    # PyQt signals for GUI updates
    new_threat_detected = pyqtSignal(dict)  # New threat found
    threat_level_changed = pyqtSignal(str, str, str)  # BSSID, old_level, new_level
    network_disappeared = pyqtSignal(str)  # BSSID disappeared
    monitoring_stats_updated = pyqtSignal(dict)  # Stats update
    networks_updated = pyqtSignal(list)  # All networks with current info
    
    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.is_monitoring = False
        self.monitor_thread = None
        self.scanner = ComprehensiveNetworkScanner(interface)
        self.threat_detector = AdvancedThreatDetector()
        
        # Monitoring configuration
        self.scan_interval = 30  # seconds between scans
        self.threat_threshold = 80  # minimum score to trigger alert (matches advanced detection)
        self.network_timeout = 300  # seconds before considering network disappeared
        
        # Data storage
        self.current_networks = {}
        self.threat_history = defaultdict(list)
        self.alert_queue = deque(maxlen=100)  # Keep last 100 alerts
        self.stats = {
            'scan_count': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'networks_seen': 0,
            'start_time': None
        }
        
        # Alert configuration
        self.alert_methods = {
            'gui': True,
            'log': True,
            'file': True,
            'sound': False,
            'email': False
        }
        
        self.alert_file = 'logs/threat_alerts.json'
        
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_monitoring:
            log.warning("Real-time monitoring is already running")
            return False
        
        self.is_monitoring = True
        self.stats['start_time'] = datetime.now().isoformat()
        
        log.info(f"Starting real-time monitoring on interface {self.interface}")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="RealTimeMonitor"
        )
        self.monitor_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if not self.is_monitoring:
            return False
        
        log.info("Stopping real-time monitoring")
        self.is_monitoring = False
        
        # Scanner cleanup (comprehensive scanner doesn't need explicit stop)
        
        # Wait for thread to finish
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        return True
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        log.info("Real-time monitoring loop started")
        
        try:
            while self.is_monitoring:
                start_time = time.time()
                
                # Perform scan
                self._perform_scan_cycle()
                
                # Update statistics
                self.stats['scan_count'] += 1
                self.monitoring_stats_updated.emit(self.stats.copy())
                
                # Calculate sleep time to maintain interval
                elapsed = time.time() - start_time
                sleep_time = max(0, self.scan_interval - elapsed)
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    
        except Exception as e:
            log.error(f"Error in monitoring loop: {e}")
        finally:
            log.info("Real-time monitoring loop stopped")
    
    def _perform_scan_cycle(self):
        """Perform one complete scan and analysis cycle"""
        try:
            # Perform comprehensive scan (shorter duration for real-time)
            networks = self.scanner.scan_all_networks(duration=10)
            
            if not networks:
                log.debug("No networks discovered in this scan cycle")
                return
            
            # Perform advanced threat analysis
            analyzed_networks, high_risk_aps = self.threat_detector.analyze_advanced_threats(networks)
            
            # Update network tracking
            self._update_network_tracking(analyzed_networks)
            
            # Process threats
            for threat in high_risk_aps:
                self._process_threat(threat)
            
            # Check for disappeared networks
            self._check_disappeared_networks()
            
            # Emit current network data to GUI for live updates
            self.networks_updated.emit(list(self.current_networks.values()))
            
            # Update statistics
            self.stats['networks_seen'] = len(self.current_networks)
            
        except Exception as e:
            log.error(f"Error in scan cycle: {e}")
    
    def _update_network_tracking(self, networks):
        """Update tracking of current networks"""
        current_time = time.time()
        current_bssids = set()
        
        for network in networks:
            bssid = network.get('BSSID')
            if not bssid:
                continue
            
            current_bssids.add(bssid)
            
            # Update or add network
            if bssid in self.current_networks:
                # Update existing network
                old_threat_level = self.current_networks[bssid].get('Advanced_Threat_Level', 'Low')
                new_threat_level = network.get('Advanced_Threat_Level', 'Low')
                
                # Check for threat level changes
                if old_threat_level != new_threat_level:
                    self.threat_level_changed.emit(bssid, old_threat_level, new_threat_level)
                    log.info(f"Threat level changed for {bssid}: {old_threat_level} -> {new_threat_level}")
                
                self.current_networks[bssid].update(network)
            else:
                # New network discovered
                network['first_seen'] = current_time
                self.current_networks[bssid] = network
                log.info(f"New network discovered: {network.get('SSID', 'Hidden')} ({bssid})")
            
            # Update last seen timestamp
            self.current_networks[bssid]['last_seen'] = current_time
    
    def _process_threat(self, threat):
        """Process a detected threat"""
        bssid = threat.get('BSSID')
        threat_score = threat.get('Advanced_Threat_Score', 0)
        threat_level = threat.get('Advanced_Threat_Level', 'Low')
        
        if threat_score < self.threat_threshold:
            return
        
        # Check if this is a new threat or escalation
        is_new_threat = False
        
        if bssid not in self.threat_history or not self.threat_history[bssid]:
            is_new_threat = True
        else:
            # Check if threat level increased
            last_threat = self.threat_history[bssid][-1]
            if threat_score > last_threat.get('score', 0):
                is_new_threat = True
        
        # Record threat in history
        threat_record = {
            'timestamp': datetime.now().isoformat(),
            'score': threat_score,
            'level': threat_level,
            'reasons': threat.get('Advanced_Reasons', ''),
            'ssid': threat.get('SSID', 'Hidden'),
            'bssid': bssid
        }
        
        self.threat_history[bssid].append(threat_record)
        
        # Trigger alerts for new threats
        if is_new_threat:
            self._trigger_alert(threat, threat_record)
            self.stats['threats_detected'] += 1
    
    def _trigger_alert(self, threat, threat_record):
        """Trigger various alert methods for a threat"""
        alert_data = {
            'timestamp': threat_record['timestamp'],
            'bssid': threat['BSSID'],
            'ssid': threat.get('SSID', 'Hidden'),
            'threat_level': threat_record['level'],
            'threat_score': threat_record['score'],
            'reasons': threat_record['reasons'],
            'signal': threat.get('Signal', 'N/A'),
            'channel': threat.get('Channel', 'N/A'),
            'vendor': threat.get('Vendor', 'Unknown')
        }
        
        # Add to alert queue
        self.alert_queue.append(alert_data)
        
        # GUI Alert
        if self.alert_methods['gui']:
            self.new_threat_detected.emit(alert_data)
        
        # Log Alert
        if self.alert_methods['log']:
            log.warning(f"THREAT ALERT: {alert_data['ssid']} ({alert_data['bssid']}) - "
                       f"Level: {alert_data['threat_level']}, Score: {alert_data['threat_score']}")
        
        # File Alert
        if self.alert_methods['file']:
            self._write_alert_to_file(alert_data)
        
        # Sound Alert
        if self.alert_methods['sound']:
            self._play_alert_sound(alert_data['threat_level'])
        
        # Email Alert (if configured)
        if self.alert_methods['email']:
            self._send_email_alert(alert_data)
    
    def _check_disappeared_networks(self):
        """Check for networks that have disappeared"""
        current_time = time.time()
        disappeared_bssids = []
        
        for bssid, network in list(self.current_networks.items()):
            last_seen = network.get('last_seen', 0)
            if current_time - last_seen > self.network_timeout:
                disappeared_bssids.append(bssid)
        
        # Remove disappeared networks
        for bssid in disappeared_bssids:
            network = self.current_networks.pop(bssid)
            ssid = network.get('SSID', 'Hidden')
            log.info(f"Network disappeared: {ssid} ({bssid})")
            self.network_disappeared.emit(bssid)
    
    def _write_alert_to_file(self, alert_data):
        """Write alert to JSON file"""
        try:
            import os
            os.makedirs(os.path.dirname(self.alert_file), exist_ok=True)
            
            # Read existing alerts
            alerts = []
            if os.path.exists(self.alert_file):
                try:
                    with open(self.alert_file, 'r') as f:
                        alerts = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    alerts = []
            
            # Add new alert
            alerts.append(alert_data)
            
            # Keep only recent alerts (last 1000)
            alerts = alerts[-1000:]
            
            # Write back to file
            with open(self.alert_file, 'w') as f:
                json.dump(alerts, f, indent=2)
                
        except Exception as e:
            log.error(f"Failed to write alert to file: {e}")
    
    def _play_alert_sound(self, threat_level):
        """Play alert sound based on threat level"""
        try:
            import subprocess
            
            # Different sounds for different threat levels
            if threat_level == 'Critical':
                # High pitched beep
                subprocess.run(['beep', '-f', '1000', '-l', '200'], timeout=2)
            elif threat_level == 'High':
                # Medium beep
                subprocess.run(['beep', '-f', '800', '-l', '150'], timeout=2)
            else:
                # Low beep
                subprocess.run(['beep', '-f', '600', '-l', '100'], timeout=2)
                
        except Exception as e:
            log.debug(f"Could not play alert sound: {e}")
    
    def _send_email_alert(self, alert_data):
        """Send email alert (placeholder for future implementation)"""
        # This would require email configuration
        log.info(f"Email alert would be sent for: {alert_data['ssid']}")
    
    def get_current_threats(self):
        """Get list of current active threats"""
        current_time = time.time()
        active_threats = []
        
        for bssid, network in self.current_networks.items():
            threat_score = network.get('Advanced_Threat_Score', 0)
            last_seen = network.get('last_seen', 0)
            
            # Only include recent high-threat networks
            if (threat_score >= self.threat_threshold and 
                current_time - last_seen < self.network_timeout):
                active_threats.append(network)
        
        return sorted(active_threats, key=lambda x: x.get('Advanced_Threat_Score', 0), reverse=True)
    
    def get_recent_alerts(self, limit=50):
        """Get recent alerts"""
        return list(self.alert_queue)[-limit:] if limit else list(self.alert_queue)
    
    def mark_false_positive(self, bssid, ssid):
        """Mark a network as false positive"""
        self.threat_detector.add_legitimate_network(bssid, ssid)
        self.stats['false_positives'] += 1
        log.info(f"Marked as false positive: {ssid} ({bssid})")
    
    def get_monitoring_stats(self):
        """Get current monitoring statistics"""
        if self.stats['start_time']:
            start_time = datetime.fromisoformat(self.stats['start_time'])
            uptime = datetime.now() - start_time
            self.stats['uptime_seconds'] = uptime.total_seconds()
        
        self.stats['active_networks'] = len(self.current_networks)
        self.stats['current_threats'] = len(self.get_current_threats())
        self.stats['total_alerts'] = len(self.alert_queue)
        
        return self.stats.copy()
    
    def configure_alerts(self, **kwargs):
        """Configure alert methods"""
        for method, enabled in kwargs.items():
            if method in self.alert_methods:
                self.alert_methods[method] = bool(enabled)
                log.info(f"Alert method '{method}' {'enabled' if enabled else 'disabled'}")
    
    def set_threat_threshold(self, threshold):
        """Set minimum threat score for alerts"""
        self.threat_threshold = max(0, min(100, threshold))
        log.info(f"Threat threshold set to {self.threat_threshold}")
    
    def set_scan_interval(self, interval):
        """Set scan interval in seconds"""
        self.scan_interval = max(10, interval)  # Minimum 10 seconds
        log.info(f"Scan interval set to {self.scan_interval} seconds")
    
    def export_threat_data(self, filename):
        """Export threat data to JSON file"""
        try:
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'monitoring_stats': self.get_monitoring_stats(),
                'current_networks': dict(self.current_networks),
                'threat_history': dict(self.threat_history),
                'recent_alerts': self.get_recent_alerts(),
                'configuration': {
                    'interface': self.interface,
                    'scan_interval': self.scan_interval,
                    'threat_threshold': self.threat_threshold,
                    'alert_methods': self.alert_methods
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            log.info(f"Threat data exported to {filename}")
            return True
            
        except Exception as e:
            log.error(f"Failed to export threat data: {e}")
            return False
