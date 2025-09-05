# sniffguard/threads/scan_thread.py

from PyQt6.QtCore import QThread, pyqtSignal
from core.scan_networks import scan_networks
from core.detect_rogue import analyze_network_threats
from utils.logger import log

class ScanThread(QThread):
    """Worker thread that scans and analyzes networks to keep the GUI responsive."""
    analysis_complete = pyqtSignal(list) # Full list of all networks
    rogue_aps_found = pyqtSignal(list)   # Filtered list of suspicious networks
    error_occurred = pyqtSignal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface

    def run(self):
        """Execute the network scan and analysis"""
        log.info(f"ScanThread started for interface '{self.interface}'.")
        
        try:
            # Step 1: Scan for raw network data
            raw_networks = scan_networks(self.interface)
            
            if not raw_networks:
                self.error_occurred.emit(f"No networks detected on {self.interface}. This could be due to:\n" +
                                       "• No WiFi networks in range\n" +
                                       "• Interface not in monitor mode\n" +
                                       "• Insufficient permissions\n" +
                                       "• Driver compatibility issues")
                return
            
            log.info(f"Scan found {len(raw_networks)} networks, analyzing threats...")
            
            # Step 2: Analyze the raw data for threats
            all_analyzed_networks, rogue_aps = analyze_network_threats(raw_networks)
            
            # Step 3: Emit signals with the results
            log.info(f"Analysis complete: {len(all_analyzed_networks)} networks analyzed, {len(rogue_aps)} potential threats")
            self.analysis_complete.emit(all_analyzed_networks)
            
            if rogue_aps:
                self.rogue_aps_found.emit(rogue_aps)
            
        except Exception as e:
            error_msg = f"Network scanning failed: {str(e)}"
            log.error(error_msg)
            self.error_occurred.emit(error_msg)
