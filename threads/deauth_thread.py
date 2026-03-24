# sniffguard/threads/deauth_thread.py

from PyQt6.QtCore import QThread, pyqtSignal
from core.deauth_attack import launch_targeted_deauth
from utils.logger import log

class DeauthThread(QThread):
    """Worker thread for deauthentication attacks to keep GUI responsive"""
    attack_complete = pyqtSignal(bool, str, dict)  # success, message, stats
    attack_progress = pyqtSignal(str)               # progress message
    
    def __init__(self, interface, target_bssid, duration=30, aggressive=False):
        super().__init__()
        self.interface = interface
        self.target_bssid = target_bssid
        self.duration = duration
        self.aggressive = aggressive
    
    def run(self):
        """Execute the deauth attack"""
        log.info(f"DeauthThread started for {self.target_bssid} on {self.interface}")
        
        try:
            self.attack_progress.emit(f"Starting deauth attack on {self.target_bssid}...")
            
            success, message, stats = launch_targeted_deauth(
                self.interface,
                self.target_bssid,
                duration=self.duration,
                aggressive=self.aggressive
            )
            
            self.attack_complete.emit(success, message, stats)
            
        except Exception as e:
            error_msg = f"Deauth thread error: {e}"
            log.error(error_msg)
            self.attack_complete.emit(False, error_msg, {})
