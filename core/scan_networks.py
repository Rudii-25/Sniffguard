import subprocess
from typing import List, Dict, Optional, Tuple
import scapy.all as scapy
from utils.status import display_status


def get_channel(packet) -> Optional[int]:
    """
    Extract the channel number from the packet's Dot11Elt info.
    The channel is usually encoded in the element with ID 3 (DS Parameter Set).
    """
    layers = packet.getlayer(scapy.Dot11Elt)
    while layers:
        if layers.ID == 3 and hasattr(layers, "info"):
            return layers.info[0]  # channel is a single byte
        layers = layers.payload.getlayer(scapy.Dot11Elt)
    return None


def scan_networks(interface: str, duration: int = 10) -> List[Dict[str, Optional[str]]]:
    """
    Scan wireless networks on the specified interface for the given duration.

    Args:
        interface (str): Wireless interface name (should be in monitor mode).
        duration (int): Scan duration in seconds.

    Returns:
        List[Dict[str, Optional[str]]]: List of found APs with SSID, BSSID, Channel, and RSSI.
    """
    networks = []
    seen_bssids = set()

    def packet_handler(packet):
        if packet.haslayer(scapy.Dot11Beacon):
            ssid = packet[scapy.Dot11Elt].info.decode(errors="ignore") if packet[scapy.Dot11Elt].info else ""
            bssid = packet[scapy.Dot11].addr2
            channel = get_channel(packet)
            rssi = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else None

            if bssid not in seen_bssids:
                seen_bssids.add(bssid)
                networks.append({
                    'SSID': ssid,
                    'BSSID': bssid,
                    'Channel': channel,
                    'Signal': rssi,
                })

    display_status("Scan", f"Starting scan on interface {interface} for {duration}s")
    try:
        scapy.sniff(iface=interface, prn=packet_handler, timeout=duration)
    except Exception as e:
        display_status("Scan Error", f"Error during scanning: {str(e)}")
    display_status("Scan", f"Scan complete, found {len(networks)} networks")

    return networks


def enable_monitor_mode(interface: str) -> Tuple[bool, str]:
    """
    Enable monitor mode on the given interface using iw and ifconfig commands.

    Args:
        interface (str): Interface name.

    Returns:
        (success (bool), message (str))
    """
    try:
        subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
        subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'monitor'], check=True)
        subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
        return True, f"Interface {interface} set to monitor mode."
    except subprocess.CalledProcessError as e:
        return False, f"Failed to enable monitor mode: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"


def disable_monitor_mode(interface: str) -> Tuple[bool, str]:
    """
    Disable monitor mode on the given interface (set to managed).

    Args:
        interface (str): Interface name.

    Returns:
        (success (bool), message (str))
    """
    try:
        subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
        subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'managed'], check=True)
        subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
        return True, f"Interface {interface} set to managed mode."
    except subprocess.CalledProcessError as e:
        return False, f"Failed to disable monitor mode: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"
