# sniffguard/core/monitor_mode.py

import subprocess
import time
from utils.logger import log

def _run_command(command, check=True):
    """A helper function to run a command and log its details."""
    try:
        log.info(f"EXECUTING: {' '.join(command)}")
        result = subprocess.run(
            command,
            check=check,
            capture_output=True,
            text=True
        )
        if result.stdout: 
            log.info(f"STDOUT: {result.stdout.strip()}")
        if result.stderr: 
            log.warning(f"STDERR: {result.stderr.strip()}")
        return True, result
    except FileNotFoundError as e:
        log.critical(f"COMMAND_NOT_FOUND: {command[0]}. Is it installed? Error: {e}")
        return False, None
    except subprocess.CalledProcessError as e:
        log.error(f"COMMAND_FAILED: {' '.join(command)} (Exit Code: {e.returncode})")
        log.error(f"STDOUT: {e.stdout.strip()}")
        log.error(f"STDERR: {e.stderr.strip()}")
        return False, None

def _interface_exists(interface):
    """Check if the given interface exists on the system."""
    success, result = _run_command(['ip', 'link', 'show', interface], check=False)
    if not success or "does not exist" in (result.stderr or ""):
        log.critical(f"INTERFACE_NOT_FOUND: {interface}")
        return False
    return True

def _disconnect_interface_from_nm(interface):
    """Disconnect specific interface from NetworkManager without stopping the service."""
    log.info(f"Disconnecting {interface} from NetworkManager (preserving other connections)...")
    
    # First try to disconnect gracefully via nmcli
    success, result = _run_command(['nmcli', 'device', 'disconnect', interface], check=False)
    if success:
        log.info(f"Successfully disconnected {interface} from NetworkManager")
    else:
        log.info(f"Interface {interface} may not be managed by NetworkManager or already disconnected")
    
    # Set the interface to unmanaged by NetworkManager temporarily
    success, result = _run_command(['nmcli', 'device', 'set', interface, 'managed', 'no'], check=False)
    if success:
        log.info(f"Set {interface} to unmanaged by NetworkManager")
    
    return True

def _reconnect_interface_to_nm(interface):
    """Reconnect specific interface to NetworkManager."""
    log.info(f"Reconnecting {interface} to NetworkManager...")
    
    # Re-enable management by NetworkManager
    success, result = _run_command(['nmcli', 'device', 'set', interface, 'managed', 'yes'], check=False)
    if success:
        log.info(f"Re-enabled NetworkManager management for {interface}")
    
    # Give NetworkManager time to recognize the interface
    time.sleep(2)
    
    return True

def enable_monitor_mode(interface):
    """Enables monitor mode on specific interface while preserving NetworkManager for others."""
    if not _interface_exists(interface):
        return False

    log.info(f"--- [START] MONITOR MODE ACTIVATION: {interface} ---")
    log.info("🌐 NetworkManager will remain active for other interfaces")

    # Only disconnect this specific interface from NetworkManager
    _disconnect_interface_from_nm(interface)
    time.sleep(2)

    # Bring interface down
    if not _run_command(['sudo', 'ip', 'link', 'set', interface, 'down'])[0]:
        log.error("Failed to bring interface down")
        return False

    # Set to monitor mode
    if not _run_command(['sudo', 'iw', interface, 'set', 'type', 'monitor'])[0]:
        log.critical("HARDWARE/DRIVER ERROR: Could not set monitor mode. Card may be unsupported.")
        # Try to reconnect to NetworkManager on failure
        _reconnect_interface_to_nm(interface)
        return False

    # Bring interface back up in monitor mode
    if not _run_command(['sudo', 'ip', 'link', 'set', interface, 'up'])[0]:
        log.error("Failed to bring interface up in monitor mode")
        return False

    # Verify monitor mode is active
    log.info("Verifying monitor mode status...")
    time.sleep(2)
    success, result = _run_command(['iw', 'dev', interface, 'info'])
    if success and "type monitor" in result.stdout:
        log.info(f"--- [SUCCESS] MONITOR MODE ACTIVE: {interface} ---")
        log.info("🌐 Other network interfaces remain unaffected")
        return True
    else:
        log.critical(f"--- [FAIL] VERIFICATION FAILED: {interface} ---")
        # Try to recover by reconnecting to NetworkManager
        _reconnect_interface_to_nm(interface)
        return False

def disable_monitor_mode(interface):
    """Disables monitor mode and restores the interface to managed mode without affecting other interfaces."""
    if not _interface_exists(interface):
        return False

    log.info(f"--- [START] MONITOR MODE DEACTIVATION: {interface} ---")
    log.info("🌐 NetworkManager connections on other interfaces will remain active")

    # Bring interface down
    if not _run_command(['sudo', 'ip', 'link', 'set', interface, 'down'])[0]:
        log.error("Failed to bring interface down")
        return False

    # Set back to managed mode
    if not _run_command(['sudo', 'iw', interface, 'set', 'type', 'managed'])[0]:
        log.error("Could not reset to managed mode. Manual intervention may be needed.")
        return False

    # Bring interface back up
    if not _run_command(['sudo', 'ip', 'link', 'set', interface, 'up'])[0]:
        log.error("Failed to bring interface up in managed mode")
        return False

    # Reconnect the interface to NetworkManager
    log.info("Reconnecting interface to NetworkManager...")
    _reconnect_interface_to_nm(interface)
    
    # Give NetworkManager time to manage the interface
    time.sleep(3)

    # Verify managed mode is active
    log.info("Verifying managed mode status...")
    success, result = _run_command(['iw', 'dev', interface, 'info'])
    if success and "type managed" in result.stdout:
        log.info(f"--- [SUCCESS] MONITOR MODE DEACTIVATED: {interface} ---")
        log.info("🌐 Interface restored to managed mode and reconnected to NetworkManager")
        log.info("🌐 Other network interfaces remained unaffected")
        return True
    else:
        log.critical(f"--- [FAIL] VERIFICATION FAILED FOR MANAGED MODE: {interface} ---")
        return False
