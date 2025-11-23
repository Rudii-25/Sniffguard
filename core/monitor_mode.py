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

def _manage_conflicting_processes(action="stop"):
    """Stops or starts common network management services."""
    services = ["NetworkManager", "wpa_supplicant"]
    log.info(f"Attempting to '{action}' conflicting network services...")

    is_running_cmd = ['systemctl', 'is-active', '--quiet']
    for service in services:
        try:
            subprocess.run([*is_running_cmd, service], check=True)
            log.info(f"Service '{service}' is active. Proceeding with '{action}'.")
            _run_command(['sudo', 'systemctl', action, service])
        except (subprocess.CalledProcessError, FileNotFoundError):
            log.info(f"Service '{service}' not active or not found, skipping.")

def enable_monitor_mode(interface):
    """Enables monitor mode using a robust, multi-step process."""
    if not _interface_exists(interface):
        return False

    log.info(f"--- [START] MONITOR MODE ACTIVATION: {interface} ---")

    _manage_conflicting_processes("stop")
    time.sleep(1)

    if not _run_command(['sudo', 'ip', 'link', 'set', interface, 'down'])[0]:
        return False

    if not _run_command(['sudo', 'iw', interface, 'set', 'type', 'monitor'])[0]:
        log.critical("HARDWARE/DRIVER ERROR: Could not set monitor mode. Card may be unsupported.")
        return False

    if not _run_command(['sudo', 'ip', 'link', 'set', interface, 'up'])[0]:
        return False

    log.info("Verifying monitor mode status...")
    time.sleep(1)
    success, result = _run_command(['iw', 'dev', interface, 'info'])
    if success and "type monitor" in result.stdout:
        log.info(f"--- [SUCCESS] MONITOR MODE ACTIVE: {interface} ---")
        return True
    else:
        log.critical(f"--- [FAIL] VERIFICATION FAILED: {interface} ---")
        return False

def disable_monitor_mode(interface):
    """Disables monitor mode and restores the interface to managed mode."""
    if not _interface_exists(interface):
        return False

    log.info(f"--- [START] MONITOR MODE DEACTIVATION: {interface} ---")

    if not _run_command(['sudo', 'ip', 'link', 'set', interface, 'down'])[0]:
        return False

    if not _run_command(['sudo', 'iw', interface, 'set', 'type', 'managed'])[0]:
        log.error("Could not reset to managed mode. Manual intervention may be needed.")
        return False

    if not _run_command(['sudo', 'ip', 'link', 'set', interface, 'up'])[0]:
        return False

    log.info("Restarting network services to restore connectivity...")
    _manage_conflicting_processes("start")

    # Fallback recovery (force NM restart)
    _run_command(['sudo', 'systemctl', 'restart', 'NetworkManager'], check=False)

    log.info("Verifying managed mode status...")
    time.sleep(1)
    success, result = _run_command(['iw', 'dev', interface, 'info'])
    if success and "type managed" in result.stdout:
        log.info(f"--- [SUCCESS] MONITOR MODE DEACTIVATED & CONNECTIVITY RESTORED: {interface} ---")
        return True
    else:
        log.critical(f"--- [FAIL] VERIFICATION FAILED FOR MANAGED MODE: {interface} ---")
        return False
