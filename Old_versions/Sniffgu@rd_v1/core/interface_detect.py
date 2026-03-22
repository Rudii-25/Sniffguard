# sniffguard/core/interface_detect.py

import subprocess
from utils.logger import log

def get_interfaces():
    """
    Detects all available network interfaces using the 'ip' command.

    Returns:
        list: A list of interface names, or an empty list on error.
    """
    interfaces = []
    log.info("Attempting to detect network interfaces.")
    try:
        # Using 'ip -o link show' provides a more consistent output
        result = subprocess.run(
            ['ip', '-o', 'link', 'show'],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split('\n')
        for line in lines:
            parts = line.split()
            # The interface name is typically the second part, after the index number
            if len(parts) > 1:
                interface_name = parts[1].strip(':')
                if interface_name != 'lo': # Exclude loopback
                    interfaces.append(interface_name)
        
        if interfaces:
            log.info(f"Detected interfaces: {', '.join(interfaces)}")
        else:
            log.warning("No network interfaces detected (excluding loopback).")
        return interfaces
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log.error(f"Failed to detect interfaces. Error: {e}. 'ip' command might be missing or failed.")
        return []