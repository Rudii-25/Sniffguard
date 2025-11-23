# This software is licensed under the MIT License: https://github.com/Rudii-25/WiFi_Penetration 
# Developer: Rudra Sharma - https://rudrasharma25.com 
# sniffguard/core/OS_detect.py

import sys
from utils.logger import log

def check_os():
    """
    Checks if the current operating system is Linux.

    Returns:
        bool: True if the OS is Linux, False otherwise.
    """
    log.info("Checking operating system.")
    if "linux" in sys.platform:
        log.info("Operating system is Linux. Execution can continue.")
        return True
    else:
        log.warning(f"Unsupported OS detected: {sys.platform}. This tool requires a Linux-based OS.")
        return False