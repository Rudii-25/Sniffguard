# sniffguard/utils/config.py

# Configuration settings with validation
APP_TITLE = "SniffGu@rd - Wireless Security Tool"
APP_GEOMETRY = "800x600"
APP_VERSION = "2.0"

# Security settings
SECURITY_SETTINGS = {
    "require_root": True,
    "require_linux": True,
    "max_network_history": 50,  # per network
    "history_cleanup_hours": 24,
    "threat_threshold": 80
}

# Network scanning settings
SCANNING_SETTINGS = {
    "default_scan_duration": 20,
    "realtime_scan_interval": 30,
    "max_scan_timeout": 30,
    "enable_comprehensive_scan": True
}

# Colors and styles for the GUI
STYLE = {
    "background": "#2E2E2E",
    "foreground": "#E0E0E0",
    "button_bg": "#4A4A4A",
    "button_fg": "#FFFFFF",
    "list_bg": "#3C3C3C",
    "list_fg": "#FFFFFF",
    "log_bg": "#1E1E1E",
    "log_fg": "#00FF00"
}

def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Validate security settings
    if not isinstance(SECURITY_SETTINGS['max_network_history'], int) or SECURITY_SETTINGS['max_network_history'] < 1:
        errors.append("max_network_history must be a positive integer")
    
    if not isinstance(SECURITY_SETTINGS['threat_threshold'], int) or not 0 <= SECURITY_SETTINGS['threat_threshold'] <= 100:
        errors.append("threat_threshold must be an integer between 0 and 100")
    
    # Validate scanning settings
    if not isinstance(SCANNING_SETTINGS['default_scan_duration'], int) or SCANNING_SETTINGS['default_scan_duration'] < 5:
        errors.append("default_scan_duration must be at least 5 seconds")
    
    return errors
