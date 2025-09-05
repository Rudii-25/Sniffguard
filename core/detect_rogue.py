# sniffguard/core/threat_analyzer.py

import requests
from collections import defaultdict
from utils.logger import log

# Simple in-memory cache to avoid repeated API calls for the same vendor
mac_vendor_cache = {}

def get_vendor_by_mac(mac_address):
    """
    Looks up the vendor of a MAC address using the macvendors.com API.
    """
    if not isinstance(mac_address, str) or len(mac_address) < 8:
        return "N/A"

    oui = mac_address[:8].upper()  # Organizationally Unique Identifier
    if oui in mac_vendor_cache:
        return mac_vendor_cache[oui]

    try:
        # Use a timeout to prevent the application from hanging
        response = requests.get(f"https://api.macvendors.com/{oui}", timeout=3)
        if response.status_code == 200:
            vendor = response.text
            mac_vendor_cache[oui] = vendor
            return vendor
        else:
            return "Not Found"
    except requests.RequestException as e:
        log.warning(f"MAC vendor lookup failed for {oui}: {e}")
        return "API Error"

def analyze_network_threats(networks):
    """
    Analyzes a list of networks, assigning a suspicious score and threat level.
    Also enriches the network data with vendor information.
    
    This function now serves as a compatibility layer that calls both the
    original analysis and the advanced detection system.
    """
    if not networks:
        return [], []

    log.info("Starting threat analysis for scanned networks.")
    
    # Run original analysis for backward compatibility
    basic_analyzed, basic_rogues = _analyze_network_threats_basic(networks)
    
    # Try to run advanced analysis if available
    try:
        from .advanced_detection import AdvancedThreatDetector
        
        # Create and use advanced detector
        detector = AdvancedThreatDetector()
        advanced_analyzed, advanced_rogues = detector.analyze_advanced_threats(basic_analyzed)
        
        log.info(f"Advanced threat analysis complete. Identified {len(advanced_rogues)} high-risk threats.")
        return advanced_analyzed, advanced_rogues
        
    except ImportError:
        log.warning("Advanced detection not available, using basic analysis only.")
        return basic_analyzed, basic_rogues
    except Exception as e:
        log.error(f"Advanced detection failed: {e}, falling back to basic analysis.")
        return basic_analyzed, basic_rogues

def _analyze_network_threats_basic(networks):
    """
    Original basic threat analysis - kept for backward compatibility
    """
    analyzed_networks = []
    ssid_map = defaultdict(list)

    # First pass: gather data and enrich with vendor info
    for net in networks:
        ssid_map[net.get('SSID')].append(net)
        net['Vendor'] = get_vendor_by_mac(net.get('BSSID'))
        analyzed_networks.append(net)

    # Second pass: calculate scores
    for net in analyzed_networks:
        score = 0
        reasons = []

        # Rule 1: Weak or no encryption
        security = net.get('Security', 'Unknown')
        if security == "Open":
            score += 40
            reasons.append("Open (Unencrypted)")
        elif security == "WEP":
            score += 25
            reasons.append("Weak Encryption (WEP)")

        # Rule 2: Suspicious SSID names
        ssid = net.get('SSID', '').lower()
        suspicious_ssids = ["free wifi", "public wifi", "airport wifi"]
        if any(sub in ssid for sub in suspicious_ssids):
            score += 15
            reasons.append("Luring SSID")

        # Rule 3: High signal strength (could indicate proximity)
        try:
            if float(net.get('Signal', -100)) > -40:
                score += 5
        except (ValueError, TypeError):
            pass # Ignore if signal is not a valid number

        # Rule 4: SSID spoofing (Evil Twin detection)
        ssid_group = ssid_map.get(net.get('SSID'))
        if ssid_group and len(ssid_group) > 1:
            is_open = security == "Open"
            has_secure_sibling = any(n.get('Security') != "Open" for n in ssid_group)
            
            # Classic Evil Twin: An open network mimicking a secure one
            if is_open and has_secure_sibling:
                score += 60
                reasons.append("Potential Evil Twin (Open variant of a secure SSID)")
            else: # General duplicate SSID
                score += 50
                reasons.append("Duplicate SSID broadcast")

        # Determine Threat Level from score
        if score >= 80:
            threat_level = "Critical"
        elif score >= 50:
            threat_level = "High"
        elif score >= 25:
            threat_level = "Medium"
        else:
            threat_level = "Low"

        net['Score'] = score
        net['Threat'] = threat_level
        net['Reasons'] = ", ".join(reasons) if reasons else "None"

    # Filter for rogue APs (Medium threat or higher)
    rogue_aps = [net for net in analyzed_networks if net['Score'] >= 25]
    
    log.info(f"Basic threat analysis complete. Identified {len(rogue_aps)} potential rogues.")
    return analyzed_networks, rogue_aps
