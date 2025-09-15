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

def _is_locally_administered_mac(mac):
    """Check if MAC address is locally administered (randomized)."""
    if not mac or len(mac) < 2:
        return False
    # Check if bit 1 of first octet is set (locally administered)
    first_octet = int(mac[:2], 16)
    return bool(first_octet & 0x02)

def _analyze_beacon_intervals(networks):
    """Analyze beacon interval patterns for anomalies."""
    interval_counts = defaultdict(int)
    anomalous_networks = []
    
    # Count beacon interval frequencies
    for net in networks:
        interval = net.get('BeaconInterval', 'Unknown')
        if interval != 'Unknown' and isinstance(interval, (int, str)):
            try:
                interval_val = int(interval)
                interval_counts[interval_val] += 1
                # Flag unusual beacon intervals (not 100 TU)
                if interval_val not in [100, 102, 1024]:  # Common legitimate intervals
                    anomalous_networks.append(net['BSSID'])
            except ValueError:
                pass
    
    return anomalous_networks

def _detect_signal_anomalies(ssid_groups):
    """Detect signal strength anomalies within SSID groups."""
    anomalous_networks = []
    
    for ssid, networks in ssid_groups.items():
        if len(networks) <= 1:
            continue
            
        signals = []
        for net in networks:
            try:
                signal = float(net.get('Signal', -100))
                signals.append(signal)
            except (ValueError, TypeError):
                signals.append(-100)
        
        # Check for unusually strong signals that might indicate proximity spoofing
        max_signal = max(signals)
        min_signal = min(signals)
        
        # If there's a >30dB difference, flag the strongest one
        if max_signal - min_signal > 30:
            for net in networks:
                try:
                    if float(net.get('Signal', -100)) == max_signal:
                        anomalous_networks.append(net['BSSID'])
                except (ValueError, TypeError):
                    pass
    
    return anomalous_networks

def analyze_network_threats(networks):
    """
    Analyzes a list of networks, assigning a suspicious score and threat level.
    Also enriches the network data with vendor information and advanced detection.
    """
    if not networks:
        return [], []

    log.info("Starting enhanced threat analysis for scanned networks.")
    analyzed_networks = []
    ssid_map = defaultdict(list)

    # First pass: gather data and enrich with vendor info
    for net in networks:
        ssid_map[net.get('SSID')].append(net)
        net['Vendor'] = get_vendor_by_mac(net.get('BSSID'))
        analyzed_networks.append(net)
    
    # Advanced analysis
    beacon_anomalies = _analyze_beacon_intervals(analyzed_networks)
    signal_anomalies = _detect_signal_anomalies(ssid_map)

    # Second pass: calculate scores with enhanced rules
    for net in analyzed_networks:
        score = 0
        reasons = []
        bssid = net.get('BSSID', '')

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
        suspicious_ssids = ["free wifi", "public wifi", "airport wifi", "hotel wifi", "starbucks", "mcdonalds"]
        if any(sub in ssid for sub in suspicious_ssids):
            score += 15
            reasons.append("Luring SSID")

        # Rule 3: High signal strength (could indicate proximity)
        try:
            if float(net.get('Signal', -100)) > -40:
                score += 5
        except (ValueError, TypeError):
            pass # Ignore if signal is not a valid number

        # Rule 4: MAC Address Randomization Detection
        if _is_locally_administered_mac(bssid):
            score += 20
            reasons.append("Locally Administered MAC (Possible Randomization)")

        # Rule 5: Beacon Interval Anomalies
        if bssid in beacon_anomalies:
            score += 15
            reasons.append("Unusual Beacon Interval")

        # Rule 6: Signal Strength Anomalies
        if bssid in signal_anomalies:
            score += 10
            reasons.append("Signal Strength Anomaly")

        # Rule 7: SSID spoofing (Evil Twin detection)
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

        # Rule 8: Vendor Analysis
        vendor = net.get('Vendor', 'Unknown')
        if vendor in ['Unknown', 'Not Found', 'API Error']:
            score += 5
            reasons.append("Unknown Vendor")
        elif 'raspberry' in vendor.lower() or 'espressif' in vendor.lower():
            score += 10
            reasons.append("DIY Hardware Vendor")

        # Rule 9: Hidden SSID with Strong Signal
        if ssid in ['<hidden>', ''] and net.get('Signal', -100) != 'Unknown':
            try:
                if float(net.get('Signal', -100)) > -50:
                    score += 15
                    reasons.append("Hidden SSID with Strong Signal")
            except (ValueError, TypeError):
                pass

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
    
    log.info(f"Threat analysis complete. Identified {len(rogue_aps)} potential rogues.")
    return analyzed_networks, rogue_aps