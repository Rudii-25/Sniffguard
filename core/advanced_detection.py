# This software is licensed under the MIT License: https://github.com/Rudii-25/WiFi_Penetration 
# Developer: Rudra Sharma - https://rudrasharma25.com 
# sniffguard/core/genuine_rogue_detector.py
# GENUINE ROGUE AP DETECTION - NO NAME-BASED FALSE POSITIVES

import numpy as np
import time
import re
from collections import defaultdict
from datetime import datetime, timedelta
from utils.logger import log

class AdvancedThreatDetector:
    """
    Genuine rogue AP detection based on TECHNICAL ANOMALIES only.
    Does NOT use network names/SSIDs for detection to avoid false positives.
    """
    
    def __init__(self):
        self.network_history = defaultdict(list)
        self.mac_sequence_tracker = {}  # Track MAC address patterns
        self.baseline_behavior = {}     # Learn normal network behavior
        
        # Technical thresholds for genuine rogue AP detection
        self.thresholds = {
            'signal': {
                'impossibly_strong': -15,    # Signal > -15 dBm (device very close)
                'rapid_variation': 20,       # Signal changes > 20 dBm quickly
                'suspicious_strength': -25   # Unusually strong for typical AP
            },
            'timing': {
                'short_lifespan': 600,       # Network active < 10 minutes  
                'rapid_cycling': 180,        # On/off cycles < 3 minutes
                'burst_appearances': 5       # Multiple appearances in short time
            },
            'hardware': {
                'sequential_threshold': 3,    # Multiple sequential MACs detected
                'locally_admin_penalty': 15, # Penalty for locally administered MAC
                'dev_board_penalty': 25      # Penalty for development board OUIs
            },
            'protocol': {
                'channel_hop_threshold': 2,  # Changing channels multiple times
                'beacon_anomaly': 100,       # Beacon interval anomalies
                'security_inconsistency': 30 # Mixed or changing security
            }
        }
        
        # Known development board OUIs commonly used in rogue APs
        self.dev_board_ouis = [
            'b8:27:eb',  # Raspberry Pi Foundation
            '24:0a:c4',  # Espressif Inc (ESP32)
            '30:ae:a4',  # Espressif Inc 
            '84:cc:a8',  # Espressif Inc
            '94:b9:7e',  # Espressif Inc
            '18:fe:34',  # Espressif Inc
            '60:01:94',  # Espressif Inc
        ]
    
    def analyze_advanced_threats(self, networks):
        """
        Analyze networks for genuine rogue AP indicators.
        Returns: (analyzed_networks, high_risk_networks)
        """
        current_time = time.time()
        analyzed_networks = []
        high_risk_networks = []
        
        # Update network history
        self._update_network_history(networks, current_time)
        
        # Analyze each network using technical methods only
        for network in networks:
            # Ensure vendor information is present
            if 'Vendor' not in network or not network.get('Vendor'):
                from utils.vendor_lookup import vendor_lookup
                bssid = network.get('BSSID', '')
                if bssid:
                    network['Vendor'] = vendor_lookup.get_vendor(bssid)
                else:
                    network['Vendor'] = 'Unknown'
            
            enhanced_network = self._analyze_single_network(network, current_time)
            analyzed_networks.append(enhanced_network)
            
            # Flag as high-risk if score >= 80 (more conservative threshold)
            # Most legitimate networks should score below 50
            threat_score = enhanced_network.get('Advanced_Threat_Score', 0)
            if threat_score >= 80:
                high_risk_networks.append(enhanced_network)
        
        log.info(f"Genuine analysis: {len(analyzed_networks)} networks, {len(high_risk_networks)} potential threats")
        return analyzed_networks, high_risk_networks
    
    def _analyze_single_network(self, network, current_time):
        """Analyze a single network for technical rogue indicators"""
        enhanced = network.copy()
        bssid = network.get('BSSID', '')
        ssid = network.get('SSID', '')
        
        threat_score = 0
        threat_reasons = []
        
        # 1. MAC Address Analysis (Most reliable indicator)
        mac_score, mac_reasons = self._analyze_mac_address(bssid)
        threat_score += mac_score
        threat_reasons.extend(mac_reasons)
        
        # 2. Signal Analysis (Physical characteristics)
        signal_score, signal_reasons = self._analyze_signal_characteristics(network, bssid)
        threat_score += signal_score
        threat_reasons.extend(signal_reasons)
        
        # 3. Temporal Behavior Analysis
        temporal_score, temporal_reasons = self._analyze_temporal_behavior(bssid, current_time)
        threat_score += temporal_score
        threat_reasons.extend(temporal_reasons)
        
        # 4. Protocol/Technical Analysis
        protocol_score, protocol_reasons = self._analyze_protocol_behavior(network, bssid)
        threat_score += protocol_score
        threat_reasons.extend(protocol_reasons)
        
        # 5. Hardware Vendor Analysis (OUI-based)
        vendor_score, vendor_reasons = self._analyze_hardware_vendor(network)
        threat_score += vendor_score
        threat_reasons.extend(vendor_reasons)
        
        # Debug high scores for legitimate networks
        if threat_score >= 50:  # Debug any significant scoring
            ssid = network.get('SSID', 'Hidden')
            log.info(f"THREAT SCORE DEBUG - {ssid} ({bssid}): Score={threat_score}, Reasons: {threat_reasons}")
        
        # Determine threat level based on score
        if threat_score >= 80:
            threat_level = "Critical"
        elif threat_score >= 60:
            threat_level = "High" 
        elif threat_score >= 35:
            threat_level = "Medium"
        else:
            threat_level = "Low"
        
        # Update enhanced network data
        enhanced.update({
            'Advanced_Threat_Score': threat_score,
            'Advanced_Threat_Level': threat_level,
            'Advanced_Reasons': ', '.join(threat_reasons) if threat_reasons else 'No technical anomalies detected',
            'Detection_Method': 'Technical Analysis',
            'Analysis_Time': datetime.now().strftime('%H:%M:%S'),
            # Also add legacy fields for backward compatibility
            'Threat_Score': threat_score,
            'Threat_Level': threat_level,
            'Threat_Reasons': ', '.join(threat_reasons) if threat_reasons else 'No technical anomalies detected'
        })
        
        return enhanced
    
    def _analyze_mac_address(self, bssid):
        """Analyze MAC address for rogue indicators"""
        score = 0
        reasons = []
        
        if not bssid or len(bssid) < 17:
            return 0, []
        
        # Check for locally administered MAC address (2nd bit of first octet)
        # Note: Many legitimate devices use MAC randomization, so this should have low penalty
        try:
            first_octet = int(bssid[:2], 16)
            if first_octet & 0x02:  # Locally administered bit set
                # Reduced penalty - legitimate devices often use MAC randomization
                score += 5  # Reduced from 15 to 5
                reasons.append("Locally administered MAC (may be legitimate randomization)")
        except ValueError:
            pass
        
        # Check for sequential MAC patterns (common in rogue AP tools)
        if self._detect_sequential_macs(bssid):
            score += 20
            reasons.append("Sequential MAC address pattern detected")
        
        # Check against known development board OUIs
        mac_oui = bssid[:8].lower()
        if mac_oui in self.dev_board_ouis:
            score += self.thresholds['hardware']['dev_board_penalty']
            reasons.append("Development board hardware detected")
        
        return score, reasons
    
    def _analyze_signal_characteristics(self, network, bssid):
        """Analyze signal strength patterns for anomalies"""
        score = 0
        reasons = []
        
        try:
            current_signal = float(network.get('Signal', '-100'))
        except (ValueError, TypeError):
            return 0, []
        
        # Check for impossibly strong signal (device very close)
        if current_signal > self.thresholds['signal']['impossibly_strong']:
            score += 25
            reasons.append(f"Unusually strong signal ({current_signal} dBm)")
        
        # Check for suspicious proximity (potential rogue device nearby)
        elif current_signal > self.thresholds['signal']['suspicious_strength']:
            score += 15
            reasons.append("Signal strength suggests close proximity")
        
        # Analyze signal variation over time
        history = self.network_history.get(bssid, [])
        if len(history) >= 3:
            recent_signals = []
            for entry in history[-5:]:  # Last 5 observations
                try:
                    sig = float(entry['data'].get('Signal', '-100'))
                    recent_signals.append(sig)
                except (ValueError, TypeError):
                    continue
            
            if len(recent_signals) >= 3:
                signal_variation = max(recent_signals) - min(recent_signals)
                if signal_variation > self.thresholds['signal']['rapid_variation']:
                    score += 10
                    reasons.append("Rapid signal strength variations")
        
        return score, reasons
    
    def _analyze_temporal_behavior(self, bssid, current_time):
        """Analyze temporal patterns for rogue behavior"""
        score = 0
        reasons = []
        
        history = self.network_history.get(bssid, [])
        if len(history) < 10:  # Need many more data points to avoid false positives
            return 0, []
        
        timestamps = [entry['timestamp'] for entry in history]
        
        # Check network lifespan - only flag if extremely short AND very unstable  
        lifespan = max(timestamps) - min(timestamps)
        if lifespan < self.thresholds['timing']['short_lifespan'] and len(history) >= 20:
            # Only flag if network appeared/disappeared MANY times in short period
            score += 10  # Further reduced score
            reasons.append(f"Very unstable network with short lifespan ({int(lifespan/60)} minutes)")
        
        # Check for rapid on/off cycling - much more strict criteria
        if len(history) >= 20:  # Need MANY more samples to avoid false positives
            time_gaps = []
            for i in range(1, len(timestamps)):
                gap = timestamps[i] - timestamps[i-1]
                time_gaps.append(gap)
            
            # Look for consistent rapid cycling pattern (very strict)
            very_short_gaps = [gap for gap in time_gaps if gap < 30]  # Less than 30 seconds
            if len(very_short_gaps) > (len(time_gaps) * 0.8):  # 80% must be very short
                score += 15  # Reduced score
                reasons.append("Extremely rapid cycling pattern detected")
        
        # Remove burst appearance check as it flags legitimate networks
        # during normal scanning
        
        return score, reasons
    
    def _analyze_protocol_behavior(self, network, bssid):
        """Analyze 802.11 protocol behavior for anomalies"""
        score = 0
        reasons = []
        
        # Check for channel hopping
        history = self.network_history.get(bssid, [])
        if len(history) >= 3:
            channels = []
            for entry in history:
                channel = entry['data'].get('Channel')
                if channel and channel != 'N/A':
                    try:
                        channels.append(int(channel))
                    except (ValueError, TypeError):
                        continue
            
            unique_channels = set(channels)
            if len(unique_channels) > self.thresholds['protocol']['channel_hop_threshold']:
                score += 25
                reasons.append(f"Channel hopping detected ({len(unique_channels)} channels)")
        
        # Check security configuration anomalies
        security = network.get('Security', '')
        if security:
            # Look for mixed security configurations (rare in legitimate APs)
            if 'WPA' in security and 'Open' in security:
                score += self.thresholds['protocol']['security_inconsistency']
                reasons.append("Mixed security configuration detected")
            
            # WEP in modern times is suspicious
            elif security == 'WEP':
                score += 15
                reasons.append("Outdated WEP security (potential honeypot)")
        
        return score, reasons
    
    def _analyze_hardware_vendor(self, network):
        """Analyze hardware vendor for suspicious characteristics"""
        score = 0
        reasons = []
        
        vendor = network.get('Vendor', '').lower()
        
        # Note: We don't penalize "Unknown" vendors as many legitimate devices 
        # have unknown OUIs. Only flag specifically suspicious ones.
        
        suspicious_vendors = [
            'raspberry pi',
            'espressif inc',
            'arduino'
        ]
        
        if any(susp in vendor for susp in suspicious_vendors):
            score += 20
            reasons.append("Development/hobbyist hardware vendor")
        
        return score, reasons
    
    def _detect_sequential_macs(self, bssid):
        """Detect if this MAC is part of a sequential pattern"""
        if not bssid:
            return False
        
        try:
            current_mac_int = int(bssid.replace(':', ''), 16)
        except ValueError:
            return False
        
        # Check against recently seen MACs for sequential patterns
        # Make this more strict to avoid false positives
        sequential_count = 0
        for other_bssid in self.network_history.keys():
            if other_bssid != bssid:
                try:
                    other_mac_int = int(other_bssid.replace(':', ''), 16)
                    diff = abs(current_mac_int - other_mac_int)
                    # Check if MACs are sequential (within 3 addresses, very strict)
                    if 1 <= diff <= 3:
                        sequential_count += 1
                except ValueError:
                    continue
        
        # Require at least 3 sequential MACs to be suspicious
        return sequential_count >= 3
    
    def _update_network_history(self, networks, current_time):
        """Update network history for behavioral analysis with memory management"""
        max_entries_per_network = 50  # Limit entries per network to prevent memory growth
        
        for network in networks:
            bssid = network.get('BSSID')
            if bssid:
                # Add new entry
                self.network_history[bssid].append({
                    'timestamp': current_time,
                    'data': network.copy()
                })
                
                # Keep only recent history (last 4 hours) AND limit entries
                cutoff_time = current_time - 14400  # 4 hours
                recent_entries = [
                    entry for entry in self.network_history[bssid]
                    if entry['timestamp'] > cutoff_time
                ]
                
                # Limit to max entries per network, keeping the most recent
                if len(recent_entries) > max_entries_per_network:
                    recent_entries = recent_entries[-max_entries_per_network:]
                
                self.network_history[bssid] = recent_entries
        
        # Cleanup old networks that haven't been seen recently
        networks_to_remove = []
        for bssid, history in self.network_history.items():
            if not history or (current_time - history[-1]['timestamp']) > 86400:  # 24 hours
                networks_to_remove.append(bssid)
        
        for bssid in networks_to_remove:
            del self.network_history[bssid]
    
    def get_detection_summary(self):
        """Get summary of detection statistics"""
        total_networks = len(self.network_history)
        current_time = time.time()
        
        # Count networks by observation frequency
        frequent_networks = 0
        recent_networks = 0
        
        for bssid, history in self.network_history.items():
            if len(history) > 5:
                frequent_networks += 1
            
            recent_entries = [e for e in history if e['timestamp'] > (current_time - 3600)]
            if recent_entries:
                recent_networks += 1
        
        return {
            'total_networks_tracked': total_networks,
            'frequent_networks': frequent_networks,
            'recent_networks': recent_networks,
            'detection_method': 'Technical Analysis Only',
            'last_analysis': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
