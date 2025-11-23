# This software is licensed under the MIT License: https://github.com/Rudii-25/WiFi_Penetration 
# Developer: Rudra Sharma - https://rudrasharma25.com 
# sniffguard/core/enhanced_monitor.py

import subprocess
import time
import re
from utils.logger import log

class EnhancedMonitorMode:
    def __init__(self):
        self.supported_drivers = {
            'ath9k': {'method': 'iw', 'stability': 'high'},
            'ath10k': {'method': 'iw', 'stability': 'medium'},
            'iwlwifi': {'method': 'iw', 'stability': 'medium'},
            'rt2x00': {'method': 'airmon', 'stability': 'high'},
            'rtl8812au': {'method': 'airmon', 'stability': 'high'},
            'rtl8188eu': {'method': 'airmon', 'stability': 'medium'},
            'mt76': {'method': 'iw', 'stability': 'medium'},
            'brcmfmac': {'method': 'nexmon', 'stability': 'low'}
        }
        
        self.known_issues = {
            'iwlwifi': ['May require iwlwifi firmware reload', 'Monitor mode limited on some versions'],
            'brcmfmac': ['Requires Nexmon patches', 'Limited monitor mode support'],
            'rtl8821au': ['Driver may be unstable in monitor mode', 'Consider using aircrack-ng drivers']
        }
        
    def analyze_interface_compatibility(self, interface):
        """Comprehensive interface compatibility analysis"""
        analysis = {
            'interface': interface,
            'exists': False,
            'driver': 'unknown',
            'chipset': 'unknown',
            'monitor_support': False,
            'recommended_method': 'iw',
            'stability_rating': 'unknown',
            'known_issues': [],
            'capabilities': [],
            'recommendations': []
        }
        
        try:
            # Check if interface exists
            if not self._interface_exists(interface):
                analysis['error'] = f"Interface {interface} does not exist"
                return analysis
            
            analysis['exists'] = True
            
            # Get driver information
            driver_info = self._get_driver_info(interface)
            analysis.update(driver_info)
            
            # Check monitor mode support
            monitor_support = self._check_monitor_support(interface)
            analysis.update(monitor_support)
            
            # Get interface capabilities
            capabilities = self._get_interface_capabilities(interface)
            analysis['capabilities'] = capabilities
            
            # Generate recommendations
            recommendations = self._generate_recommendations(analysis)
            analysis['recommendations'] = recommendations
            
            log.info(f"Interface analysis complete for {interface}: {analysis['driver']} driver, "
                    f"monitor support: {analysis['monitor_support']}")
            
        except Exception as e:
            log.error(f"Error analyzing interface {interface}: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _interface_exists(self, interface):
        """Check if interface exists"""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', interface],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_driver_info(self, interface):
        """Get detailed driver information"""
        driver_info = {
            'driver': 'unknown',
            'driver_version': 'unknown',
            'chipset': 'unknown',
            'firmware_version': 'unknown'
        }
        
        try:
            # Get driver from ethtool
            result = subprocess.run(
                ['ethtool', '-i', interface],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse driver info
                for line in output.split('\n'):
                    if line.startswith('driver:'):
                        driver_info['driver'] = line.split(':', 1)[1].strip()
                    elif line.startswith('version:'):
                        driver_info['driver_version'] = line.split(':', 1)[1].strip()
                    elif line.startswith('firmware-version:'):
                        driver_info['firmware_version'] = line.split(':', 1)[1].strip()
            
            # Try alternative method using sysfs
            if driver_info['driver'] == 'unknown':
                try:
                    with open(f'/sys/class/net/{interface}/device/uevent', 'r') as f:
                        content = f.read()
                        if 'DRIVER=' in content:
                            for line in content.split('\n'):
                                if line.startswith('DRIVER='):
                                    driver_info['driver'] = line.split('=', 1)[1]
                                    break
                except (FileNotFoundError, PermissionError):
                    pass
            
            # Get chipset information from lspci/lsusb
            chipset = self._get_chipset_info(interface)
            if chipset:
                driver_info['chipset'] = chipset
            
        except Exception as e:
            log.debug(f"Error getting driver info for {interface}: {e}")
        
        return driver_info
    
    def _get_chipset_info(self, interface):
        """Get chipset information"""
        try:
            # Try to get PCI info first
            result = subprocess.run(['lspci'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Network controller' in line or 'Wireless' in line:
                        # Extract chipset name
                        parts = line.split(': ', 1)
                        if len(parts) > 1:
                            return parts[1].strip()
            
            # Try USB info
            result = subprocess.run(['lsusb'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '802.11' in line.lower() or 'wireless' in line.lower():
                        # Extract device info
                        parts = line.split(' ', 6)
                        if len(parts) > 6:
                            return parts[6].strip()
        
        except Exception as e:
            log.debug(f"Error getting chipset info: {e}")
        
        return 'unknown'
    
    def _check_monitor_support(self, interface):
        """Check monitor mode support using multiple methods"""
        support_info = {
            'monitor_support': False,
            'supported_modes': [],
            'current_mode': 'unknown'
        }
        
        try:
            # Method 1: iw list
            result = subprocess.run(
                ['iw', 'list'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout
                # Look for supported interface modes
                if 'Supported interface modes:' in output:
                    in_modes_section = False
                    modes = []
                    
                    for line in output.split('\n'):
                        line = line.strip()
                        if 'Supported interface modes:' in line:
                            in_modes_section = True
                            continue
                        elif in_modes_section and line.startswith('*'):
                            mode = line.replace('*', '').strip()
                            modes.append(mode)
                            if 'monitor' in mode.lower():
                                support_info['monitor_support'] = True
                        elif in_modes_section and not line.startswith('*') and line:
                            break
                    
                    support_info['supported_modes'] = modes
            
            # Method 2: Check current mode
            result = subprocess.run(
                ['iw', 'dev', interface, 'info'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'type' in line:
                        support_info['current_mode'] = line.split('type')[1].strip()
                        break
            
            # Method 3: Try iwconfig as fallback
            if not support_info['monitor_support']:
                result = subprocess.run(
                    ['iwconfig', interface],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0 and 'Mode:' in result.stdout:
                    # If iwconfig works, assume monitor mode is possible
                    support_info['monitor_support'] = True
                    support_info['supported_modes'].append('monitor (iwconfig)')
        
        except Exception as e:
            log.debug(f"Error checking monitor support for {interface}: {e}")
        
        return support_info
    
    def _get_interface_capabilities(self, interface):
        """Get detailed interface capabilities"""
        capabilities = []
        
        try:
            # Check for injection support
            if self._test_packet_injection(interface):
                capabilities.append('packet_injection')
            
            # Check for frequency support
            freqs = self._get_supported_frequencies(interface)
            if freqs:
                capabilities.extend([f'freq_{freq}' for freq in freqs[:5]])  # Limit to first 5
            
            # Check for TX power control
            if self._check_tx_power_control(interface):
                capabilities.append('tx_power_control')
            
        except Exception as e:
            log.debug(f"Error getting capabilities for {interface}: {e}")
        
        return capabilities
    
    def _test_packet_injection(self, interface):
        """Test if interface supports packet injection"""
        try:
            # This is a simplified test - in practice, you'd need to test actual injection
            result = subprocess.run(
                ['iw', 'list'],
                capture_output=True, text=True, timeout=5
            )
            
            # Look for injection-related features
            if result.returncode == 0:
                output = result.stdout.lower()
                injection_indicators = ['ap', 'monitor', 'mesh point']
                return any(indicator in output for indicator in injection_indicators)
            
        except Exception:
            pass
        
        return False
    
    def _get_supported_frequencies(self, interface):
        """Get supported frequencies/channels"""
        try:
            result = subprocess.run(
                ['iw', 'list'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                frequencies = []
                in_freq_section = False
                
                for line in result.stdout.split('\n'):
                    if 'Frequencies:' in line:
                        in_freq_section = True
                        continue
                    elif in_freq_section and line.strip().startswith('*'):
                        # Extract frequency
                        freq_match = re.search(r'(\d{4})\s*MHz', line)
                        if freq_match:
                            frequencies.append(freq_match.group(1))
                    elif in_freq_section and not line.strip():
                        break
                
                return frequencies[:10]  # Return first 10 frequencies
        
        except Exception:
            pass
        
        return []
    
    def _check_tx_power_control(self, interface):
        """Check if TX power can be controlled"""
        try:
            result = subprocess.run(
                ['iw', 'dev', interface, 'info'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                return 'txpower' in result.stdout.lower()
        
        except Exception:
            pass
        
        return False
    
    def _generate_recommendations(self, analysis):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        driver = analysis.get('driver', 'unknown')
        monitor_support = analysis.get('monitor_support', False)
        
        if not monitor_support:
            recommendations.append('⚠️ Monitor mode may not be supported by this adapter')
            recommendations.append('💡 Consider using a compatible USB WiFi adapter')
            
            if driver in ['brcmfmac', 'brcmsmac']:
                recommendations.append('📦 Try installing Nexmon patches for Broadcom chipsets')
            elif 'rtl' in driver.lower():
                recommendations.append('📦 Install proper Realtek drivers from aircrack-ng repository')
        
        if driver in self.supported_drivers:
            info = self.supported_drivers[driver]
            method = info['method']
            stability = info['stability']
            
            analysis['recommended_method'] = method
            analysis['stability_rating'] = stability
            
            if method == 'airmon':
                recommendations.append('🔧 Use airmon-ng for enabling monitor mode')
            elif method == 'nexmon':
                recommendations.append('🔧 Requires Nexmon patches - check installation')
            
            if stability == 'low':
                recommendations.append('⚠️ This driver has known stability issues in monitor mode')
        
        if driver in self.known_issues:
            issues = self.known_issues[driver]
            analysis['known_issues'] = issues
            for issue in issues:
                recommendations.append(f'⚠️ Known issue: {issue}')
        
        # Add general recommendations
        if monitor_support:
            recommendations.append('✅ Interface appears to support monitor mode')
            recommendations.append('🔧 Stop NetworkManager before enabling monitor mode')
            recommendations.append('🔧 Ensure no other processes are using the interface')
        
        return recommendations
    
    def enable_monitor_mode_enhanced(self, interface):
        """Enhanced monitor mode enabling with multiple fallback methods"""
        analysis = self.analyze_interface_compatibility(interface)
        
        if not analysis['exists']:
            return False, f"Interface {interface} does not exist"
        
        if not analysis['monitor_support']:
            log.warning(f"Monitor mode support uncertain for {interface}")
        
        # Try multiple methods based on driver
        driver = analysis.get('driver', 'unknown')
        recommended_method = analysis.get('recommended_method', 'iw')
        
        log.info(f"Attempting to enable monitor mode on {interface} using {recommended_method} method")
        
        # Method 1: Standard iw approach
        if recommended_method == 'iw':
            success, message = self._enable_monitor_iw(interface)
            if success:
                return True, message
            log.warning(f"Standard iw method failed: {message}")
        
        # Method 2: airmon-ng approach
        if recommended_method == 'airmon' or not success:
            success, message = self._enable_monitor_airmon(interface)
            if success:
                return True, message
            log.warning(f"airmon-ng method failed: {message}")
        
        # Method 3: Manual approach with interface recreation
        log.info("Trying manual monitor mode setup...")
        success, message = self._enable_monitor_manual(interface)
        if success:
            return True, message
        
        return False, "All monitor mode enabling methods failed"
    
    def _enable_monitor_iw(self, interface):
        """Enable monitor mode using iw commands"""
        try:
            # Standard approach from the original code
            commands = [
                ['sudo', 'ip', 'link', 'set', interface, 'down'],
                ['sudo', 'iw', interface, 'set', 'type', 'monitor'],
                ['sudo', 'ip', 'link', 'set', interface, 'up']
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                
                if result.returncode != 0:
                    return False, f"Command failed: {' '.join(cmd)} - {result.stderr}"
            
            # Verify monitor mode
            if self._verify_monitor_mode(interface):
                return True, f"Monitor mode enabled on {interface}"
            else:
                return False, "Monitor mode enabling appeared successful but verification failed"
        
        except Exception as e:
            return False, f"Error enabling monitor mode: {e}"
    
    def _enable_monitor_airmon(self, interface):
        """Enable monitor mode using airmon-ng"""
        try:
            # Check if airmon-ng is available
            result = subprocess.run(
                ['which', 'airmon-ng'],
                capture_output=True, timeout=5
            )
            
            if result.returncode != 0:
                return False, "airmon-ng not found"
            
            # Kill conflicting processes
            subprocess.run(
                ['sudo', 'airmon-ng', 'check', 'kill'],
                capture_output=True, timeout=30
            )
            
            # Enable monitor mode
            result = subprocess.run(
                ['sudo', 'airmon-ng', 'start', interface],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                # airmon-ng usually creates a new interface like wlan0mon
                new_interface = f"{interface}mon"
                
                # Check if new interface exists
                if self._interface_exists(new_interface):
                    if self._verify_monitor_mode(new_interface):
                        return True, f"Monitor mode enabled on {new_interface}"
                
                # Check if original interface is in monitor mode
                if self._verify_monitor_mode(interface):
                    return True, f"Monitor mode enabled on {interface}"
            
            return False, f"airmon-ng failed: {result.stderr}"
        
        except Exception as e:
            return False, f"Error with airmon-ng: {e}"
    
    def _enable_monitor_manual(self, interface):
        """Manual monitor mode enabling with interface recreation"""
        try:
            # This is an advanced method that recreates the interface
            log.info("Attempting manual monitor mode setup...")
            
            # Get current interface info
            result = subprocess.run(
                ['iw', 'dev', interface, 'info'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode != 0:
                return False, "Cannot get interface info"
            
            # Extract phy info
            phy_match = re.search(r'wiphy (\d+)', result.stdout)
            if not phy_match:
                return False, "Cannot determine phy number"
            
            phy_num = phy_match.group(1)
            
            # Delete and recreate interface in monitor mode
            commands = [
                ['sudo', 'iw', 'dev', interface, 'del'],
                ['sudo', 'iw', f'phy{phy_num}', 'interface', 'add', f'{interface}mon', 'type', 'monitor'],
                ['sudo', 'ip', 'link', 'set', f'{interface}mon', 'up']
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                
                if result.returncode != 0:
                    log.debug(f"Manual method command failed: {' '.join(cmd)} - {result.stderr}")
                    # Try to restore original interface
                    subprocess.run(
                        ['sudo', 'iw', f'phy{phy_num}', 'interface', 'add', interface, 'type', 'managed'],
                        capture_output=True, timeout=10
                    )
                    return False, f"Manual method failed at: {' '.join(cmd)}"
            
            # Verify new monitor interface
            new_interface = f"{interface}mon"
            if self._verify_monitor_mode(new_interface):
                return True, f"Monitor mode enabled on {new_interface} (manual method)"
            
            return False, "Manual method completed but verification failed"
        
        except Exception as e:
            return False, f"Manual method error: {e}"
    
    def _verify_monitor_mode(self, interface):
        """Verify that interface is in monitor mode"""
        try:
            result = subprocess.run(
                ['iw', 'dev', interface, 'info'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                return 'type monitor' in result.stdout.lower()
            
        except Exception:
            pass
        
        return False
    
    def get_interface_recommendations(self, interface=None):
        """Get recommendations for interface or general WiFi adapter recommendations"""
        if interface:
            analysis = self.analyze_interface_compatibility(interface)
            return analysis.get('recommendations', [])
        else:
            # General recommendations for buying/choosing adapters
            return [
                "🏆 Recommended USB adapters for penetration testing:",
                "   • Alfa AWUS036ACS (802.11ac, dual-band)",
                "   • Alfa AWUS036ACH (high power, excellent range)",
                "   • TP-Link AC600 T2U Plus (budget option)",
                "   • Panda PAU09 (compact, reliable)",
                "",
                "📋 What to look for in WiFi adapters:",
                "   • Atheros chipsets (ath9k, ath10k) - best compatibility",
                "   • Ralink/MediaTek chipsets (rt2x00, mt76) - good support",
                "   • Avoid Broadcom chipsets without Nexmon patches",
                "   • Check for monitor mode and packet injection support",
                "",
                "⚠️ Chipsets to avoid:",
                "   • Most built-in laptop WiFi (limited monitor support)",
                "   • Broadcom without Nexmon patches",
                "   • Some newer Realtek drivers (unstable)"
            ]
