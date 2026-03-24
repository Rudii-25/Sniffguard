# sniffguard/utils/vendor_lookup.py
# MAC Address Vendor Lookup Utility

import requests
import time
import json
import os
from utils.logger import log

class VendorLookup:
    def __init__(self):
        self.cache = {}  # Local cache for vendor lookups
        self.cache_file = "logs/vendor_cache.json"
        self.load_cache()
        
        # Common OUI database (partial for offline use)
        self.common_ouis = {
            # Apple
            '00:03:93': 'Apple, Inc.',
            '00:0a:95': 'Apple, Inc.', 
            '00:0d:93': 'Apple, Inc.',
            '00:17:f2': 'Apple, Inc.',
            '00:1b:63': 'Apple, Inc.',
            '00:1e:c2': 'Apple, Inc.',
            '00:1f:f3': 'Apple, Inc.',
            '00:21:e9': 'Apple, Inc.',
            '00:23:12': 'Apple, Inc.',
            '00:23:df': 'Apple, Inc.',
            '00:25:00': 'Apple, Inc.',
            '00:25:4b': 'Apple, Inc.',
            '00:25:bc': 'Apple, Inc.',
            '00:26:08': 'Apple, Inc.',
            '00:26:4a': 'Apple, Inc.',
            '00:26:b0': 'Apple, Inc.',
            '00:26:bb': 'Apple, Inc.',
            # Samsung
            '00:12:fb': 'Samsung Electronics Co.,Ltd',
            '00:15:b9': 'Samsung Electronics Co.,Ltd',
            '00:16:32': 'Samsung Electronics Co.,Ltd',
            '00:17:c9': 'Samsung Electronics Co.,Ltd',
            '00:1a:8a': 'Samsung Electronics Co.,Ltd',
            '00:1b:98': 'Samsung Electronics Co.,Ltd',
            '00:1d:25': 'Samsung Electronics Co.,Ltd',
            '00:1e:7d': 'Samsung Electronics Co.,Ltd',
            '00:21:19': 'Samsung Electronics Co.,Ltd',
            '00:23:39': 'Samsung Electronics Co.,Ltd',
            '00:26:5d': 'Samsung Electronics Co.,Ltd',
            '00:26:e2': 'Samsung Electronics Co.,Ltd',
            # Google
            '00:1a:11': 'Google, Inc.',
            '00:25:9c': 'Google, Inc.',
            'da:a1:19': 'Google, Inc.',
            # Development boards (important for rogue detection)
            'b8:27:eb': 'Raspberry Pi Foundation',
            'dc:a6:32': 'Raspberry Pi Foundation',
            'e4:5f:01': 'Raspberry Pi Foundation',
            '24:0a:c4': 'Espressif Inc.',
            '30:ae:a4': 'Espressif Inc.',
            '84:cc:a8': 'Espressif Inc.',
            '94:b9:7e': 'Espressif Inc.',
            '18:fe:34': 'Espressif Inc.',
            '60:01:94': 'Espressif Inc.',
            # Routers/Networking
            '00:0f:66': 'Linksys',
            '00:14:6c': 'Netgear',
            '00:18:e7': 'Netgear',
            '00:1f:33': 'Netgear',
            '00:24:b2': 'Netgear',
            '00:26:f2': 'Netgear',
            '00:03:7f': 'Atheros Communications Inc.',
            '00:0b:6b': 'Intel Corporate',
            '00:13:e8': 'Intel Corporate',
            '00:15:00': 'Intel Corporate',
            '00:16:ea': 'Intel Corporate',
            '00:19:d1': 'Intel Corporate',
            '00:1b:77': 'Intel Corporate',
            '00:1c:bf': 'Intel Corporate',
            '00:1f:3a': 'Intel Corporate',
            '00:21:6a': 'Intel Corporate',
            '00:23:15': 'Intel Corporate',
            '00:24:d6': 'Intel Corporate',
            '00:27:10': 'Intel Corporate',
            # TP-Link
            '00:1f:3c': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            '00:23:cd': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            '00:25:86': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            '00:27:19': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            '14:cc:20': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            '50:c7:bf': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            '84:16:f9': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            'a0:f3:c1': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            'c4:e9:84': 'TP-LINK TECHNOLOGIES CO.,LTD.',
            # D-Link
            '00:05:5d': 'D-Link Corporation',
            '00:0f:3d': 'D-Link Corporation',
            '00:11:95': 'D-Link Corporation',
            '00:15:e9': 'D-Link Corporation',
            '00:17:9a': 'D-Link Corporation',
            '00:19:5b': 'D-Link Corporation',
            '00:1b:11': 'D-Link Corporation',
            '00:1c:f0': 'D-Link Corporation',
            '00:1e:58': 'D-Link Corporation',
            '00:21:91': 'D-Link Corporation',
            '00:22:b0': 'D-Link Corporation',
            '00:24:01': 'D-Link Corporation',
            '00:26:5a': 'D-Link Corporation',
            # ASUS
            '00:0e:a6': 'ASUSTek COMPUTER INC.',
            '00:11:2f': 'ASUSTek COMPUTER INC.',
            '00:13:d4': 'ASUSTek COMPUTER INC.',
            '00:15:f2': 'ASUSTek COMPUTER INC.',
            '00:17:31': 'ASUSTek COMPUTER INC.',
            '00:18:f3': 'ASUSTek COMPUTER INC.',
            '00:1a:92': 'ASUSTek COMPUTER INC.',
            '00:1b:fc': 'ASUSTek COMPUTER INC.',
            '00:1d:60': 'ASUSTek COMPUTER INC.',
            '00:1f:c6': 'ASUSTek COMPUTER INC.',
            '00:22:15': 'ASUSTek COMPUTER INC.',
            '00:23:54': 'ASUSTek COMPUTER INC.',
            '00:24:8c': 'ASUSTek COMPUTER INC.',
            '00:26:18': 'ASUSTek COMPUTER INC.',
            # Broadcom (common in routers)
            '00:10:18': 'Broadcom Corporation',
            '00:14:a5': 'Broadcom Corporation', 
            '00:17:10': 'Broadcom Corporation',
            '00:1a:1e': 'Broadcom Corporation',
            # Qualcomm Atheros
            '00:03:7f': 'Qualcomm Atheros',
            '00:15:af': 'Qualcomm Atheros',
            '00:19:07': 'Qualcomm Atheros',
            '00:1d:0f': 'Qualcomm Atheros',
            '00:24:2c': 'Qualcomm Atheros',
            '04:f0:21': 'Qualcomm Atheros',
            '18:1b:eb': 'Qualcomm Atheros',
            '20:f4:78': 'Qualcomm Atheros',
            '24:a0:74': 'Qualcomm Atheros',
            '40:a8:f0': 'Qualcomm Atheros',
            # Realtek
            '00:e0:4c': 'Realtek Semiconductor Co., Ltd.',
            '52:54:00': 'Realtek Semiconductor Co., Ltd.',
            '00:21:cc': 'Realtek Semiconductor Co., Ltd.',
            '10:7b:44': 'Realtek Semiconductor Co., Ltd.',
            '14:dd:a9': 'Realtek Semiconductor Co., Ltd.',
            '18:db:f2': 'Realtek Semiconductor Co., Ltd.',
            '2c:4d:54': 'Realtek Semiconductor Co., Ltd.',
            '50:eb:f6': 'Realtek Semiconductor Co., Ltd.',
            '98:de:d0': 'Realtek Semiconductor Co., Ltd.',
            # MediaTek
            '00:0c:43': 'Mediatek Inc.',
            '70:f1:1c': 'Mediatek Inc.',
            '9c:9d:7e': 'Mediatek Inc.',
            # Xiaomi
            '34:ce:00': 'Xiaomi Communications Co Ltd',
            '50:8f:4c': 'Xiaomi Communications Co Ltd',
            '64:09:80': 'Xiaomi Communications Co Ltd',
            '78:11:dc': 'Xiaomi Communications Co Ltd',
            '8c:be:be': 'Xiaomi Communications Co Ltd',
            # Huawei
            '00:e0:fc': 'Huawei Technologies Co.,Ltd',
            '28:6e:d4': 'Huawei Technologies Co.,Ltd',
            '4c:54:99': 'Huawei Technologies Co.,Ltd',
            '50:3d:e5': 'Huawei Technologies Co.,Ltd',
            '58:2a:f7': 'Huawei Technologies Co.,Ltd',
            '68:3e:34': 'Huawei Technologies Co.,Ltd',
            '84:a4:23': 'Huawei Technologies Co.,Ltd',
            'ac:85:3d': 'Huawei Technologies Co.,Ltd'
        }
    
    def get_vendor(self, mac_address, skip_online=False):
        """
        Get vendor information for a MAC address
        Args:
            mac_address: MAC address string (e.g., 'AA:BB:CC:DD:EE:FF')
            skip_online: If True, skip online lookups for faster response
        Returns:
            vendor name string or 'Unknown'
        """
        if not mac_address or len(mac_address) < 8:
            return 'Unknown'
        
        # Extract OUI (first 3 octets)
        oui = mac_address[:8].lower()
        
        # Check cache first (instant)
        if oui in self.cache:
            return self.cache[oui]
        
        # Check offline database (instant)
        if oui in self.common_ouis:
            vendor = self.common_ouis[oui]
            self.cache[oui] = vendor
            # Don't save cache for every lookup - batch save later
            return vendor
        
        # For fast scanning, skip online lookup by default
        if not skip_online:
            # Try online lookup (slow - only when explicitly requested)
            vendor = self._online_lookup(oui)
            if vendor and vendor != 'Unknown':
                self.cache[oui] = vendor
                return vendor
        
        # Default for unknown - cache it to avoid future lookups
        self.cache[oui] = 'Unknown'
        return 'Unknown'
    
    def _online_lookup(self, oui):
        """Perform online vendor lookup with multiple APIs"""
        try:
            # Method 1: macvendors.co API (free, no registration)
            url = f"https://macvendors.co/api/{oui.replace(':', '')}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('result') and data['result'].get('company'):
                    return data['result']['company']
        except Exception as e:
            log.debug(f"Online vendor lookup failed for {oui}: {e}")
        
        try:
            # Method 2: maclookup.app API (backup)
            clean_oui = oui.replace(':', '')
            url = f"https://maclookup.app/api/v2/macs/{clean_oui}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if not data.get('error') and data.get('company'):
                    return data['company']
        except Exception as e:
            log.debug(f"Backup vendor lookup failed for {oui}: {e}")
        
        return 'Unknown'
    
    def load_cache(self):
        """Load vendor cache from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                log.debug(f"Loaded {len(self.cache)} vendor entries from cache")
        except Exception as e:
            log.debug(f"Failed to load vendor cache: {e}")
            self.cache = {}
    
    def save_cache(self):
        """Save vendor cache to file"""
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            log.debug(f"Failed to save vendor cache: {e}")
    
    def bulk_lookup(self, mac_addresses, fast_mode=True):
        """
        Look up vendors for multiple MAC addresses efficiently
        Args:
            mac_addresses: List of MAC address strings
            fast_mode: If True, skip online lookups for instant results
        Returns:
            dict: {mac_address: vendor_name}
        """
        results = {}
        for mac in mac_addresses:
            if fast_mode:
                results[mac] = self.get_vendor(mac, skip_online=True)
            else:
                results[mac] = self.get_vendor(mac, skip_online=False)
                # Small delay to avoid rate limiting only for online lookups
                time.sleep(0.1)
        
        # Batch save cache after all lookups
        if results:
            self.save_cache()
        
        return results
    
    def fast_lookup(self, mac_address):
        """
        Fast vendor lookup using only cache and offline database
        Args:
            mac_address: MAC address string
        Returns:
            vendor name string or 'Unknown'
        """
        return self.get_vendor(mac_address, skip_online=True)

# Global instance
vendor_lookup = VendorLookup()
