
from typing import Dict, List, Optional
from backend.logger import Logger
import re

logger = Logger('fingerprinter').get_logger()

class DeviceFingerprinter:
    def __init__(self):
        # Initialize MAC parser if available
        try:
            from manuf import manuf
            self.mac_parser = manuf.MacParser(update=False)
        except ImportError:
            self.mac_parser = None
            logger.warning("manuf module not found, MAC lookup will be limited")

    def fingerprint(self, mac_address: str, ip_address: str, open_ports: List[int], banners: Dict[int, str] = None, os_match: str = None) -> Dict:
        """
        Identify device details based on available evidence.
        
        Args:
            mac_address: Device MAC
            ip_address: Device IP
            open_ports: List of open ports
            banners: Dictionary of port -> service banner string
            os_match: OS detection string from Nmap
            
        Returns:
            Dict containing: manufacturer, model, version, device_type, cpe, confidence_score
        """
        evidence = {
            "mac_vendor": self._get_mac_vendor(mac_address),
            "ports": set(open_ports),
            "banners": banners or {},
            "os": os_match
        }
        
        # 0. Normalize Manufacturer Name
        evidence["mac_vendor"] = self._normalize_vendor(evidence["mac_vendor"])

        # 1. Deduce Manuf/Model
        manufacturer = evidence["mac_vendor"]
        model = "Unknown"
        version = None
        device_type = "Unknown"
        confidence = 0.0

        # Heuristic 1: MAC Vendor provides baseline manufacturer
        if manufacturer != "Unknown":
            confidence += 0.3
            
        # Heuristic 2: Service Banners often contain specific model info
        # Example: "Server: Tasmota/9.5.0"
        for port, banner in evidence["banners"].items():
            if not banner:
                continue
                
            # HTTP Server Header Check
            if "Server:" in banner:
                server_sig = banner.split("Server:")[1].split("\r\n")[0].strip()
                
                if "Tasmota" in server_sig:
                    model = "Tasmota Device"
                    device_type = "IoT Controller"
                    manufacturer = "Espressif" if manufacturer == "Unknown" else manufacturer
                    # Extract version
                    v_match = re.search(r'Tasmota/([\d\.]+)', server_sig)
                    if v_match:
                        version = v_match.group(1)
                    confidence += 0.5
                    
                elif "Boa" in server_sig:
                    device_type = "Router" # Boa is common on older routers
                    confidence += 0.1
                    
                elif "Hikvision" in server_sig or "Hik" in server_sig:
                    manufacturer = "Hikvision"
                    device_type = "Camera"
                    model = "IP Camera"
                    confidence += 0.6
                
                elif "Apache" in server_sig:
                    # Generic server
                    if device_type == "Unknown":
                        device_type = "Server"

            # SSH Banner Check
            if "SSH" in banner and ("OpenSSH" in banner or "Dropbear" in banner):
                # Generic Linux stuff, but Dropbear is common on embedded
                if "Dropbear" in banner:
                    device_type = "Embedded Device"
                    confidence += 0.1

        # Heuristic 3: Specific Port Profiles
        if device_type == "Unknown":
            if 554 in evidence["ports"]: # RTSP
                device_type = "Camera"
                confidence += 0.2
            elif 1883 in evidence["ports"]: # MQTT
                device_type = "IoT Device"
                confidence += 0.2
            elif 80 in evidence["ports"] and 443 in evidence["ports"] and 53 in evidence["ports"]:
                device_type = "Router" # DNS + Web
                confidence += 0.2
            elif 62078 in evidence["ports"]: # Common iOS sync port
                manufacturer = "Apple"
                device_type = "Mobile"
                confidence += 0.4
            elif 5000 in evidence["ports"] or 8000 in evidence["ports"] or 8080 in evidence["ports"]:
                 # Development ports often imply generic servers or desktops
                 if "Windows" in str(evidence["os"]):
                     device_type = "Workstation"
                 elif "Linux" in str(evidence["os"]):
                     device_type = "Linux Server"
        
        # Heuristic 4: OS Detection
        if evidence["os"] and evidence["os"] != "Unknown":
            if "Linux" in evidence["os"]:
                if device_type == "Unknown":
                    device_type = "Linux Server/Device"
            elif "Windows" in evidence["os"]:
                device_type = "Workstation"
                manufacturer = "Microsoft"
            elif "Android" in evidence["os"]:
                device_type = "Mobile/Tablet"
                manufacturer = "Google/Android OEM"        
                
        # Heuristic 5: Manufacturer implied types
        if device_type == "Unknown" and manufacturer != "Unknown":
            man_lower = manufacturer.lower()
            if "camera" in man_lower or "axis" in man_lower:
                device_type = "Camera"
            elif "router" in man_lower or "netgear" in man_lower or "linksys" in man_lower:
                device_type = "Router"
            elif "apple" in man_lower:
                device_type = "Mobile/Mac"
            elif "espressif" in man_lower:
                device_type = "IoT Controller"
            elif "xiaomi" in man_lower:
                device_type = "Smart Device"
                
        # Generate CPE
        cpe = self._generate_cpe(manufacturer, model, version, device_type)

        return {
            "manufacturer": manufacturer,
            "model": model,
            "version": version,
            "device_type": device_type,
            "cpe": cpe,
            "confidence": min(confidence, 1.0)
        }

    def _get_mac_vendor(self, mac_address: str) -> str:
        if not self.mac_parser or not mac_address:
            return "Unknown"
        try:
            return self.mac_parser.get_manuf(mac_address) or "Unknown"
        except:
            return "Unknown"

    def _generate_cpe(self, make: str, model: str, version: str, device_type: str) -> str:
        """
        Generate a CPE v2.3 string.
        Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        Part: h (hardware), o (os), a (application)
        """
        part = "h" # Default to hardware
        
        safe_make = self._clean_cpe_str(make)
        safe_model = self._clean_cpe_str(model)
        safe_ver = self._clean_cpe_str(version) if version else "*"
        
        if safe_make == "*":
            return None
            
        cpe = f"cpe:2.3:{part}:{safe_make}:{safe_model}:{safe_ver}:*:*:*:*:*:*:*"
        return cpe

    def _clean_cpe_str(self, s: str) -> str:
        if not s or s == "Unknown":
            return "*"
        # Lowercase and replace spaces with underscores, remove special chars
        s = s.lower()
        s = re.sub(r'[^a-z0-9_]', '_', s)
        s = re.sub(r'_+', '_', s) # Remove duplicate underscores
        return s.strip('_')

    def _normalize_vendor(self, vendor: str) -> str:
        """Clean up truncated or weird vendor names from OUI lookup"""
        if not vendor or vendor == "Unknown":
            return "Unknown"
        
        v_lower = vendor.lower()
        
        # Common truncated/weird names map
        normalization_map = {
            "espressi": "Espressif",
            "xiaomico": "Xiaomi",
            "shenzhen": "Generic Shenzhen OEM",
            "lavainte": "Lava International",
            "asustekc": "ASUS",
            "currento": "Current Options", # Example based on OUI
            "texasins": "Texas Instruments",
            "raspberry": "Raspberry Pi",
            "guozi": "Guozi", # Often cameras
            "d-linkin": "D-Link", 
            "tp-linkt": "TP-Link",
            "ubiquiti": "Ubiquiti",
            "synology": "Synology",
            "netgear": "Netgear",
            "hewlettp": "HP",
            "apple": "Apple",
            "intelcor": "Intel",
            "microsoft": "Microsoft"
        }
        
        # Direct lookup
        if vendor.lower() in normalization_map:
            return normalization_map[vendor.lower()]

        # Partial match
        for key, val in normalization_map.items():
            if key in v_lower:
                return val
                
        return vendor
