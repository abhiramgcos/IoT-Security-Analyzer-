import nmap
import socket
from typing import List, Dict
from backend.logger import Logger
from backend.config import settings
from backend.database import Database
from backend.services.fingerprinter import DeviceFingerprinter

logger = Logger('network_scanner').get_logger()

class NetworkScanner:
    def __init__(self, subnet: str, interface: str = "eth0"):
        self.subnet = subnet
        self.interface = interface
        self.db = Database()
        self.fingerprinter = DeviceFingerprinter()
    
    def scan_network(self) -> List[Dict]:
        """Perform network scan with deep fingerprinting"""
        logger.info(f"Starting professional scan on {self.subnet}")
        devices = []
        
        try:
            nm = nmap.PortScanner()
            # -sn: Host discovery
            nm.scan(hosts=self.subnet, arguments='-sn -T4')
            
            active_hosts = [h for h in nm.all_hosts() if nm[h].state() == 'up']
            logger.info(f"Host discovery found {len(active_hosts)} active devices")
            
            for host in active_hosts:
                try:
                    # Basic info
                    mac = nm[host]['addresses'].get('mac', '')
                    hostname = nm[host].hostname() or "Unknown"
                    
                    # Perform deep scan on this host
                    # -sV: Version detection (banners)
                    # -O: OS detection
                    # --version-intensity 2: Light version scan to save time (increase for precision)
                    logger.info(f"Fingerprinting {host}...")
                    deep_nm = nmap.PortScanner()
                    deep_nm.scan(host, arguments='-sV -O --version-intensity 2 -T4')
                    
                    # Extract Ports and Banners
                    open_ports = []
                    banners = {}
                    
                    if host in deep_nm.all_hosts():
                        if 'tcp' in deep_nm[host]:
                            for port, meta in deep_nm[host]['tcp'].items():
                                if meta['state'] == 'open':
                                    open_ports.append(port)
                                    # Construct a banner string from product + version + extra
                                    product = meta.get('product', '')
                                    version = meta.get('version', '')
                                    extrainfo = meta.get('extrainfo', '')
                                    full_banner = f"{product} {version} {extrainfo}".strip()
                                    if full_banner:
                                        banners[port] = f"Server: {full_banner}" # Simulate header style for fingerprinter
                        
                        # OS Match
                        os_match = "Unknown"
                        if 'osmatch' in deep_nm[host] and deep_nm[host]['osmatch']:
                            # Take the highest accuracy match
                            os_match = deep_nm[host]['osmatch'][0]['name']

                    # Run Fingerprinter Model
                    fingerprint = self.fingerprinter.fingerprint(
                        mac_address=mac,
                        ip_address=host,
                        open_ports=open_ports,
                        banners=banners,
                        os_match=os_match
                    )
                    
                    device_info = {
                        'ip_address': host,
                        'mac_address': mac,
                        'hostname': hostname,
                        'manufacturer': fingerprint['manufacturer'],
                        'model': fingerprint['model'],
                        'device_type': fingerprint['device_type'],
                        'cpe': fingerprint.get('cpe'),
                        'open_ports': open_ports,
                        'status': 'online',
                    }
                    
                    # Save to database
                    self.db.upsert_device(device_info)
                    devices.append(device_info)
                    
                except Exception as e:
                    logger.error(f"Deep scan failed for {host}: {e}")
                    # Fallback to basic info
                    devices.append({
                        'ip_address': host,
                        'mac_address': nm[host]['addresses'].get('mac', ''),
                        'status': 'online',
                         'manufacturer': 'Unknown'
                    })

            logger.info(f"Scan completed: {len(devices)} devices fingerprinting")
            return devices
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return []
    
    # Helper for legacy calls if any
    def _guess_device_type(self, vendor: str, ip: str) -> str:
        return "Unknown"
