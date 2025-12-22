
import nmap
import socket
from typing import List, Dict
from datetime import datetime
from backend.logger import Logger
from backend.database import Database

logger = Logger('network_scanner').get_logger()

class NetworkScanner:
    def __init__(self, subnet: str, interface: str = 'eth0'):
        self.subnet = subnet
        self.interface = interface
        self.nm = nmap.PortScanner()
        self.db = Database()

    def scan_network(self) -> List[Dict]:
        """Run Nmap scan on subnet"""
        logger.info(f"Starting generic scan on {self.subnet}")
        
        try:
            # -sn: Ping Scan - disable port scan
            # -PR: ARP Ping
            self.nm.scan(hosts=self.subnet, arguments='-sn -PR')
            
            hosts_list = [(x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()]
            devices = []
            
            for host, status in hosts_list:
                if status == 'up':
                    device_info = self._get_device_details(host)
                    self.db.upsert_device(device_info)
                    devices.append(device_info)
            
            return devices
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return []

    def _get_device_details(self, ip: str) -> Dict:
        """Get detailed info for a single host"""
        try:
            # Run aggressive scan on single host for OS detection and ports
            # -O: OS detection
            # -F: Fast mode (fewer ports)
            scan_res = self.nm.scan(ip, arguments='-O -F')
            
            mac = scan_res['scan'][ip]['addresses'].get('mac', 'Unknown')
            vendor = scan_res['scan'][ip].get('vendor', {}).get(mac, 'Unknown')
            
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = scan_res['scan'][ip]['hostnames'][0]['name'] if scan_res['scan'][ip]['hostnames'] else 'Unknown'

            # Get open ports
            open_ports = []
            if 'tcp' in scan_res['scan'][ip]:
                for port, port_data in scan_res['scan'][ip]['tcp'].items():
                    if port_data['state'] == 'open':
                        open_ports.append(port)

            return {
                "ip_address": ip,
                "mac_address": mac,
                "hostname": hostname,
                "manufacturer": vendor,
                "device_type": "Unknown", # Would need deeper fingerprinting
                "model": "Unknown",
                "open_ports": open_ports
            }
            
        except Exception as e:
            logger.error(f"Error detailing {ip}: {e}")
            return {
                "ip_address": ip,
                "mac_address": "Unknown",
                "hostname": "Unknown",
                "manufacturer": "Unknown",
                "model": "Unknown",
                "device_type": "Unknown",
                "open_ports": []
            }
