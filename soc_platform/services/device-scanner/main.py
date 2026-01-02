import time
import os
import logging
import json
import nmap
import netifaces
import psycopg2
from psycopg2.extras import RealDictCursor
import redis
import requests
from manuf import manuf

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("device-scanner")

# Config
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "300"))

# Initialize parsers
nm = nmap.PortScanner()
mac_parser = manuf.MacParser(update=False)

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def get_local_subnet():
    """Get local subnet CIDR (e.g., 192.168.1.0/24)"""
    try:
        gateways = netifaces.gateways()
        default = gateways.get('default', {}).get(netifaces.AF_INET)
        if not default:
            return "192.168.1.0/24"
            
        iface = default[1]
        addrs = netifaces.ifaddresses(iface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        mask = ip_info['netmask']
        
        # Simple heuristic: assume /24 for now if mask analysis is complex
        # Or calculate properly:
        ip_parts = ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    except Exception as e:
        logger.error(f"Error checking subnet: {e}")
        return "192.168.1.0/24"

def scan_network():
    subnet = get_local_subnet()
    logger.info(f"Starting scan on {subnet}...")
    
    try:
        # Ping scan + OS detection + Service version
        # -sn = ping scan (disable port scan) - fast
        # -O = OS detection (requires root/sudo, container has capabilities)
        nm.scan(hosts=subnet, arguments='-sn')
        
        hosts = nm.all_hosts()
        logger.info(f"Found {len(hosts)} hosts")
        
        conn = get_db_connection()
        cur = conn.cursor()
        r = redis.from_url(REDIS_URL)

        for host in hosts:
            try:
                # Extract details
                mac = nm[host]['addresses'].get('mac')
                ip = nm[host]['addresses'].get('ipv4')
                vendor = nm[host]['vendor'].get(mac, '')
                
                if not mac:
                    continue

                # Enhance vendor lookup
                if not vendor:
                    vendor = mac_parser.get_manuf(mac) or "Unknown"

                # Hostname
                hostname = nm[host].hostname()
                
                logger.info(f"Device: {ip} ({mac}) - {vendor}")

                # Upsert into DB
                cur.execute("""
                    INSERT INTO devices (ip_address, mac_address, hostname, manufacturer, last_seen)
                    VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (mac_address) 
                    DO UPDATE SET 
                        ip_address = EXCLUDED.ip_address,
                        hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
                        last_seen = NOW();
                """, (ip, mac, hostname, vendor))
                
                # Notify UI via Redis
                msg = {
                    "type": "device_discovered",
                    "data": {
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "hostname": hostname
                    }
                }
                r.publish('events', json.dumps(msg))
                
            except Exception as e:
                logger.error(f"Error processing host {host}: {e}")

        conn.commit()
        cur.close()
        conn.close()
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")

if __name__ == "__main__":
    logger.info("Device Scanner Service Started")
    while True:
        scan_network()
        logger.info(f"Sleeping for {SCAN_INTERVAL}s...")
        time.sleep(SCAN_INTERVAL)
