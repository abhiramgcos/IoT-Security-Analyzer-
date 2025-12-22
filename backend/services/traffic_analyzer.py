
import time
import subprocess
import os
from typing import List, Dict
from backend.config import settings
from backend.logger import Logger

logger = Logger('traffic_analyzer').get_logger()

class TrafficAnalyzer:
    def __init__(self):
        self.capturing = False
        
    def start_capture(self, interface: str, duration: int):
        """
        Start capturing traffic on interface for duration using tcpdump.
        Requires NET_ADMIN capability in Docker.
        """
        logger.info(f"Starting capture on {interface} for {duration}s")
        
        timestamp = int(time.time())
        filename = f"capture_{timestamp}.pcap"
        filepath = os.path.join(settings.PCAP_DIR, filename)

        try:
            # -i: interface, -w: write to file, -G: rotate every X seconds (used here as timeout)
            # -W: limit number of files (1)
            # Alternative: use subprocess `timeout` cmd or python threading
            
            cmd = [
                "timeout", str(duration),
                "tcpdump", "-i", interface, "-w", filepath, "-n"
            ]
            
            # Start in background (simplified for this context)
            subprocess.Popen(cmd)
            
            return filename
            
        except Exception as e:
            logger.error(f"Capture start failed: {e}")
            return None

    def analyze_pcap(self, pcap_path: str) -> Dict:
        """Analyze a PCAP file using tcpdump -r for basic stats"""
        logger.info(f"Analyzing {pcap_path}")
        
        if not os.path.exists(pcap_path):
            return {"error": "File not found"}

        stats = {
            "total_packets": 0,
            "suspicious_ips": [],
            "protocols": {},
            "anomalies": []
        }

        try:
            # Read packets
            cmd = ["tcpdump", "-nn", "-r", pcap_path]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0:
                lines = process.stdout.splitlines()
                stats["total_packets"] = len(lines)
                
                # Basic parsing (Very simplified)
                for line in lines:
                    if "IP" in line:
                        parts = line.split()
                        # Extract IPs/Ports would require regex
                        # Just counting protocols roughly
                        if "UDP" in line:
                            stats["protocols"]["UDP"] = stats["protocols"].get("UDP", 0) + 1
                        elif "TCP" in line:
                            stats["protocols"]["TCP"] = stats["protocols"].get("TCP", 0) + 1
                        elif "ICMP" in line:
                            stats["protocols"]["ICMP"] = stats["protocols"].get("ICMP", 0) + 1
                            
            return stats

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {"error": str(e)}
