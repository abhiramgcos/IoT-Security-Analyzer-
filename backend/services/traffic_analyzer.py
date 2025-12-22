
import time
import subprocess
import os
import json
from typing import List, Dict
from backend.config import settings
from backend.logger import Logger

logger = Logger('traffic_analyzer').get_logger()

class TrafficAnalyzer:
    def __init__(self):
        self.capturing = False
        
    def start_capture(self, interface: str, duration: int):
        """
        Start capturing traffic on interface using tshark.
        Requires NET_ADMIN capability in Docker.
        """
        logger.info(f"Starting tshark capture on {interface} for {duration}s")
        
        timestamp = int(time.time())
        filename = f"capture_{timestamp}.pcap"
        filepath = os.path.join(settings.PCAP_DIR, filename)

        try:
            # Use tshark instead of tcpdump for richer analysis
            cmd = [
                "timeout", str(duration),
                "tshark", "-i", interface, "-w", filepath, 
                "-f", "not port 22"  # Exclude SSH to reduce noise
            ]
            
            # Start in background
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return filename
            
        except Exception as e:
            logger.error(f"Capture start failed: {e}")
            return None

    def analyze_pcap(self, pcap_path: str) -> Dict:
        """Analyze PCAP file using tshark for detailed protocol statistics"""
        logger.info(f"Analyzing {pcap_path} with tshark")
        
        if not os.path.exists(pcap_path):
            return {"error": "File not found"}

        stats = {
            "total_packets": 0,
            "protocols": {},
            "conversations": [],
            "suspicious_ips": [],
            "anomalies": [],
            "bandwidth": {}
        }

        try:
            # Get protocol hierarchy statistics
            proto_cmd = ["tshark", "-r", pcap_path, "-q", "-z", "io,phs"]
            proto_result = subprocess.run(proto_cmd, capture_output=True, text=True, timeout=30)
            
            if proto_result.returncode == 0:
                stats["protocols"] = self._parse_protocol_hierarchy(proto_result.stdout)
            
            # Get conversation statistics (top IP pairs)
            conv_cmd = ["tshark", "-r", pcap_path, "-q", "-z", "conv,ip"]
            conv_result = subprocess.run(conv_cmd, capture_output=True, text=True, timeout=30)
            
            if conv_result.returncode == 0:
                stats["conversations"] = self._parse_conversations(conv_result.stdout)
            
            # Get packet count
            count_cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "frame.number"]
            count_result = subprocess.run(count_cmd, capture_output=True, text=True, timeout=30)
            
            if count_result.returncode == 0:
                stats["total_packets"] = len(count_result.stdout.strip().split('\n'))
            
            # Detect anomalies (simplified)
            stats["anomalies"] = self._detect_anomalies(stats)
                            
            return stats

        except subprocess.TimeoutExpired:
            logger.error("Tshark analysis timeout")
            return {"error": "Analysis timeout"}
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {"error": str(e)}
    
    def _parse_protocol_hierarchy(self, output: str) -> Dict:
        """Parse tshark protocol hierarchy output"""
        protocols = {}
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('=') or 'frames' in line.lower():
                continue
            
            # Extract protocol name and count
            if 'ip' in line.lower():
                protocols['IP'] = protocols.get('IP', 0) + 1
            if 'tcp' in line.lower():
                protocols['TCP'] = protocols.get('TCP', 0) + 1
            if 'udp' in line.lower():
                protocols['UDP'] = protocols.get('UDP', 0) + 1
           if 'http' in line.lower():
                protocols['HTTP'] = protocols.get('HTTP', 0) + 1
            if 'dns' in line.lower():
                protocols['DNS'] = protocols.get('DNS', 0) + 1
            if 'tls' in line.lower() or 'ssl' in line.lower():
                protocols['TLS/SSL'] = protocols.get('TLS/SSL', 0) + 1
        
        return protocols
    
    def _parse_conversations(self, output: str) -> List[Dict]:
        """Parse tshark conversation output"""
        conversations = []
        lines = output.split('\n')
        
        # Skip header lines
        data_started = False
        for line in lines:
            if '<->' in line:
                data_started = True
            if not data_started or not line.strip():
                continue
            
            # Parse conversation line
            parts = line.split()
            if len(parts) >= 7:
                try:
                    conversations.append({
                        "address_a": parts[0],
                        "address_b": parts[2],  # Skip the <->
                        "frames": int(parts[3]),
                        "bytes": int(parts[4])
                    })
                except (ValueError, IndexError):
                    continue
        
        # Return top 10 by bytes
        conversations.sort(key=lambda x: x.get('bytes', 0), reverse=True)
        return conversations[:10]
    
    def _detect_anomalies(self, stats: Dict) -> List[str]:
        """Detect potential security anomalies"""
        anomalies = []
        
        protocols = stats.get('protocols', {})
        
        # Check for excessive UDP traffic
        udp_count = protocols.get('UDP', 0)
        total_packets = stats.get('total_packets', 1)
        if udp_count > total_packets * 0.7:
            anomalies.append("High volume of UDP traffic detected")
        
        # Check for DNS tunneling indicators
        dns_count = protocols.get('DNS', 0)
        if dns_count > total_packets * 0.5:
            anomalies.append("Unusual DNS query volume (possible tunneling)")
        
        # Check for unencrypted HTTP
        http_count = protocols.get('HTTP', 0)
        if http_count > 0:
            anomalies.append(f"Unencrypted HTTP traffic detected ({http_count} packets)")
        
        return anomalies
