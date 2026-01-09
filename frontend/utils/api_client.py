
import requests
import json
from typing import List, Optional, Dict, Any

class APIClient:
    """Client for communicating with IoT Analyzer API"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
    
    # ========== SCANNER ENDPOINTS ==========
    
    def start_scan(self, subnet: str, interface: str = "eth0") -> Dict:
        """Start a network scan"""
        response = self.session.post(
            f"{self.base_url}/api/scanner/start",
            json={"subnet": subnet, "interface": interface}
        )
        response.raise_for_status()
        return response.json()
    
    def get_devices(self, limit: int = 100) -> List[Dict]:
        """Get all discovered devices"""
        response = self.session.get(
            f"{self.base_url}/api/scanner/devices",
            params={"limit": limit}
        )
        response.raise_for_status()
        return response.json()
    
    def get_device(self, ip_address: str) -> Dict:
        """Get specific device"""
        response = self.session.get(
            f"{self.base_url}/api/scanner/devices/{ip_address}"
        )
        response.raise_for_status()
        return response.json()
    
    def get_scan_status(self, scan_id: int) -> Dict:
        """Get scan status"""
        response = self.session.get(
            f"{self.base_url}/api/scanner/status/{scan_id}"
        )
        response.raise_for_status()
        return response.json()
    
    # ========== FIRMWARE ENDPOINTS ==========
    
    def fetch_firmware(self, manufacturer: str, model: str, 
                      version: Optional[str] = None) -> Dict:
        """Fetch firmware"""
        response = self.session.post(
            f"{self.base_url}/api/firmware/fetch",
            json={
                "manufacturer": manufacturer,
                "model": model,
                "firmware_version": version
            }
        )
        response.raise_for_status()
        return response.json()
    
    def upload_firmware(self, file) -> Dict:
        """Upload firmware file for analysis"""
        files = {'file': file}
        response = self.session.post(
            f"{self.base_url}/api/firmware/upload",
            files=files
        )
        response.raise_for_status()
        return response.json()
    
    def analyze_firmware(self, firmware_path: str) -> Dict:
        """Analyze firmware using Binwalk"""
        response = self.session.post(
            f"{self.base_url}/api/firmware/analyze",
            data={"firmware_path": firmware_path}
        )
        response.raise_for_status()
        return response.json()
    
    def start_emulation(self, firmware_path: str) -> Dict:
        """Start FirmAE emulation"""
        response = self.session.post(
            f"{self.base_url}/api/firmware/emulate",
            data={"firmware_path": firmware_path}
        )
        response.raise_for_status()
        return response.json()
    
    def get_emulation_status(self, request_id: str) -> Dict:
        """Get FirmAE emulation status"""
        response = self.session.get(
            f"{self.base_url}/api/firmware/emulate/status/{request_id}"
        )
        response.raise_for_status()
        return response.json()
    
    def get_emulation_result(self, request_id: str) -> Dict:
        """Get FirmAE emulation result"""
        response = self.session.get(
            f"{self.base_url}/api/firmware/emulate/result/{request_id}"
        )
        response.raise_for_status()
        return response.json()
    
    def get_emulation_logs(self, request_id: str) -> Dict:
        """Get FirmAE emulation logs"""
        response = self.session.get(
            f"{self.base_url}/api/firmware/emulate/logs/{request_id}"
        )
        response.raise_for_status()
        return response.json()
    
    def get_cached_firmware(self) -> Dict:
        """Get cached firmware"""
        response = self.session.get(
            f"{self.base_url}/api/firmware/cache"
        )
        response.raise_for_status()
        return response.json()
    
    def delete_firmware(self, filename: str) -> Dict:
        """Delete cached firmware file"""
        response = self.session.delete(
            f"{self.base_url}/api/firmware/cache/{filename}"
        )
        response.raise_for_status()
        return response.json()
    
    # ========== VULNERABILITY ENDPOINTS ==========
    
    def scan_cves(self, ip_address: str) -> Dict:
        """Trigger CVE scan for a device"""
        response = self.session.post(
            f"{self.base_url}/api/vulnerabilities/scan/{ip_address}"
        )
        response.raise_for_status()
        return response.json()

    def get_device_vulnerabilities(self, ip_address: str) -> List[Dict]:
        """Get device vulnerabilities"""
        response = self.session.get(
            f"{self.base_url}/api/vulnerabilities/device/{ip_address}"
        )
        response.raise_for_status()
        return response.json()
    
    def get_vulnerability_summary(self) -> Dict:
        """Get vulnerability summary"""
        response = self.session.get(
            f"{self.base_url}/api/vulnerabilities/summary"
        )
        response.raise_for_status()
        return response.json()
    
    def get_top_vulnerabilities(self, limit: int = 10) -> Dict:
        """Get top vulnerabilities"""
        response = self.session.get(
            f"{self.base_url}/api/vulnerabilities/top-cvss",
            params={"limit": limit}
        )
        response.raise_for_status()
        return response.json()
    
    # ========== TRAFFIC ENDPOINTS ==========
    
    def start_traffic_capture(self, interface: str, duration: int = 300) -> Dict:
        """Start traffic capture"""
        response = self.session.post(
            f"{self.base_url}/api/traffic/start-capture/{interface}",
            params={"duration": duration}
        )
        response.raise_for_status()
        return response.json()
    
    def get_traffic_events(self, session_id: int) -> List[Dict]:
        """Get traffic events"""
        response = self.session.get(
            f"{self.base_url}/api/traffic/events/{session_id}"
        )
        response.raise_for_status()
        return response.json()
    
    def get_traffic_analysis(self, session_id: int) -> Dict:
        """Get traffic analysis"""
        response = self.session.get(
            f"{self.base_url}/api/traffic/analysis/{session_id}"
        )
        response.raise_for_status()
        return response.json()
    
    # ========== REPORT ENDPOINTS ==========
    
    def generate_report(self, subnet: str, include_firmware: bool = True,
                       include_traffic: bool = True, 
                       include_recommendations: bool = True) -> Dict:
        """Generate report"""
        response = self.session.post(
            f"{self.base_url}/api/reports/generate",
            json={
                "subnet": subnet,
                "include_firmware": include_firmware,
                "include_traffic": include_traffic,
                "include_recommendations": include_recommendations
            }
        )
        response.raise_for_status()
        return response.json()
    
    def download_report(self, report_id: int, format: str = "pdf") -> bytes:
        """Download report"""
        response = self.session.get(
            f"{self.base_url}/api/reports/download/{report_id}",
            params={"format": format}
        )
        response.raise_for_status()
        return response.content
    
    def get_network_score(self) -> Dict:
        """Get network score"""
        response = self.session.get(
            f"{self.base_url}/api/reports/score"
        )
        response.raise_for_status()
        return response.json()
    
    # ========== HEALTH & INFO ==========
    
    def health_check(self) -> Dict:
        """Check API health"""
        response = self.session.get(
            f"{self.base_url}/health"
        )
        response.raise_for_status()
        return response.json()
    
    def get_info(self) -> Dict:
        """Get system info"""
        response = self.session.get(
            f"{self.base_url}/info"
        )
        response.raise_for_status()
        return response.json()
