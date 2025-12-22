
import os
import json
from datetime import datetime
from backend.config import settings
from backend.logger import Logger
from backend.database import Database

logger = Logger('report_generator').get_logger()

class ReportGenerator:
    def __init__(self):
        self.report_dir = settings.REPORT_DIR
        self.db = Database()

    def generate(self, subnet: str, options: dict) -> str:
        """Generate security report for subnet based on real data"""
        logger.info(f"Generating report for {subnet}")
        report_id = int(datetime.now().timestamp())
        
        # 1. Fetch Devices
        devices = self.db.get_all_devices()
        device_count = len(devices)
        
        # 2. Aggregated Vulnerabilities
        total_vulns = 0
        vuln_details = []
        for dev in devices:
            dev_vulns = self.db.get_device_vulnerabilities(dev['id'])
            total_vulns += len(dev_vulns)
            vuln_details.extend(dev_vulns)
            
        # 3. Calculate Health Score (Basic logic)
        # Start at 100, deduct for vulns
        health_score = 100
        for v in vuln_details:
            severity = v.get('severity', 'LOW')
            if severity == 'CRITICAL': health_score -= 20
            elif severity == 'HIGH': health_score -= 10
            elif severity == 'MEDIUM': health_score -= 5
            else: health_score -= 1
        health_score = max(0, health_score)

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "subnet": subnet,
            "options": options,
            "summary": {
                "devices_found": device_count,
                "vulnerabilities": total_vulns,
                "health_score": health_score
            },
            "devices": devices, # Full device list
            "recommendations": [
                "Patch critical vulnerabilities immediately" if health_score < 50 else "Maintain current security posture",
                "Review open ports on all devices"
            ]
        }
        
        # Save JSON
        json_path = os.path.join(self.report_dir, f"report_{report_id}.json")
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        return str(report_id)
