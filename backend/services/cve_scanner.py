
import requests
from typing import List, Dict
from backend.config import settings
from backend.logger import Logger

logger = Logger('cve_scanner').get_logger()

class CVEScanner:
    def __init__(self):
        self.api_key = settings.NVD_API_KEY

    def scan_device(self, vendor: str, model: str, version: str) -> List[Dict]:
        """
        Check NVD for known vulnerabilities using the official API (v2.0).
        """
        logger.info(f"Scanning for CVEs: {vendor} {model} {version}")
        
        if not self.api_key:
            logger.warning("No NVD API Key found. Returning empty list.")
            return []

        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": self.api_key}
        
        # Construct search query (simplified for demonstration)
        # Using virtualMatchString is better but complex to construct correctly without CPE
        # We try keyword search here
        params = {
            "keywordSearch": f"{vendor} {model}",
            "resultsPerPage": 10
        }

        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    
                    vuln = {
                        "cve_id": cve.get("id"),
                        "description": cve.get("descriptions", [{}])[0].get("value", "No description"),
                        "severity": metrics.get("baseSeverity", "UNKNOWN"),
                        "cvss_score": metrics.get("baseScore", 0.0),
                        "remediation": "Check vendor updates"
                    }
                    vulnerabilities.append(vuln)
                
                return vulnerabilities
            else:
                logger.error(f"NVD API Error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"CVE Scan failed: {e}")
            return []
