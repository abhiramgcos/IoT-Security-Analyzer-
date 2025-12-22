
import requests
from typing import List, Dict
from backend.config import settings
from backend.logger import Logger

logger = Logger('cve_scanner').get_logger()

class CVEScanner:
    def __init__(self):
        self.api_key = settings.NVD_API_KEY

    def scan_device(self, vendor: str, model: str, version: str = None, cpe: str = None) -> List[Dict]:
        """
        Check NVD for known vulnerabilities using the official API (v2.0).
        Now supports precision lookup via CPE.
        """
        logger.info(f"Scanning for CVEs: {vendor} {model} {version} (CPE: {cpe})")
        
        if not self.api_key:
            logger.warning("No NVD API Key found. Returning empty list.")
            return []

        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": self.api_key}
        params = {"resultsPerPage": 20}
        
        # Priority 1: Use CPE if available (Most precise)
        if cpe:
            params["cpeName"] = cpe
        
        # Priority 2: Use Keyword Search
        else:
            search_terms = f"{vendor} {model}"
            if version:
                search_terms += f" {version}"
            params["keywordSearch"] = search_terms

        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    
                    # If keyword search was used, double check description for model name to reduce false positives
                    description = cve.get("descriptions", [{}])[0].get("value", "No description")
                    if not cpe and model.lower() not in description.lower():
                         # Skip if model name not in description (simple filter)
                         continue

                    vuln = {
                        "cve_id": cve.get("id"),
                        "description": description,
                        "severity": metrics.get("baseSeverity", "UNKNOWN"),
                        "cvss_score": metrics.get("baseScore", 0.0),
                        "remediation": "Check vendor updates",
                        "component": f"{vendor} {model}"
                    }
                    vulnerabilities.append(vuln)
                
                logger.info(f"Found {len(vulnerabilities)} CVEs")
                return vulnerabilities
            else:
                logger.error(f"NVD API Error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"CVE Scan failed: {e}")
            return []
