
import requests
from typing import List, Dict, Any

class TrafficClient:
    """Client for communicating with Traffic Analyzer API"""
    
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def get_alerts(self) -> List[Dict]:
        """Get recent IDS alerts"""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/alerts")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            # Return empty list if service is down/unreachable to prevent UI crash
            return []
            
    def predict_anomaly(self, features: Dict[str, float]) -> Dict:
        """Get anomaly score for a packet"""
        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/predict",
                json={"features": features}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return {"anomaly_score": 0.0, "is_anomaly": False}

    def health_check(self) -> bool:
        """Check if traffic analyzer is up"""
        try:
            # Check openapi.json as a health proxy since /health might not be implemented
            response = self.session.get(f"{self.base_url}/api/v1/openapi.json")
            return response.status_code == 200
        except:
            return False
