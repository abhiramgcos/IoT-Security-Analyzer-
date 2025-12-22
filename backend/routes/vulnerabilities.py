
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from backend.database import Database
from backend.logger import Logger

logger = Logger('vulnerability_routes').get_logger()
router = APIRouter()
db = Database()

class VulnerabilityResponse(BaseModel):
    cve_id: str
    component: str
    cvss_score: float
    severity: str
    description: str
    remediation: Optional[str]

@router.get("/device/{ip_address}", response_model=List[VulnerabilityResponse])
async def get_device_vulnerabilities(ip_address: str):
    """
    Get all vulnerabilities for a specific device
    
    ### Parameters:
    - **ip_address**: Device IP address
    
    ### Returns:
    List of CVEs with CVSS scores and remediation
    """
    try:
        device = db.get_device(ip_address)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Implementation would fetch from CVE database
        vulns = db.get_device_vulnerabilities(device['id'])
        return vulns
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/summary")
async def get_vulnerability_summary():
    """
    Get summary of all vulnerabilities across network
    
    ### Returns:
    - total_cves: Total number of CVEs found
    - critical: Count of critical vulnerabilities
    - high: Count of high severity
    - medium: Count of medium severity
    - low: Count of low severity
    """
    try:
        # Get all devices and aggregate their vulnerabilities
        devices = db.get_all_devices()
        
        total_cves = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        cvss_scores = []
        
        for device in devices:
            vulns = db.get_device_vulnerabilities(device['id'])
            total_cves += len(vulns)
            
            for vuln in vulns:
                severity = vuln.get('severity', '').upper()
                if severity == 'CRITICAL':
                    critical += 1
                elif severity == 'HIGH':
                    high += 1
                elif severity == 'MEDIUM':
                    medium += 1
                elif severity == 'LOW':
                    low += 1
                
                score = vuln.get('cvss_score')
                if score:
                    cvss_scores.append(float(score))
        
        average_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        
        summary = {
            "total_cves": total_cves,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "average_cvss": round(average_cvss, 2)
        }
        
        logger.info(f"Vulnerability summary: {summary}")
        return summary
    
    except Exception as e:
        logger.error(f"Error generating summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/top-cvss")
async def get_top_vulnerabilities(limit: int = 10):
    """
    Get top vulnerabilities by CVSS score
    
    ### Parameters:
    - **limit**: Number of vulnerabilities to return
    """
    try:
        # Get all vulnerabilities from all devices
        devices = db.get_all_devices()
        all_vulns = []
        
        for device in devices:
            vulns = db.get_device_vulnerabilities(device['id'])
            for vuln in vulns:
                vuln['device_ip'] = device.get('ip_address')
                all_vulns.append(vuln)
        
        # Sort by CVSS score descending
        sorted_vulns = sorted(all_vulns, key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        return {
            "vulnerabilities": sorted_vulns[:limit]
        }
    
    except Exception as e:
        logger.error(f"Error fetching top vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))
