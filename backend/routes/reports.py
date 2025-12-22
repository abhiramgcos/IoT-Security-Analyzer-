
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from backend.logger import Logger
import os
from backend.config import settings

logger = Logger('reports_routes').get_logger()
router = APIRouter()

class ReportRequest(BaseModel):
    subnet: str
    include_firmware: bool = True
    include_traffic: bool = True
    include_recommendations: bool = True

@router.post("/generate")
async def generate_report(request: ReportRequest):
    """
    Generate comprehensive security report
    
    ### Parameters:
    - **subnet**: Network scanned
    - **include_firmware**: Include firmware analysis
    - **include_traffic**: Include traffic analysis
    - **include_recommendations**: Include remediation recommendations
    
    ### Returns:
    - report_id: Report identifier
    - status: Generation status
    - format_options: Available export formats
    """
    try:
        from backend.services.report_generator import ReportGenerator
        
        logger.info(f"Generating report for {request.subnet}")
        
        generator = ReportGenerator()
        report_id = generator.generate(
            subnet=request.subnet,
            options={
                "include_firmware": request.include_firmware,
                "include_traffic": request.include_traffic,
                "include_recommendations": request.include_recommendations
            }
        )
        
        return {
            "report_id": report_id,
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "format_options": ["JSON"],
            "estimated_completion": "Completed"
        }
    
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download/{report_id}")
async def download_report(report_id: int, format: str = "pdf"):
    """
    Download generated report
    
    ### Parameters:
    - **report_id**: Report identifier
    - **format**: Export format (pdf, json, html)
    """
    try:
        # Implementation would fetch from file storage
        report_path = os.path.join(settings.REPORT_DIR, f"report_{report_id}.{format}")
        
        if not os.path.exists(report_path):
            raise HTTPException(status_code=404, detail="Report not found")
        
        return FileResponse(report_path, filename=f"report_{report_id}.{format}")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/score")
async def get_network_score():
    """
    Get overall network security score
    
    ### Returns:
    - overall_score: 0-100
    - grade: A-F
    - breakdown: Component scores
    """
    from backend.database import Database
    db = Database()
    
    # Get real data
    devices = db.get_all_devices()
    device_count = len(devices)
    
    # Calculate vulnerability score
    total_vulns = 0
    critical = 0
    high = 0
    medium = 0
    
    for device in devices:
        vulns = db.get_device_vulnerabilities(device['id'])
        total_vulns += len(vulns)
        for vuln in vulns:
            severity = vuln.get('severity', '').upper()
            if severity == 'CRITICAL':
                critical += 1
            elif severity == 'HIGH':
                high += 1
            elif severity == 'MEDIUM':
                medium += 1
    
    # Calculate score (100 - penalty for vulnerabilities)
    score = 100
    score -= critical * 20  # -20 per critical
    score -= high * 10      # -10 per high
    score -= medium * 5     # -5 per medium
    score = max(0, score)
    
    # Determine grade
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    
    return {
        "overall_score": score,
        "grade": grade,
        "breakdown": {
            "device_security": score,
            "firmware_status": score,
            "traffic_health": 100,  # No traffic analysis data yet
            "vulnerability_management": max(0, 100 - (total_vulns * 2))
        }
    }
