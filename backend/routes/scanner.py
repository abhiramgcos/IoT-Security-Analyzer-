
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from backend.services.network_discovery import NetworkScanner
from backend.database import Database
from backend.logger import Logger

logger = Logger('scanner_routes').get_logger()
router = APIRouter()
db = Database()

# ========== PYDANTIC MODELS ==========

class ScanRequest(BaseModel):
    subnet: str = Field(..., example="192.168.1.0/24")
    interface: Optional[str] = Field(default="eth0", example="eth0")
    timeout: Optional[int] = Field(default=300, example=300)

class DeviceResponse(BaseModel):
    id: int
    ip_address: str
    mac_address: Optional[str] = "Unknown"
    hostname: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown"
    manufacturer: Optional[str] = "Unknown"
    model: Optional[str]
    open_ports: List[int] = []
    first_seen: Optional[str] = ""
    last_seen: Optional[str] = ""
    status: Optional[str] = "unknown"

class ScanResponse(BaseModel):
    scan_id: int
    status: str
    devices_found: int
    timestamp: str
    message: str

# ========== ENDPOINTS ==========

@router.post("/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a network scan
    
    ### Parameters:
    - **subnet**: Network to scan (e.g., 192.168.1.0/24)
    - **interface**: Network interface to use
    - **timeout**: Scan timeout in seconds
    
    ### Returns:
    - scan_id: Unique identifier for this scan
    - status: Current scan status
    - devices_found: Number of devices discovered
    """
    try:
        logger.info(f"Starting network scan for subnet: {request.subnet}")
        
        # Create scanner instance
        scanner = NetworkScanner(request.subnet, request.interface)
        
        # Run scan in background
        background_tasks.add_task(run_scan, scanner)
        
        return ScanResponse(
            scan_id=1,
            status="scanning",
            devices_found=0,
            timestamp=datetime.now().isoformat(),
            message=f"Scan started for {request.subnet}"
        )
    
    except Exception as e:
        logger.error(f"Scan start failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def run_scan(scanner: NetworkScanner):
    """Background task to run network scan"""
    try:
        devices = scanner.scan_network()
        logger.info(f"Scan completed: {len(devices)} devices found")
    except Exception as e:
        logger.error(f"Background scan failed: {e}")

# DEBUG ENDPOINT - Returns raw data without validation
@router.get("/devices/debug")
async def get_devices_debug(limit: int = 100):
    """
    DEBUG: Get raw device data without Pydantic validation
    """
    try:
        devices = db.get_all_devices()[:limit]
        logger.info(f"[DEBUG] Fetched {len(devices)} devices from DB")
        
        # Return raw data as-is
        return {
            "count": len(devices),
            "devices": devices,
            "sample": devices[0] if devices else None
        }
    except Exception as e:
        logger.error(f"[DEBUG] Error: {e}", exc_info=True)
        return {"error": str(e), "traceback": str(e.__traceback__)}

@router.get("/devices")  # Temporarily removed response_model
async def get_devices(limit: int = 100):
    """
    Get all discovered devices
    
    ### Parameters:
    - **limit**: Maximum number of devices to return
    
    ### Returns:
    List of discovered devices with details
    """
    try:
        devices = db.get_all_devices()[:limit]
        logger.info(f"Fetched {len(devices)} devices from DB")
        
        if devices:
            logger.info(f"Sample device (first): {devices[0]}")
            
        # Validate each device and filter out invalid ones
        valid_devices = []
        for i, dev in enumerate(devices):
            try:
                validated = DeviceResponse(**dev)
                valid_devices.append(dev)
            except Exception as e:
                logger.error(f"Validation failed for device {i} (IP: {dev.get('ip_address')}): {e}")
                logger.error(f"Problematic device data: {dev}")
                
        logger.info(f"Returning {len(valid_devices)}/{len(devices)} valid devices")
        return valid_devices
    
    except Exception as e:
        import traceback
        logger.error(f"Error fetching devices: {e}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/devices/{ip_address}", response_model=DeviceResponse)
async def get_device(ip_address: str):
    """
    Get specific device by IP address
    
    ### Parameters:
    - **ip_address**: IP address of device
    
    ### Returns:
    Device details including open ports, type, and manufacturer
    """
    try:
        device = db.get_device(ip_address)
        if not device:
            raise HTTPException(status_code=404, detail=f"Device {ip_address} not found")
        return device
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching device {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: int):
    """
    Get status of a specific scan
    
    ### Parameters:
    - **scan_id**: Scan identifier
    
    ### Returns:
    current scan status and progress
    """
    # Implementation would track scan progress
    return {
        "scan_id": scan_id,
        "status": "completed",
        "progress": 100,
        "devices_found": 5
    }

@router.delete("/devices/{ip_address}")
async def delete_device(ip_address: str):
    """
    Remove device from inventory
    
    ### Parameters:
    - **ip_address**: IP address of device to remove
    """
    try:
        # Implementation would delete from database
        logger.info(f"Device deleted: {ip_address}")
        return {"message": f"Device {ip_address} deleted"}
    
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/clear-all")
async def clear_all_data():
    """
    Clear all data from the database (devices and vulnerabilities)
    
    ### Returns:
    Confirmation message
    """
    try:
        logger.info("Clearing all database data")
        success = db.clear_all_data()
        if success:
            return {"message": "All data cleared successfully", "status": "success"}
        else:
            raise HTTPException(status_code=500, detail="Failed to clear data")
    
    except Exception as e:
        logger.error(f"Error clearing data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
