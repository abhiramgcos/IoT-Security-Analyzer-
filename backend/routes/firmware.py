
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional
from backend.services.firmware_fetcher import FirmwareFetcher
from backend.logger import Logger

logger = Logger('firmware_routes').get_logger()
router = APIRouter()

class FirmwareRequest(BaseModel):
    manufacturer: str = Field(..., example="TP-Link")
    model: str = Field(..., example="Archer C7")
    firmware_version: Optional[str] = Field(None, example="1.9.1")

class FirmwareResponse(BaseModel):
    status: str
    manufacturer: str
    model: str
    path: Optional[str]
    size: Optional[int]
    hash: Optional[str]

@router.post("/fetch", response_model=FirmwareResponse)
async def fetch_firmware(request: FirmwareRequest, background_tasks: BackgroundTasks):
    """
    Download firmware for a device
    
    ### Parameters:
    - **manufacturer**: Device manufacturer (TP-Link, D-Link, ASUS, etc.)
    - **model**: Device model number
    - **firmware_version**: Specific firmware version (optional)
    
    ### Returns:
    Firmware file path and metadata
    """
    try:
        logger.info(f"Fetching firmware for {request.manufacturer} {request.model}")
        
        fetcher = FirmwareFetcher()
        fw_path = fetcher.get_firmware(
            request.manufacturer,
            request.model,
            request.firmware_version
        )
        
        if not fw_path:
            raise HTTPException(status_code=404, detail="Firmware not found")
        
        return FirmwareResponse(
            status="success",
            manufacturer=request.manufacturer,
            model=request.model,
            path=fw_path,
            size=None,
            hash=None
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firmware fetch failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cache")
async def get_cached_firmware():
    """List all cached firmware files"""
    import os
    from backend.config import settings
    
    try:
        cached = {}
        if os.path.exists(settings.FIRMWARE_CACHE_DIR):
            for item in os.listdir(settings.FIRMWARE_CACHE_DIR):
                # Skip .gitkeep and other non-directory files
                if item.startswith('.'):
                    continue
                    
                vendor_path = os.path.join(settings.FIRMWARE_CACHE_DIR, item)
                
                # Only process if it's a directory
                if os.path.isdir(vendor_path):
                    cached[item] = os.listdir(vendor_path)
        
        return {"cached_firmware": cached}
    
    except Exception as e:
        logger.error(f"Error listing cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))
