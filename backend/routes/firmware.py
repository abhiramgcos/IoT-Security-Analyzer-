
from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File, Form
from pydantic import BaseModel, Field
from typing import Optional, List
import os
import hashlib
import aiofiles
import httpx
from backend.services.firmware_fetcher import FirmwareFetcher
from backend.services.firmware_analyzer import FirmwareAnalyzer
from backend.config import settings
from backend.logger import Logger

logger = Logger('firmware_routes').get_logger()
router = APIRouter()

# FirmAE API URL (Docker service)
FIRMAE_API_URL = os.getenv("FIRMAE_API_URL", "http://localhost:8002")

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

class UploadResponse(BaseModel):
    status: str
    filename: str
    path: str
    size: int
    sha256: str

class AnalysisResponse(BaseModel):
    status: str
    firmware_path: str
    analysis: dict

class EmulationResponse(BaseModel):
    status: str
    request_id: str
    message: str

# ========== FIRMWARE FETCH ==========

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

# ========== FIRMWARE UPLOAD ==========

@router.post("/upload", response_model=UploadResponse)
async def upload_firmware(file: UploadFile = File(...)):
    """
    Upload a firmware file for analysis
    
    ### Parameters:
    - **file**: Firmware binary file (.bin, .img, .trx, etc.)
    
    ### Returns:
    Upload status with file path and hash
    """
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        # Create upload directory
        upload_dir = os.path.join(settings.FIRMWARE_CACHE_DIR, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate safe filename
        safe_filename = file.filename.replace(" ", "_").replace("/", "_")
        file_path = os.path.join(upload_dir, safe_filename)
        
        # Calculate SHA256 while saving
        sha256_hash = hashlib.sha256()
        file_size = 0
        
        async with aiofiles.open(file_path, 'wb') as out_file:
            while content := await file.read(8192):
                await out_file.write(content)
                sha256_hash.update(content)
                file_size += len(content)
        
        logger.info(f"Firmware uploaded: {file_path} ({file_size} bytes)")
        
        return UploadResponse(
            status="success",
            filename=safe_filename,
            path=file_path,
            size=file_size,
            sha256=sha256_hash.hexdigest()
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firmware upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== BASIC ANALYSIS (BINWALK) ==========

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_firmware(firmware_path: str = Form(...)):
    """
    Perform basic firmware analysis using Binwalk
    
    ### Parameters:
    - **firmware_path**: Path to firmware file
    
    ### Returns:
    Analysis results including architecture, filesystem, secrets
    """
    try:
        if not os.path.exists(firmware_path):
            raise HTTPException(status_code=404, detail="Firmware file not found")
        
        analyzer = FirmwareAnalyzer()
        results = analyzer.analyze(firmware_path)
        
        if "error" in results:
            raise HTTPException(status_code=500, detail=results["error"])
        
        return AnalysisResponse(
            status="success",
            firmware_path=firmware_path,
            analysis=results
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firmware analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== ADVANCED EMULATION (FIRMAE) ==========

@router.post("/emulate", response_model=EmulationResponse)
async def start_emulation(firmware_path: str = Form(...)):
    """
    Start advanced firmware emulation using FirmAE
    
    ### Parameters:
    - **firmware_path**: Path to firmware file (from upload endpoint)
    
    ### Returns:
    Request ID to poll for emulation status
    """
    try:
        if not os.path.exists(firmware_path):
            raise HTTPException(status_code=404, detail="Firmware file not found")
        
        # Call FirmAE API
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Read firmware file and send to FirmAE
            with open(firmware_path, 'rb') as f:
                files = {'file': (os.path.basename(firmware_path), f, 'application/octet-stream')}
                response = await client.post(f"{FIRMAE_API_URL}/analyze", files=files)
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code, 
                    detail=f"FirmAE error: {response.text}"
                )
            
            result = response.json()
            
            return EmulationResponse(
                status="queued",
                request_id=result.get("request_id", ""),
                message="Emulation started. Use /emulate/status/{request_id} to check progress."
            )
    
    except httpx.ConnectError:
        logger.error("FirmAE service not available")
        raise HTTPException(
            status_code=503, 
            detail="FirmAE service not available. Ensure FirmAE container is running."
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Emulation start failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/emulate/status/{request_id}")
async def get_emulation_status(request_id: str):
    """
    Get the status of a FirmAE emulation job
    
    ### Parameters:
    - **request_id**: Emulation request ID from /emulate endpoint
    
    ### Returns:
    Current status (queued, running, completed, failed)
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{FIRMAE_API_URL}/status/{request_id}")
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            
            return response.json()
    
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="FirmAE service not available")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/emulate/result/{request_id}")
async def get_emulation_result(request_id: str):
    """
    Get the results of a completed FirmAE emulation
    
    ### Parameters:
    - **request_id**: Emulation request ID
    
    ### Returns:
    Emulation results including network reachability and web interface status
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{FIRMAE_API_URL}/result/{request_id}")
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            
            return response.json()
    
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="FirmAE service not available")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Result fetch failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/emulate/logs/{request_id}")
async def get_emulation_logs(request_id: str):
    """
    Get the logs for a FirmAE emulation job
    
    ### Parameters:
    - **request_id**: Emulation request ID
    
    ### Returns:
    List of log entries with timestamps
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{FIRMAE_API_URL}/logs/{request_id}")
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            
            return response.json()
    
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="FirmAE service not available")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logs fetch failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== FIRMWARE CACHE ==========

@router.get("/cache")
async def get_cached_firmware():
    """List all cached firmware files"""
    try:
        cached = {}
        uploads = []
        
        if os.path.exists(settings.FIRMWARE_CACHE_DIR):
            for item in os.listdir(settings.FIRMWARE_CACHE_DIR):
                # Skip .gitkeep and other hidden files
                if item.startswith('.'):
                    continue
                    
                item_path = os.path.join(settings.FIRMWARE_CACHE_DIR, item)
                
                # Handle uploads directory specially
                if item == "uploads" and os.path.isdir(item_path):
                    for upload in os.listdir(item_path):
                        file_path = os.path.join(item_path, upload)
                        uploads.append({
                            "filename": upload,
                            "path": file_path,
                            "size": os.path.getsize(file_path) if os.path.isfile(file_path) else 0
                        })
                # Only process if it's a directory
                elif os.path.isdir(item_path):
                    cached[item] = os.listdir(item_path)
        
        return {
            "cached_firmware": cached,
            "uploads": uploads
        }
    
    except Exception as e:
        logger.error(f"Error listing cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/cache/{filename}")
async def delete_cached_firmware(filename: str):
    """Delete a cached firmware file"""
    try:
        # Check in uploads directory
        upload_path = os.path.join(settings.FIRMWARE_CACHE_DIR, "uploads", filename)
        
        if os.path.exists(upload_path):
            os.remove(upload_path)
            logger.info(f"Deleted firmware: {upload_path}")
            return {"status": "deleted", "filename": filename}
        
        raise HTTPException(status_code=404, detail="Firmware file not found")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

