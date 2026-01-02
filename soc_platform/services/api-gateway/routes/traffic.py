from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def list_traffic():
    """Get traffic flow data"""
    return {"message": "Traffic endpoint - to be implemented"}

@router.get("/interfaces")
async def list_interfaces():
    """List available network interfaces"""
    return {"interfaces": ["eth0",  "wlp0s20f3", "docker0"]}

@router.post("/start")
async def start_capture():
    """Start packet capture"""
    return {"message": "Capture started"}

@router.post("/stop")
async def stop_capture():
    """Stop packet capture"""
    return {"message": "Capture stopped"}
