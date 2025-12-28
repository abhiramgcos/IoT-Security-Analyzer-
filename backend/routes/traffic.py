

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import List, Optional
import asyncio
import time
import traceback
from backend.logger import Logger
from backend.services.traffic_analyzer import RealTimeAnalyzer

logger = Logger('traffic_routes').get_logger()
router = APIRouter()

class TrafficEvent(BaseModel):
    device_ip: str
    event_type: str
    protocol: str
    severity: str
    description: str

@router.websocket("/live/{interface}")
async def websocket_traffic_endpoint(websocket: WebSocket, interface: str):
    """
    WebSocket endpoint for real-time traffic monitoring
    """
    await websocket.accept()
    logger.info(f"WebSocket client connected for interface {interface}")
    
    analyzer = RealTimeAnalyzer()
    
    try:
        packet_count = 0
        async for packet in analyzer.start_capture(interface):
            await websocket.send_json(packet)
            packet_count += 1
            
            if packet_count % 100 == 0:
                logger.info(f"Sent {packet_count} packets to client")
            
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected after {packet_count} packets")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        logger.error(traceback.format_exc())
        try:
           await websocket.close(code=1011, reason=str(e))
        except:
           pass
    finally:
        analyzer.stop_capture()
        logger.info("Analyzer stopped")

@router.post("/start-capture/{interface}")
async def start_traffic_capture(interface: str, duration: int = 300):
    """
    Start capturing network traffic (Background Mode)
    
    ### Parameters:
    - **interface**: Network interface to capture on
    - **duration**: Capture duration in seconds
    
    ### Returns:
    Capture session ID
    """
    try:
        from backend.services.traffic_analyzer import TrafficAnalyzer
        analyzer = TrafficAnalyzer()
        
        # Determine actual available interface if requested one fails
        # For now, just pass through
        
        filename = analyzer.start_capture(interface, duration)
        
        if not filename:
             raise HTTPException(status_code=500, detail="Failed to start capture")

        return {
            "session_id": int(time.time()), 
            "interface": interface,
            "duration": duration,
            "status": "capturing",
            "file": filename
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Capture failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/events/{session_id}", response_model=List[TrafficEvent])
async def get_traffic_events(session_id: int):
    """
    Get captured traffic events
    
    ### Parameters:
    - **session_id**: Traffic capture session ID
    
    ### Returns:
    List of captured events with analysis
    """
    try:
        return []
    
    except Exception as e:
        logger.error(f"Error fetching events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/analysis/{session_id}")
async def get_traffic_analysis(session_id: int):
    """
    Get analysis of captured traffic
    
    ### Returns:
    - anomalies: List of detected anomalies
    - protocols: Protocol breakdown
    - suspicious_connections: Flagged connections
    """
    return {
        "anomalies": [],
        "protocols": {},
        "suspicious_connections": []
    }
