from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import logging
import json
from datetime import datetime
from typing import List, Optional
from contextlib import asynccontextmanager

from database import engine, get_db
from routes import devices, traffic, alerts, firmware, reports, auth
from websocket_manager import WebSocketManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# WebSocket manager
ws_manager = WebSocketManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    logger.info("🚀 SOC IoT Platform API Gateway starting...")
    
    # Startup: Initialize database tables
    # Note: Tables are created by init-db.sql in PostgreSQL init
    
    logger.info("✅ API Gateway ready!")
    
    yield
    
    # Shutdown
    logger.info("👋 Shutting down API Gateway...")

# Create FastAPI app
app = FastAPI(
    title="SOC IoT Security Platform API",
    description="Professional SOC analyst tool for IoT security monitoring and analysis",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(devices.router, prefix="/api/v1/devices", tags=["Devices"])
app.include_router(traffic.router, prefix="/api/v1/traffic", tags=["Traffic"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(firmware.router, prefix="/api/v1/firmware", tags=["Firmware"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])

# ============================================
# Root & Health Endpoints
# ============================================

@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "service": "SOC IoT Security Platform",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "api": "operational",
            "database": "connected",  # Add actual DB check
            "redis": "connected"  # Add actual Redis check
        }
    }

@app.get("/info")
async def system_info():
    """System information endpoint"""
    return {
        "platform": "SOC IoT Security Platform",
        "version": "1.0.0",
        "components": {
            "api_gateway": "operational",
            "traffic_monitor": "operational",
            "device_scanner": "operational",
            "firmware_analyzer": "operational",
            "suricata_ids": "operational"
        },
        "capabilities": [
            "traffic_monitoring",
            "ids_detection",
            "device_discovery",
            "firmware_analysis",
            "vulnerability_assessment",
            "real_time_alerts"
        ]
    }

# ============================================
# WebSocket Endpoints
# ============================================

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """
    WebSocket for real-time updates
    Streams: packets, alerts, device discoveries
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()
            
            try:
                msg = json.loads(data)
                
                # If message is traffic batch from traffic-gateway, broadcast to UI clients
                if msg.get("type") == "traffic_batch":
                    # Optimization: Don't broadcast everything if too fast?
                    # For now, just broadcast
                    await ws_manager.broadcast(msg)
                
                elif msg.get("type") == "ping":
                    await ws_manager.send_personal({"type": "pong"}, websocket)
                    
            except json.JSONDecodeError:
                pass
                
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")

@app.get("/ws/stats")
async def websocket_stats():
    """Get WebSocket connection statistics"""
    return {
        "active_connections": len(ws_manager.active_connections),
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================
# Error Handlers
# ============================================

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Resource not found", "path": str(request.url)}
    )

@app.exception_handler(500)
async def server_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}")
    # DEBUG: Return actual error
    return JSONResponse(
        status_code=500,
        content={"error": f"Internal server error: {str(exc)}"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
