
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from contextlib import asynccontextmanager
import asyncio
from backend.logger import Logger
from backend.database import Database
from backend.routes import scanner, firmware, vulnerabilities, traffic, reports, auth

logger = Logger('main').get_logger()
db = Database()

# Startup/Shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("=== IoT Security Analyzer Starting ===")
    logger.info("Backend API initialized")
    
    # Create default admin user if needed
    from backend.services.auth_service import AuthService
    auth_svc = AuthService(db)
    auth_svc.create_default_admin()
    
    yield
    # Shutdown
    logger.info("=== IoT Security Analyzer Shutting Down ===")

# Create FastAPI app
app = FastAPI(
    title="IoT Security Analyzer API",
    description="Network IoT device security analysis platform",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for dev (restrict in prod)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scanner.router, prefix="/api/scanner", tags=["Network Scanning"])
app.include_router(firmware.router, prefix="/api/firmware", tags=["Firmware Management"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerability Analysis"])
app.include_router(traffic.router, prefix="/api/traffic", tags=["Traffic Analysis"])
app.include_router(reports.router, prefix="/api/reports", tags=["Report Generation"])

# ========== HEALTH & INFO ENDPOINTS ==========

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "IoT Security Analyzer API",
        "version": "1.0.0"
    }

@app.get("/info", tags=["Info"])
async def get_info():
    """Get system information"""
    devices_count = len(db.get_all_devices())
    return {
        "service": "IoT Security Analyzer",
        "version": "1.0.0",
        "devices_scanned": devices_count,
        "database": "SQLite3",
        "api_docs": "/docs"
    }

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API documentation link"""
    return {
        "message": "IoT Security Analyzer API",
        "docs": "/docs",
        "redoc": "/redoc"
    }

# ========== ERROR HANDLERS ==========

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
