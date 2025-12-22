
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # App Config
    APP_NAME: str = "IoT Security Analyzer"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Network Scanning
    SCAN_SUBNET: str = "192.168.1.0/24"
    SCAN_INTERFACE: str = "eth0"
    SCAN_TIMEOUT: int = 300
    
    # Database
    DB_PATH: str = "./data/devices.db"
    
    # Paths
    FIRMWARE_CACHE_DIR: str = "./data/firmware"
    REPORT_DIR: str = "./data/reports"
    PCAP_DIR: str = "./data/pcaps"
    LOG_DIR: str = "./logs"
    
    # External APIs
    NVD_API_KEY: str = ""
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

# Ensure directories exist
for path in [settings.FIRMWARE_CACHE_DIR, settings.REPORT_DIR, settings.PCAP_DIR, settings.LOG_DIR]:
    os.makedirs(path, exist_ok=True)
