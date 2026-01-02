from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, JSON, Text, BigInteger
from sqlalchemy.dialects.postgresql import INET, MACADDR, JSONB
import os
from datetime import datetime

# Database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://socuser:changeme@localhost:5432/iot_soc")

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    pool_size=10,
    max_overflow=20
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Base class for models
Base = declarative_base()

# ============================================
# Database Models
# ============================================

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(INET, unique=True, nullable=False)
    mac_address = Column(MACADDR, unique=True, nullable=False)
    hostname = Column(String(255))
    manufacturer = Column(String(255))
    model = Column(String(255))
    firmware_version = Column(String(100))
    device_type = Column(String(50))
    os_family = Column(String(100))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default='active')
    confidence_score = Column(Float, default=0.0)
    extra_data = Column("metadata", JSONB)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    src_ip = Column(INET)
    dst_ip = Column(INET)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(10))
    signature = Column(Text, nullable=False)
    signature_id = Column(Integer)
    severity = Column(Integer)
    category = Column(String(100))
    payload = Column(Text)
    packet_data = Column(Text)  # Base64 encoded
    acknowledged = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    notes = Column(Text)
    extra_data = Column("metadata", JSONB)

class Firmware(Base):
    __tablename__ = "firmware"
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer)  # Foreign key to devices
    firmware_hash = Column(String(64), unique=True, nullable=False)
    manufacturer = Column(String(255))
    model = Column(String(255))
    version = Column(String(100))
    filename = Column(String(255))
    file_size = Column(BigInteger)
    upload_date = Column(DateTime, default=datetime.utcnow)
    analysis_status = Column(String(20), default='pending')
    filesystem_extracted = Column(Boolean, default=False)
    emulation_possible = Column(Boolean, default=False)
    extra_data = Column("metadata", JSONB)

class FirmwareVulnerability(Base):
    __tablename__ = "firmware_vulnerabilities"
    
    id = Column(Integer, primary_key=True)
    firmware_id = Column(Integer)  # Foreign key to firmware
    cve_id = Column(String(20), nullable=False)
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    severity = Column(String(20))
    description = Column(Text)
    affected_component = Column(String(255))
    exploitable = Column(Boolean, default=False)
    patch_available = Column(Boolean, default=False)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    extra_data = Column("metadata", JSONB)

# ============================================
# Dependency injection
# ============================================

async def get_db():
    """Database session dependency"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
