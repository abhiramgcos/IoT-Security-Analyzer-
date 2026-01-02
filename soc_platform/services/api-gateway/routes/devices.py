from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from database import get_db, Device

router = APIRouter()

# ============================================
# Pydantic Models
# ============================================

class DeviceResponse(BaseModel):
    id: int
    ip_address: str
    mac_address: str
    hostname: Optional[str]
    manufacturer: Optional[str]
    model: Optional[str]
    firmware_version: Optional[str]
    device_type: Optional[str]
    status: str
    first_seen: datetime
    last_seen: datetime
    
    class Config:
        from_attributes = True

class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    notes: Optional[str] = None

# ============================================
# Endpoints
# ============================================

@router.get("/", response_model=List[DeviceResponse])
async def list_devices(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    device_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get list of discovered devices"""
    query = select(Device)
    
    if status:
        query = query.where(Device.status == status)
    if device_type:
        query = query.where(Device.device_type == device_type)
    
    query = query.order_by(Device.last_seen.desc()).limit(limit).offset(offset)
    
    result = await db.execute(query)
    devices = result.scalars().all()
    
    return devices

@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(device_id: int, db: AsyncSession = Depends(get_db)):
    """Get specific device by ID"""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return device

@router.patch("/{device_id}")
async def update_device(
    device_id: int,
    device_update: DeviceUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update device information"""
    update_data = device_update.model_dump(exclude_unset=True)
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No update data provided")
    
    result = await db.execute(
        update(Device).where(Device.id == device_id).values(**update_data)
    )
    
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Device not found")
    
    await db.commit()
    
    return {"message": "Device updated successfully"}

@router.delete("/{device_id}")
async def delete_device(device_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a device"""
    result = await db.execute(delete(Device).where(Device.id == device_id))
    
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Device not found")
    
    await db.commit()
    
    return {"message": "Device deleted successfully"}

@router.get("/{device_id}/vulnerabilities")
async def get_device_vulnerabilities(device_id: int, db: AsyncSession = Depends(get_db)):
    """Get vulnerabilities for a specific device"""
    # TODO: Join with firmware_vulnerabilities table
    return {"device_id": device_id, "vulnerabilities": []}

@router.post("/{device_id}/scan")
async def trigger_device_scan(device_id: int, db: AsyncSession = Depends(get_db)):
    """Trigger a deep scan for a specific device"""
    # TODO: Trigger nmap scan via device-scanner service
    return {"message": "Scan triggered", "device_id": device_id}
