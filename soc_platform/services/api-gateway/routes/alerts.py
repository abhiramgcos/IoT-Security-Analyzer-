from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db

router = APIRouter()

@router.get("/")
async def list_alerts(db: AsyncSession = Depends(get_db)):
    """Get IDS alerts"""
    return {"alerts": []}

@router.patch("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int):
    """Acknowledge an alert"""
    return {"message": "Alert acknowledged", "alert_id": alert_id}
