from fastapi import APIRouter

router = APIRouter()

@router.post("/login")
async def login():
    """Login endpoint"""
    return {"token": "stub_token"}

@router.post("/logout")
async def logout():
    """Logout endpoint"""
    return {"message": "Logged out"}
