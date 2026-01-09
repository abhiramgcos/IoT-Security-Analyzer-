
from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from backend.database import Database
from backend.services.auth_service import AuthService
from backend.logger import Logger

logger = Logger('auth_routes').get_logger()
router = APIRouter()
security = HTTPBearer(auto_error=False)

# Initialize auth service
db = Database()
auth_service = AuthService(db)

# ========== PYDANTIC MODELS ==========

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    email: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str]
    role: str

# ========== DEPENDENCY FOR AUTHENTICATION ==========

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None)
):
    """
    Dependency to get current authenticated user.
    Supports both JWT token and API key authentication.
    """
    # Try JWT token first
    if credentials:
        token = credentials.credentials
        payload = auth_service.verify_token(token)
        if payload:
            user_id = payload.get("sub")
            if user_id:
                user = auth_service.get_user_by_id(int(user_id))
                if user:
                    return user
    
    # Try API key
    if x_api_key:
        user = auth_service.get_user_by_api_key(x_api_key)
        if user:
            return user
    
    # No valid authentication
    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"}
    )

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None)
):
    """
    Optional authentication - returns None if not authenticated
    """
    try:
        return await get_current_user(credentials, x_api_key)
    except HTTPException:
        return None

# ========== ENDPOINTS ==========

@router.post("/register", response_model=dict)
async def register(user: UserRegister):
    """
    Register a new user
    
    ### Parameters:
    - **username**: Unique username (3-50 characters)
    - **password**: Password (min 6 characters)
    - **email**: Optional email address
    
    ### Returns:
    User details with API key (store this securely!)
    """
    logger.info(f"Registration attempt for: {user.username}")
    
    result = auth_service.register_user(
        username=user.username,
        password=user.password,
        email=user.email
    )
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return {
        "message": "User registered successfully",
        "user": {
            "id": result["id"],
            "username": result["username"],
            "email": result["email"],
            "role": result["role"]
        },
        "api_key": result["api_key"]  # Only shown once!
    }

@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """
    Login with username and password
    
    ### Parameters:
    - **username**: Your username
    - **password**: Your password
    
    ### Returns:
    JWT access token for API authentication
    """
    logger.info(f"Login attempt for: {credentials.username}")
    
    user = auth_service.authenticate_user(
        username=credentials.username,
        password=credentials.password
    )
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )
    
    # Create access token
    access_token = auth_service.create_access_token(
        data={"sub": str(user["id"]), "username": user["username"]}
    )
    
    return TokenResponse(
        access_token=access_token,
        user={
            "id": user["id"],
            "username": user["username"],
            "email": user.get("email"),
            "role": user["role"]
        }
    )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Get current authenticated user info
    
    Requires: Bearer token or X-API-Key header
    """
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user.get("email"),
        role=current_user["role"]
    )

@router.post("/regenerate-api-key")
async def regenerate_api_key(current_user: dict = Depends(get_current_user)):
    """
    Regenerate API key for current user
    
    **Warning**: This invalidates your old API key!
    """
    new_key = auth_service.regenerate_api_key(current_user["id"])
    
    if not new_key:
        raise HTTPException(status_code=500, detail="Failed to regenerate API key")
    
    return {
        "message": "API key regenerated successfully",
        "api_key": new_key  # Only shown once!
    }

@router.get("/health")
async def auth_health():
    """Check auth service health"""
    return {"status": "ok", "service": "authentication"}

# Create default admin on import (optional)
# Uncomment to auto-create admin user
# auth_service.create_default_admin()
