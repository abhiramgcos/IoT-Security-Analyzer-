
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict
from backend.logger import Logger

logger = Logger('auth_service').get_logger()

# Try to import optional dependencies
try:
    from jose import JWTError, jwt
    from passlib.context import CryptContext
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logger.warning("python-jose and passlib not installed. Auth features limited.")

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Password hashing
if JWT_AVAILABLE:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """Authentication service for user management and JWT tokens"""
    
    def __init__(self, db):
        self.db = db
        self._ensure_users_table()
    
    def _ensure_users_table(self):
        """Create users table if it doesn't exist"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    api_key TEXT UNIQUE,
                    role TEXT DEFAULT 'user',
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
                ''')
                
                # Create sessions table for token tracking
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    token_hash TEXT,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                ''')
                
                conn.commit()
                logger.info("Auth tables initialized")
        except Exception as e:
            logger.error(f"Auth table creation failed: {e}")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        if not JWT_AVAILABLE:
            return plain_password == hashed_password  # Fallback (not secure!)
        return pwd_context.verify(plain_password, hashed_password)
    
    def hash_password(self, password: str) -> str:
        """Hash a password"""
        if not JWT_AVAILABLE:
            return password  # Fallback (not secure!)
        return pwd_context.hash(password)
    
    def generate_api_key(self) -> str:
        """Generate a new API key"""
        return f"iot_{secrets.token_urlsafe(32)}"
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        if not JWT_AVAILABLE:
            return secrets.token_urlsafe(32)
        
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify a JWT token and return the payload"""
        if not JWT_AVAILABLE:
            return None
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError as e:
            logger.warning(f"Token verification failed: {e}")
            return None
    
    def register_user(self, username: str, password: str, email: Optional[str] = None, 
                      role: str = "user") -> Dict:
        """Register a new user"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if user exists
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    return {"error": "Username already exists"}
                
                if email:
                    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                    if cursor.fetchone():
                        return {"error": "Email already exists"}
                
                # Hash password and generate API key
                password_hash = self.hash_password(password)
                api_key = self.generate_api_key()
                
                cursor.execute('''
                INSERT INTO users (username, email, password_hash, api_key, role)
                VALUES (?, ?, ?, ?, ?)
                ''', (username, email, password_hash, api_key, role))
                
                conn.commit()
                user_id = cursor.lastrowid
                
                logger.info(f"User registered: {username}")
                
                return {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "api_key": api_key,
                    "role": role
                }
                
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return {"error": str(e)}
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate a user and return user data"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                SELECT id, username, email, password_hash, api_key, role, is_active
                FROM users WHERE username = ?
                ''', (username,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                user = dict(row)
                
                if not user.get('is_active'):
                    return None
                
                if not self.verify_password(password, user['password_hash']):
                    return None
                
                # Update last login
                cursor.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now().isoformat(), user['id'])
                )
                conn.commit()
                
                # Remove password hash from response
                del user['password_hash']
                
                return user
                
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return None
    
    def get_user_by_api_key(self, api_key: str) -> Optional[Dict]:
        """Get user by API key"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                SELECT id, username, email, role, is_active
                FROM users WHERE api_key = ? AND is_active = 1
                ''', (api_key,))
                
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"API key lookup failed: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                SELECT id, username, email, role, is_active, created_at, last_login
                FROM users WHERE id = ?
                ''', (user_id,))
                
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"User lookup failed: {e}")
            return None
    
    def regenerate_api_key(self, user_id: int) -> Optional[str]:
        """Regenerate API key for a user"""
        try:
            new_key = self.generate_api_key()
            
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET api_key = ? WHERE id = ?",
                    (new_key, user_id)
                )
                conn.commit()
                
            return new_key
            
        except Exception as e:
            logger.error(f"API key regeneration failed: {e}")
            return None
    
    def create_default_admin(self):
        """Create default admin user if none exists"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE role = 'admin'")
                
                if not cursor.fetchone():
                    result = self.register_user(
                        username="admin",
                        password="admin123",  # Should be changed on first login
                        email="admin@localhost",
                        role="admin"
                    )
                    if "id" in result:
                        logger.info("Default admin user created (username: admin, password: admin123)")
                    return result
                
            return {"message": "Admin user already exists"}
            
        except Exception as e:
            logger.error(f"Default admin creation failed: {e}")
            return {"error": str(e)}
