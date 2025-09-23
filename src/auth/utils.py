import jwt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional
import argon2

from src.common.database import user_db, session_db, blocked_token_db, User, Session
from src.auth.errors import InvalidTokenException, InvalidAccountException

# JWT secret key - in production, this should be in environment variables
JWT_SECRET_KEY = "your-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"

def create_jwt_token(user_id: int, expires_minutes: int) -> str:
    """Create a JWT token with user_id as subject"""
    expires_at = datetime.utcnow() + timedelta(minutes=expires_minutes)
    payload = {
        "sub": str(user_id),
        "exp": expires_at
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict:
    """Verify and decode JWT token"""
    try:
        # Check if token is in blacklist
        if token in blocked_token_db:
            raise InvalidTokenException()
        
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise InvalidTokenException()
    except jwt.InvalidTokenError:
        raise InvalidTokenException()

def authenticate_user(email: str, password: str) -> Optional[User]:
    """Authenticate user with email and password"""
    # Find user by email
    user = None
    for u in user_db:
        if u.email == email:
            user = u
            break
    
    if not user:
        return None
    
    # Verify password
    password_hasher = argon2.PasswordHasher()
    try:
        password_hasher.verify(user.hashed_password, password)
        return user
    except argon2.exceptions.VerifyMismatchError:
        return None

def create_session(user_id: int, lifespan_minutes: int) -> str:
    """Create a new session"""
    sid = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=lifespan_minutes)
    
    session = Session(
        sid=sid,
        user_id=user_id,
        expires_at=expires_at
    )
    
    session_db[sid] = session
    return sid

def get_user_from_session(sid: str) -> Optional[User]:
    """Get user from session ID"""
    if sid not in session_db:
        return None
    
    session = session_db[sid]
    
    # Check if session is expired
    if datetime.utcnow() > session.expires_at:
        # Remove expired session
        del session_db[sid]
        return None
    
    # Find and return user
    for user in user_db:
        if user.user_id == session.user_id:
            return user
    
    return None

def get_user_from_token(token: str) -> Optional[User]:
    """Get user from JWT token"""
    try:
        payload = verify_jwt_token(token)
        user_id = int(payload["sub"])
        
        # Find and return user
        for user in user_db:
            if user.user_id == user_id:
                return user
        
        return None
    except (InvalidTokenException, ValueError):
        return None

def add_token_to_blacklist(token: str):
    """Add token to blacklist"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
        exp_timestamp = payload.get("exp")
        if exp_timestamp:
            exp_datetime = datetime.fromtimestamp(exp_timestamp)
            blocked_token_db[token] = exp_datetime
    except jwt.InvalidTokenError:
        # If we can't decode the token, still add it to blacklist with current time
        blocked_token_db[token] = datetime.utcnow()

def cleanup_expired_tokens():
    """Remove expired tokens from blacklist"""
    current_time = datetime.utcnow()
    expired_tokens = [token for token, exp_time in blocked_token_db.items() if current_time > exp_time]
    for token in expired_tokens:
        del blocked_token_db[token] 