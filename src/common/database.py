from typing import Dict, List, Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime

class User(BaseModel):
    user_id: int
    email: EmailStr
    hashed_password: str
    name: str
    phone_number: str
    height: float
    bio: Optional[str] = None

class Session(BaseModel):
    sid: str
    user_id: int
    expires_at: datetime

# Database storage
blocked_token_db: Dict[str, datetime] = {}  # token -> expiry_time
user_db: List[User] = []
session_db: Dict[str, Session] = {}  # sid -> Session
next_user_id: int = 1