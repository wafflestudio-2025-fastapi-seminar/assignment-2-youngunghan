from typing import Annotated, Optional
import argon2

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db, User
import src.common.database as db
from src.users.errors import EmailAlreadyExistsException
from src.auth.utils import get_user_from_session, get_user_from_token
from src.auth.errors import (
    InvalidSessionException, BadAuthorizationHeaderException, 
    InvalidTokenException, UnauthenticatedException
)

user_router = APIRouter(prefix="/users", tags=["users"])

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    # Check if email already exists
    for existing_user in user_db:
        if existing_user.email == request.email:
            raise EmailAlreadyExistsException()
    
    # Hash the password
    password_hasher = argon2.PasswordHasher()
    hashed_password = password_hasher.hash(request.password)
    
    # Create new user
    new_user = User(
        user_id=db.next_user_id,
        email=request.email,
        hashed_password=hashed_password,
        name=request.name,
        phone_number=request.phone_number,
        height=request.height,
        bio=request.bio
    )
    
    # Add to database
    user_db.append(new_user)
    db.next_user_id += 1
    
    # Return user response (without password)
    return UserResponse(
        user_id=new_user.user_id,
        name=new_user.name,
        email=new_user.email,
        phone_number=new_user.phone_number,
        height=new_user.height,
        bio=new_user.bio
    )

@user_router.get("/me")
def get_user_info(
    sid: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None)
) -> UserResponse:
    user = None
    
    # Try session-based authentication first
    if sid:
        user = get_user_from_session(sid)
        if not user:
            raise InvalidSessionException()
    
    # Try token-based authentication if no session
    elif authorization:
        # Parse Bearer token
        if not authorization.startswith("Bearer "):
            raise BadAuthorizationHeaderException()
        
        token = authorization[7:]  # Remove "Bearer " prefix
        user = get_user_from_token(token)
        if not user:
            raise InvalidTokenException()
    
    # No authentication provided
    else:
        raise UnauthenticatedException()
    
    # Return user info
    return UserResponse(
        user_id=user.user_id,
        name=user.name,
        email=user.email,
        phone_number=user.phone_number,
        height=user.height,
        bio=user.bio
    )