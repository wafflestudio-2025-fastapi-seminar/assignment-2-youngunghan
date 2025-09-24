from fastapi import APIRouter, Depends, Cookie, Header, Response, status
from typing import Optional

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import LoginRequest, TokenResponse
from src.auth.utils import (
    authenticate_user, create_jwt_token, verify_jwt_token, 
    add_token_to_blacklist, create_session, get_user_from_session
)
from src.auth.errors import (
    InvalidAccountException, BadAuthorizationHeaderException, 
    InvalidTokenException, UnauthenticatedException
)

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

@auth_router.post("/token")
def login_token(request: LoginRequest) -> TokenResponse:
    # Authenticate user
    user = authenticate_user(request.email, request.password)
    if not user:
        raise InvalidAccountException()
    
    # Create tokens
    access_token = create_jwt_token(user.user_id, SHORT_SESSION_LIFESPAN)
    refresh_token = create_jwt_token(user.user_id, LONG_SESSION_LIFESPAN)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )

@auth_router.post("/token/refresh")
def refresh_token(authorization: Optional[str] = Header(None)) -> TokenResponse:
    # Check authorization header
    if not authorization:
        raise UnauthenticatedException()
    
    # Parse Bearer token
    if not authorization.startswith("Bearer "):
        raise BadAuthorizationHeaderException()
    
    token = authorization[7:]  # Remove "Bearer " prefix
    
    # Verify refresh token
    try:
        payload = verify_jwt_token(token)
        user_id = int(payload["sub"])
    except (InvalidTokenException, ValueError):
        raise InvalidTokenException()
    
    # Find user
    user = None
    for u in user_db:
        if u.user_id == user_id:
            user = u
            break
    
    if not user:
        raise InvalidTokenException()
    
    # Add old refresh token to blacklist
    add_token_to_blacklist(token)
    
    # Create new tokens
    new_access_token = create_jwt_token(user.user_id, SHORT_SESSION_LIFESPAN)
    new_refresh_token = create_jwt_token(user.user_id, LONG_SESSION_LIFESPAN)
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token
    )

@auth_router.delete("/token")
def logout_token(authorization: Optional[str] = Header(None)):
    # Check authorization header
    if not authorization:
        raise UnauthenticatedException()
    
    # Parse Bearer token
    if not authorization.startswith("Bearer "):
        raise BadAuthorizationHeaderException()
    
    token = authorization[7:]  # Remove "Bearer " prefix
    
    # Verify token (just to make sure it's valid before blacklisting)
    try:
        verify_jwt_token(token)
    except InvalidTokenException:
        raise InvalidTokenException()
    
    # Add to blacklist
    add_token_to_blacklist(token)
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@auth_router.post("/session")
def login_session(request: LoginRequest, response: Response):
    # Authenticate user
    user = authenticate_user(request.email, request.password)
    if not user:
        raise InvalidAccountException()
    
    # Create session
    sid = create_session(user.user_id, LONG_SESSION_LIFESPAN)
    
    # Set cookie
    response.set_cookie(key="sid", value=sid, httponly=True)
    
    return {"message": "Session created successfully"}

@auth_router.delete("/session")
def logout_session(response: Response, sid: Optional[str] = Cookie(None)):
    # Always return 204, regardless of whether session exists
    if sid:
        # Remove session from database if it exists
        if sid in session_db:
            del session_db[sid]
        
        # Delete the cookie by using delete_cookie method
        response.delete_cookie(key="sid")
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)
