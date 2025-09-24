from fastapi import APIRouter

from src.users.router import user_router

api_router = APIRouter(prefix="/api")

api_router.include_router(user_router)