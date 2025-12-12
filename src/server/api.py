from fastapi import APIRouter, Depends, status, HTTPException

from server.db import DB, get_db
from server.hasher import Hasher, get_hasher
from server.models import LoginRequest

AUTH_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid credentials",
    headers={"WWW-Authenticate": "Bearer"}
)

router = APIRouter()


@router.post("/login", status_code=status.HTTP_200_OK)
async def login(
        login_request: LoginRequest,
        db: DB = Depends(get_db),
        hasher: Hasher = Depends(get_hasher)
):
    username, password = login_request.username, login_request.password
    user = db.get_user(username)
    if not user:
        raise AUTH_EXCEPTION

    is_password_correct = hasher.verify_password(password, user.hashed_password)
    if not is_password_correct:
        raise AUTH_EXCEPTION

    return {
        "access_token": f"SUCCESS_TOKEN_FOR_{username}",
        "token_type": "bearer",
        "message": "Authentication successful"
    }
