from typing import Awaitable, Callable

from fastapi import APIRouter, Depends, status, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from server.db import DB, get_db
from server.defenses import Defense
from server.hasher import Hasher, get_hasher
from server.models import LoginRequest

AUTH_FAILED_RESPONSE = Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Invalid credentials")

_defenses: list[Defense] = []


def set_defenses(defenses: list[Defense]):
    global _defenses
    _defenses = defenses


class DefenseMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable | Awaitable) -> Response:
        if request.url.path == "/login":
            login_request = LoginRequest.model_validate(await request.json())
            user = get_db().get_user(login_request.username)
            if user is None:
                return AUTH_FAILED_RESPONSE
            for defense in _defenses:
                if not await defense.pre_login(request, login_request, user):
                    return AUTH_FAILED_RESPONSE
            response = await call_next(request)
            for defense in _defenses:
                if not await defense.post_login(request, response, login_request, user):
                    return AUTH_FAILED_RESPONSE
            return response
        return await call_next(request)


router = APIRouter()


@router.post("/login", status_code=status.HTTP_200_OK)
async def login(
        request: Request,
        db: DB = Depends(get_db),
        hasher: Hasher = Depends(get_hasher)
):
    login_request = LoginRequest.model_validate(await request.json())
    username, password = login_request.username, login_request.password
    user = db.get_user(username)
    if not user:
        return AUTH_FAILED_RESPONSE

    is_password_correct = hasher.verify_password(password, user.hashed_password)
    if not is_password_correct:
        return AUTH_FAILED_RESPONSE

    return {
        "access_token": f"SUCCESS_TOKEN_FOR_{username}",
        "token_type": "bearer",
        "message": "Authentication successful"
    }
