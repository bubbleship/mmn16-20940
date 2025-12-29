import hashlib
import hmac
from typing import Awaitable, Callable

from fastapi import APIRouter, Depends, status, Request, Response, Query
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from src.config.config import GROUP_SEED
from src.server.db import DB, get_db
from src.server.defenses import Defense
from src.server.hasher import Hasher, get_hasher
from src.server.models import LoginRequest
from src.server.responses import USERNAME_NOT_FOUND, INVALID_CREDENTIALS, LOGIN_SUCCESS, INVALID_GROUP_SEED

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
                return USERNAME_NOT_FOUND
            for defense in _defenses:
                if not await defense.pre_login(request, login_request, user):
                    return defense.response
            response = await call_next(request)
            for defense in _defenses:
                if not await defense.post_login(request, response, login_request, user):
                    return defense.response
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

    is_password_correct = hasher.verify_password(password, user.hashed_password)
    if not is_password_correct:
        return INVALID_CREDENTIALS

    return LOGIN_SUCCESS


@router.get("/admin/get_captcha_token", status_code=status.HTTP_200_OK)
async def get_captcha_token(
        request_group_seed: str = Query(...)
):
    if request_group_seed != GROUP_SEED:
        return INVALID_GROUP_SEED

    token = hmac.new(  # It doesn't matter what the token is, in the experiment
        str(GROUP_SEED).encode(),
        None,
        hashlib.sha256
    ).hexdigest()

    return {"captcha_token": token}
