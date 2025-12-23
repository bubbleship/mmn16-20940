from typing import Awaitable, Callable

from fastapi import APIRouter, Depends, status, Request, Response , Query
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

import hmac
import hashlib
import time


from server.db import DB, get_db
from server.defenses import Defense
from server.hasher import Hasher, get_hasher
from server.models import LoginRequest
from server.responses import USERNAME_NOT_FOUND, INVALID_CREDENTIALS, LOGIN_SUCCESS , INVALID_GROUP_SEED

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
    request_group_seed: str = Query(...),
    db: DB = Depends(get_db)
):
    group_seed = db.get_group_seed()
    if request_group_seed != group_seed:
        return INVALID_GROUP_SEED

    timestamp = str(int(time.time()))
    #token = signature.timeStamp -> let us validate the time of creation and also slows the attacker
    signature = hmac.new(
        group_seed.encode(),
        timestamp.encode(),
        hashlib.sha256
    ).hexdigest()

    combined_token = f"{timestamp}.{signature}"

    return {"captcha_token": combined_token}
