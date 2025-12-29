import threading

import uvicorn
from fastapi import FastAPI

from src.config.config import ServerConfig, DefenseConfig, MFADefenseConfig, RateLimitDefenseConfig, \
    AccountLockoutDefenseConfig, CaptchaDefenseConfig, HasherConfig, HasherType
from src.server import api
from src.server import hasher
from src.server.api import router, DefenseMiddleware
from src.server.db import InMemoryDB, init_db, get_db
from src.server.defenses import MFADefense, RateLimitDefense, AccountLockoutDefense, CaptchaDefense
from src.server.hasher import PlainTextHasher, get_hasher, Hasher, BCryptHasher, Argon2IDHasher
from src.server.models import User


def start(config: ServerConfig) -> None:
    # Startup: Initialize the research environment
    init_db(InMemoryDB())
    hasher.set_hasher(PlainTextHasher(HasherConfig(hasher_type=HasherType.PlainText)))

    app = FastAPI()
    app.include_router(router)  # Include API routes
    app.add_middleware(DefenseMiddleware)

    threading.Thread(
        target=lambda: uvicorn.run(app, host=config.host, port=config.port, log_level="info"),
        name="uvicorn",
        daemon=True
    ).start()


def set_users(user_list: list[dict]) -> None:
    db = get_db()
    if db is None:
        raise RuntimeError("Database not initialized. Please call server.start() before calling set_users().")
    users = {}
    for entry in user_list:
        username = entry['username']
        password = entry['password']
        hashed_password = get_hasher().hash_password(password)
        password_strength_class = entry['strength_class']
        totp_secret = entry['totp_secret']

        user = User(
            username=username,
            hashed_password=hashed_password,
            password_strength=password_strength_class,
            totp_secret=totp_secret,
            _internal_plain_password=password
        )
        users[username] = user
    db.users = users


def set_hasher(hasher_config: HasherConfig) -> None:
    """Sets the hasher to be used by the server."""
    hasher_map: dict[HasherType, type[Hasher]] = {
        HasherType.PlainText: PlainTextHasher,
        HasherType.BCrypt: BCryptHasher,
        HasherType.Argon2ID: Argon2IDHasher
    }
    hasher.set_hasher(hasher_map[hasher_config.hasher_type](hasher_config))


def set_defenses(*args: DefenseConfig) -> None:
    defenses_map: dict[type[DefenseConfig], type] = {
        MFADefenseConfig: MFADefense,
        RateLimitDefenseConfig: RateLimitDefense,
        AccountLockoutDefenseConfig: AccountLockoutDefense,
        CaptchaDefenseConfig: CaptchaDefense
    }
    api.set_defenses([defenses_map[type(config)](**config.as_dict()) for config in args])
