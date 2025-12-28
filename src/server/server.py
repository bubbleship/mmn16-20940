# Context manager to ensure user data is ready before the server starts
import threading
import csv
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from config.config import ServerConfig, DefenseConfig, MFADefenseConfig, RateLimitDefenseConfig, \
    AccountLockoutDefenseConfig, CaptchaDefenseConfig, DefensesConfig
from server import api
from server.api import router, DefenseMiddleware
from server.db import InMemoryDB, init_db, get_db
from server.defenses import MFADefense, RateLimitDefense, AccountLockoutDefense , CaptchaDefense
from server.hasher import set_hasher, PlainTextHasher, get_hasher
from server.models import User


def start(config: ServerConfig) -> None:
    # Startup: Initialize the research environment
    init_db(InMemoryDB())
    set_hasher(PlainTextHasher())

    app = FastAPI()
    app.include_router(router)  # Include API routes
    app.add_middleware(DefenseMiddleware)

    threading.Thread(
        target=lambda: uvicorn.run(app, host=config.host, port=config.port, log_level="info"),
        name="uvicorn",
        daemon=True
    ).start()


def set_users(path: Path) -> None:
    db = get_db()
    if db is None:
        raise RuntimeError("Database not initialized. Please call server.start() before calling set_users().")
    with open(path, 'r') as f:
        users = {}
        reader = csv.DictReader(f)
        for row in reader:
            username = row['username']
            password = row['password']
            hashed_password = get_hasher().hash_password(password)
            password_strength_class = row['strength_class']
            totp_secret = row['totp_secret']

            user = User(
                username=username,
                hashed_password=hashed_password,
                password_strength=password_strength_class,
                totp_secret=totp_secret,
                _internal_plain_password=password
            )
            users[username] = user
        db.users = users


def set_defenses(defense_config: DefensesConfig) -> None:
    defenses_map: dict[type[DefenseConfig], type] = {
        MFADefenseConfig: MFADefense,
        RateLimitDefenseConfig: RateLimitDefense,
        AccountLockoutDefenseConfig: AccountLockoutDefense,
        CaptchaDefenseConfig: CaptchaDefense
    }
    api.set_defenses([defenses_map[type(config)](**config.as_dict()) for config in defense_config.configs])
