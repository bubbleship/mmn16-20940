# Context manager to ensure user data is ready before the server starts
import threading

import uvicorn
from fastapi import FastAPI

from config.config import ServerConfig
from server.api import router, DefenseMiddleware
from server.db import InMemoryDB, init_db
from server.hasher import set_hasher, PlainTextHasher


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
