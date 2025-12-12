# Context manager to ensure user data is ready before the server starts
import threading
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from config.config import ServerConfig
from server.api import router
from server.db import InMemoryDB, init_db
from server.hasher import set_hasher, PlainTextHasher


# noinspection PyUnusedLocal
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize the research environment
    init_db(InMemoryDB())
    set_hasher(PlainTextHasher())

    print(f"\n--- RESEARCH SERVER STARTUP ---")

    print("-----------------------------\n")

    yield

    print("\n--- RESEARCH SERVER SHUTDOWN ---\n")


class Server:
    def __init__(self, config: ServerConfig):
        self.config = config

        self.app = FastAPI(lifespan=lifespan)
        self.app.include_router(router)  # Include API routes

    def start(self) -> None:
        threading.Thread(
            target=lambda: uvicorn.run(self.app, host=self.config.host, port=self.config.port, log_level="info"),
            name="uvicorn",
            daemon=True
        ).start()
