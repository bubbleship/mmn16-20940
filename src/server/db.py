from typing import Protocol

from src.server.models import User


class DB(Protocol):
    """Protocol defining the interface for all database implementations."""

    def save_user(self, user: User) -> None:
        """Saves a new user in the database."""
        ...

    def get_user(self, username) -> User | None:
        """Retrieves a user from the database by username if it exists."""
        ...

    @property
    def users(self) -> dict[str, User]:
        """Returns a dictionary of all users in the database."""
        ...

    def clear(self):
        """Clears the database of all users."""
        ...


class InMemoryDB(DB):
    """Basic in-memory database implementation."""

    def __init__(self):
        self._users: dict[str, User] = {}

    def save_user(self, user: User) -> None:
        self._users[user.username] = user

    def get_user(self, username) -> User | None:
        return self._users.get(username)

    @property
    def users(self) -> dict[str, User]:
        return self._users

    def clear(self):
        self._users.clear()


_db: DB | None = None


def init_db(db: DB) -> None:
    global _db
    _db = db


def get_db() -> DB:
    if _db is None:
        raise RuntimeError("Database not initialized.")
    return _db
