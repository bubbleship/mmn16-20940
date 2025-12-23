from typing import Protocol

from server.models import User


class DB(Protocol):
    """Protocol defining the interface for all database implementations."""

    def save_user(self, user: User) -> None:
        """Saves a new user in the database."""
        ...

    def get_user(self, username) -> User | None:
        """Retrieves a user from the database by username if it exists."""
        ...

    def get_group_seed(self) -> int | None:
        ...


class InMemoryDB(DB):
    """Basic in-memory database implementation."""

    def __init__(self):
        self.users: dict[str, User] = {}
        self.group_seed: int = 123456789

    def save_user(self, user: User) -> None:
        self.users[user.username] = user

    def get_user(self, username) -> User | None:
        return self.users.get(username)

    def get_group_seed(self) -> int | None:
        return self.group_seed


_db: DB | None = None


def init_db(db: DB) -> None:
    global _db
    _db = db


def get_db() -> DB:
    if _db is None:
        raise RuntimeError("Database not initialized.")
    return _db
