from typing import Protocol


class Hasher(Protocol):
    """Protocol defining the interface for all hashing implementations."""

    def hash_password(self, password: str) -> str:
        """Generates a cryptographic hash of the password."""
        ...

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verifies a password against a stored hash."""
        ...


class PlainTextHasher(Hasher):
    """Control group: No hashing, simple comparison."""

    def hash_password(self, password: str) -> str:
        """For control case, the password is stored as plaintext."""
        return password

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Direct string comparison for verification."""
        return password == hashed_password


_hasher: Hasher | None = None


def set_hasher(hasher: Hasher) -> None:
    global _hasher
    _hasher = hasher


get_hasher = lambda: _hasher
