from typing import Protocol

import bcrypt
from argon2 import PasswordHasher, Type as Argon2Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError


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


class BcryptHasher(Hasher):
    """Implements bcrypt legacy hashing with an OWASP recommended cost factor."""

    def __init__(self, pepper: str | None = None):
        """Initializes pepper and bcrypt hasher with recommended parameters."""
        self.pepper = pepper
        self.work_factor = 12  # 12 >= 10 per OWASP recommendation

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt with pepper if set."""
        if self.pepper:
            password = f'{password}{self.pepper}'

        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=self.work_factor)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against bcrypt hash."""
        if self.pepper:
            password = f'{password}{self.pepper}'

        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        try:
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except ValueError:
            # Handles issues like hash being truncated or malformed
            return False


class Argon2IDHasher:
    """Implements Argon2ID hashing with OWASP recommended parameters."""

    def __init__(self, pepper: str | None = None):
        """Initializes pepper and Argon2ID hasher with recommended parameters."""
        self.pepper = pepper
        self.ph = PasswordHasher(
            time_cost=2,
            memory_cost=19 * 1024,
            parallelism=1,
            type=Argon2Type.ID
        )

    def hash_password(self, password: str) -> str:
        """Hash password using Argon2ID with pepper if set."""
        if self.pepper:
            password = f'{password}{self.pepper}'

        return self.ph.hash(password)

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against Argon2ID hash."""
        if self.pepper:
            password = f'{password}{self.pepper}'

        try:
            return self.ph.verify(hashed_password, password)
        except VerifyMismatchError | VerificationError | InvalidHashError:
            return False


_hasher: Hasher | None = None


def set_hasher(hasher: Hasher) -> None:
    global _hasher
    _hasher = hasher


get_hasher = lambda: _hasher
