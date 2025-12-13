from typing import Protocol

import pyotp

from server.models import LoginRequest, User


class Defense(Protocol):
    """Protocol defining the interface for all server-side defense implementations."""

    def __call__(self, login_request: LoginRequest, user: User) -> bool: ...


class MFADefence(Defense):
    """Multi-Factor Authentication (MFA) Defense that checks the user's TOTP code against the secret stored in the database."""

    def __call__(self, login_request: LoginRequest, user: User) -> bool:
        totp = pyotp.TOTP(user.totp_secret)
        return totp.verify(login_request.totp_code)
