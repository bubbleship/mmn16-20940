import asyncio
from enum import StrEnum
from typing import Protocol, Iterable

from client.client import Client


class Result(StrEnum):
    SUCCESS = "SUCCESS"
    INVALID_CREDENTIALS = "INVALID CREDENTIALS"
    USERNAME_NOT_FOUND = "USERNAME NOT FOUND"
    MFA = "MFA"
    RATE_LIMIT = "RATE LIMIT"
    ACCOUNT_LOCKOUT = "ACCOUNT LOCKOUT"
    CAPTCHA = "CAPTCHA"
    INTERNAL_SERVER_ERROR = "INTERNAL SERVER ERROR"


class Attacker(Protocol):
    """Represents an attacker that can launch attacks against a target."""

    def __init__(self, client: Client):
        self.client: Client = client

    async def launch_attack(self, targets: Iterable[str], patterns: Iterable[str], delay: float = 0.0) -> None:
        """
        Simulates a dictionary-based attack on the given targets.

        Args:
            targets: username to target in the attack
            patterns: an iterable of passwords to try against the targets
            delay: the delay between each password attempt, in seconds. Defaults to None.

        Returns:
            The result of the attack.
        """
        ...

    async def attempt_login(self, username: str, password: str) -> Result:
        """Attempts to log in with the given username and password and interprets the result."""
        response = await self.client.send_login_request(username, password)
        # noinspection PyRedundantParentheses
        match (response.status_code):
            case 200:
                return Result.SUCCESS
            case 401:
                return Result.INVALID_CREDENTIALS
            case 404:
                return Result.USERNAME_NOT_FOUND
            case 403:
                return Result.MFA
            case 429:
                return Result.RATE_LIMIT
            case 423:
                return Result.ACCOUNT_LOCKOUT
            case 418:
                return Result.CAPTCHA
            case _:
                return Result.INTERNAL_SERVER_ERROR


class BruteForceAttacker(Attacker):
    """Represents a brute force attacker that tries the given dictionary of passwords against a small set of targets."""

    async def launch_attack(self, targets: Iterable[str], patterns: Iterable[str], delay: float = 0.0) -> None:
        for target in targets:
            for pattern in patterns:
                result = await self.attempt_login(target, pattern)
                await asyncio.sleep(delay)
                if result is Result.INVALID_CREDENTIALS:
                    continue
                else:  # LOGIN_SUCCESS, USERNAME_NOT_FOUND, any defenses
                    break
        raise ValueError('Empty targets or patterns not allowed.')


class PasswordSprayAttacker(Attacker):
    """Represents a password spray attacker that tries the given dictionary of passwords against a large set of targets."""

    async def launch_attack(self, targets: Iterable[str], patterns: Iterable[str], delay: float = 0.0) -> None:
        for pattern in patterns:
            for target in targets:
                result = await self.attempt_login(target, pattern)
                await asyncio.sleep(delay)
                if result is Result.INVALID_CREDENTIALS:
                    continue
                else:  # LOGIN_SUCCESS, USERNAME_NOT_FOUND, any defenses
                    break
        raise ValueError('Empty targets or patterns not allowed.')
