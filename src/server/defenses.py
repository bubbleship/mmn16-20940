import time
from collections import defaultdict
from typing import Protocol

import pyotp
from fastapi import Request, Response

from server.db import get_db
from server.models import LoginRequest, User
from server.responses import INVALID_TOKEN, ACCOUNT_LOCKED, TOO_MANY_REQUESTS


class Defense(Protocol):
    """Protocol defining the interface for all server-side defense implementations."""

    async def pre_login(self, request: Request, login_request: LoginRequest, user: User) -> bool: ...

    async def post_login(self, request: Request, response: Response, login_request: LoginRequest, user: User) -> bool: ...

    @property
    def response(self) -> Response: ...


class MFADefense(Defense):
    """Multi-Factor Authentication (MFA) Defense that checks the user's TOTP token against the secret stored in the database."""

    async def pre_login(self, request: Request, login_request: LoginRequest, user: User) -> bool:
        totp = pyotp.TOTP(user.totp_secret)
        return totp.verify(login_request.totp_token)

    async def post_login(self, request: Request, response: Response, login_request: LoginRequest, user: User) -> bool:
        return True

    @property
    def response(self) -> Response:
        return INVALID_TOKEN


class RateLimitDefense(Defense):
    """
    Rate Limiting Defense that limits the number of login attempts per IP address.

    Implements the Token Bucket Algorithm (https://en.wikipedia.org/wiki/Token_bucket).
    """

    class TokenBucket:
        """Simple token bucket implementation with fixed capacity and refill rate."""

        def __init__(self, rate: int, capacity: int):
            self.capacity = capacity  # Maximum number of tokens for this bucket
            self.rate = rate  # Refill rate: the rate at which tokens are added
            self.tokens = capacity  # Current token count: starts with a full bucket
            self.last_refill = time.time()  # Last time the bucket was checked

        def allow_request(self) -> bool:
            now = time.time()
            # Calculate the number of tokens added since the last check
            self.tokens += (now - self.last_refill) * self.rate
            self.tokens = min(self.tokens, self.capacity)
            self.last_refill = now

            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

    def __init__(self, rate: int = 10, capacity: int = 20):
        self.rate: int = rate
        self.capacity: int = capacity
        bucket_factory = lambda: RateLimitDefense.TokenBucket(rate, capacity)
        self.buckets: defaultdict[str, RateLimitDefense.TokenBucket] = defaultdict(bucket_factory)

    async def pre_login(self, request: Request, login_request: LoginRequest, user: User) -> bool:
        return self.buckets[request.client.host].allow_request()

    async def post_login(self, request: Request, response: Response, login_request: LoginRequest, user: User) -> bool:
        return True

    @property
    def response(self) -> Response:
        return TOO_MANY_REQUESTS


class AccountLockoutDefense(Defense):
    """Lockout Defense that prevents brute force attacks by limiting the number of failed login attempts per account."""

    class AttemptTracker:
        def __init__(self, max_attempts: int):
            self.max_attempts: int = max_attempts
            self.count: int = 0

        def make_attempt(self) -> bool:
            self.count += 1
            return self.count < self.max_attempts

    def __init__(self, max_attempts: int = 5):
        self.max_attempts: int = max_attempts
        attempt_tracker_factory = lambda: AccountLockoutDefense.AttemptTracker(max_attempts)
        self.attempts: defaultdict[str, AccountLockoutDefense.AttemptTracker] = defaultdict(attempt_tracker_factory)

    async def pre_login(self, request: Request, login_request: LoginRequest, user: User) -> bool:
        now = time.time()
        return user.locked_until < now

    async def post_login(self, request: Request, response: Response, login_request: LoginRequest, user: User) -> bool:
        now = time.time()
        if response.status_code == 200:
            self.attempts.pop(user.username, None)
            return True
        # Login attempt unsuccessful
        if self.attempts[user.username].make_attempt():
            return True  # An attempt within range
        user.locked_until = now + 60 * 60  # Too many failed attempts
        get_db().save_user(user)  # Update user entry in the database (has no effect when db is in-memory)
        self.attempts.pop(user.username, None)  # Attempt tracker instance is no longer needed
        return False

    @property
    def response(self) -> Response:
        return ACCOUNT_LOCKED
