from dataclasses import dataclass, asdict, field
from enum import StrEnum

GROUP_SEED: int = 511584106


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int


class HasherType(StrEnum):
    PlainText = "PlainText"
    BCrypt = "BCrypt"
    Argon2ID = "Argon2ID"


@dataclass(frozen=True)
class HasherConfig:
    hasher_type: HasherType
    pepper: str | None = field(default=None)


@dataclass(frozen=True)
class DefenseConfig:
    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MFADefenseConfig(DefenseConfig):
    pass


@dataclass(frozen=True)
class RateLimitDefenseConfig(DefenseConfig):
    rate: int
    capacity: int


@dataclass(frozen=True)
class AccountLockoutDefenseConfig(DefenseConfig):
    max_attempts: int


@dataclass(frozen=True)
class CaptchaDefenseConfig(DefenseConfig):
    max_attempts: int


@dataclass(frozen=True)
class ClientConfig:
    target_url: str
    admin_url: str
    group_seed: int = field(default=GROUP_SEED, init=False)


@dataclass(frozen=True)
class PasswordConfig:
    weak_alphabet: str
    weak_length: int
    medium_alphabet: str
    medium_length: int
    strong_alphabet: str
    strong_length: int
