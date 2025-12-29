from dataclasses import dataclass, asdict, field

GROUP_SEED: int = 511584106


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int


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
