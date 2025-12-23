from dataclasses import dataclass, asdict


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
class DefensesConfig:
    configs: set[DefenseConfig]


@dataclass(frozen=True)
class ClientConfig:
    target_url: str
    admin_url: str
