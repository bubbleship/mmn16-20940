from dataclasses import dataclass, asdict


@dataclass
class ServerConfig:
    host: str
    port: int


@dataclass
class DefenseConfig:
    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class MFADefenseConfig(DefenseConfig):
    pass


@dataclass
class RateLimitDefenseConfig(DefenseConfig):
    rate: int
    capacity: int


@dataclass
class AccountLockoutDefenseConfig(DefenseConfig):
    max_attempts: int


@dataclass
class DefensesConfig:
    configs: set[DefenseConfig]


@dataclass
class ClientConfig:
    target_url: str
