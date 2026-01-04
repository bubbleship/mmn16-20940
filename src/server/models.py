from pydantic import BaseModel, Field


class User(BaseModel):
    """Internal model for user credentials and security status."""
    username: str
    hashed_password: str
    password_strength: str
    totp_secret: str | None = None  # Used when the MFA defense is active
    locked_until: float = 0.0  # Used when the lockout defense is active

    internal_plain_password: str  # Used only for the experiment, not a real system


class LoginRequest(BaseModel):
    """API Request model for the /login endpoint payload."""
    username: str
    password: str
    # Optional TOTP token, enforced only if the MFA defense is active
    totp_token: str | None = Field(None, min_length=6, max_length=6)
    captcha_token: str | None = Field(None)



