from pydantic import BaseModel


class User(BaseModel):
    """Internal model for user credentials and security status."""
    username: str
    hashed_password: str
    password_strength: str
    _internal_plain_password: str  # Used only for testing, excluded from API


class LoginRequest(BaseModel):
    """API Request model for the /login endpoint payload."""
    username: str
    password: str
