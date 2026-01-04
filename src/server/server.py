"""
Password Security Experiment Server Control Module

This module provides runtime control interfaces for configuring and managing
the server during the experiment. It enables dynamic reconfiguration of
cryptographic hashing algorithms, defense mechanisms, and user databases without
requiring server restarts.

This module abstracts the complexity of server state management and provides
a clean interface for experimental scenarios to modify server behavior.
"""

import threading
from typing import Iterable

import uvicorn
from fastapi import FastAPI

from src.config.config import ServerConfig, DefenseConfig, MFADefenseConfig, RateLimitDefenseConfig, \
    AccountLockoutDefenseConfig, CaptchaDefenseConfig, HasherConfig, HasherType
from src.server import api
from src.server import hasher
from src.server.api import router, DefenseMiddleware
from src.server.db import InMemoryDB, init_db, get_db
from src.server.defenses import MFADefense, RateLimitDefense, AccountLockoutDefense, CaptchaDefense
from src.server.hasher import PlainTextHasher, Hasher, BCryptHasher, Argon2IDHasher
from src.server.models import User


def start(config: ServerConfig) -> None:
    """
    Initialize and start the experimental authentication server in daemon mode.
    
    Creates a FastAPI application instance with an authentication endpoint and
    defense middleware, then launches it as a background daemon thread. Initializes
    the in-memory database and sets a placeholder plaintext hasher.
    
    The server runs asynchronously to allow the experiment runner to continue
    execution while maintaining server availability for attack simulations.
    
    Args:
        config: Server configuration specifying host address and port binding.
        
    Note:
        This function must be called before any other server control functions
        to ensure proper initialization of the database.
    """
    # Startup: Initialize the research environment
    init_db(InMemoryDB())
    hasher.set_hasher(PlainTextHasher(HasherConfig(hasher_type=HasherType.PlainText)))

    app = FastAPI()
    app.include_router(router)  # Include API routes
    app.add_middleware(DefenseMiddleware)

    threading.Thread(
        target=lambda: uvicorn.run(app, host=config.host, port=config.port, log_level="info"),
        name="uvicorn",
        daemon=True
    ).start()


def set_users(user_list: list[dict]) -> None:
    """
    Populate the server database with the given user accounts.
    
    Clears the existing user database and creates new user records from the provided
    list. Each user account is configured with authentication credentials, password
    strength classification, and TOTP secrets for multifactor authentication.
    
    Passwords are hashed using the currently configured hashing algorithm, while
    preserving plaintext passwords for potential hasher migrations during the experiment.
    
    Args:
        user_list: List of user dictionaries, each containing:
            - 'username': Unique identifier for the user
            - 'password': Plaintext password
            - 'strength_class': Password strength category ('weak', 'medium', 'strong')
            - 'totp_secret': Base32-encoded TOTP secret for MFA
            
    Raises:
        RuntimeError: If the database is not initialized. Call start() first.
        
    Note:
        This function replaces all existing users in the database.
    """
    db = get_db()
    if db is None:
        raise RuntimeError("Database not initialized. Please call server.start() before calling set_users().")
    db.clear()
    for entry in user_list:
        username = entry['username']
        password = entry['password']
        hashed_password = hasher.get_hasher().hash_password(password)
        password_strength_class = entry['strength_class']
        totp_secret = entry['totp_secret']

        user = User(
            username=username,
            hashed_password=hashed_password,
            password_strength=password_strength_class,
            totp_secret=totp_secret,
            internal_plain_password=password
        )
        db.save_user(user)


def set_hasher(hasher_config: HasherConfig) -> None:
    """
    Dynamically configure the cryptographic hashing algorithm for password storage.
    
    Updates the server's password hashing mechanism and migrates all existing user
    passwords to the new algorithm. This enables seamless transitions between hashing
    strategies.
    
    Supported algorithms: plaintext (for control cases), BCrypt (legacy comparison),
    and Argon2ID (modern standard), with optional pepper enhancement.
    
    Args:
        hasher_config: Configuration object specifying the hashing algorithm type
                      and optional parameters such as server-side pepper values.
                      
    Raises:
        RuntimeError: If the database is not initialized. Call start() first.
        KeyError: If the specified hasher type is not supported.
    """
    hasher_map: dict[HasherType, type[Hasher]] = {
        HasherType.PlainText: PlainTextHasher,
        HasherType.BCrypt: BCryptHasher,
        HasherType.Argon2ID: Argon2IDHasher
    }
    hasher.set_hasher(hasher_map[hasher_config.hasher_type](hasher_config))
    # Migrate all users to the new hash algorithm
    db = get_db()
    if db is None:
        raise RuntimeError("Database not initialized. Please call server.start() before calling set_hasher().")
    for user in db.users.values():
        new_user = User(
            username=user.username,
            hashed_password=hasher.get_hasher().hash_password(user.internal_plain_password),
            password_strength=user.password_strength,
            totp_secret=user.totp_secret,
            internal_plain_password=user.internal_plain_password
        )
        db.save_user(new_user)


_defenses_config_cache: Iterable[DefenseConfig] = []


def set_defenses(*args: DefenseConfig) -> None:
    """
    Configure active defense mechanisms for the authentication server.
    
    Dynamically enables and configures security defenses based on the provided
    configuration objects. Multiple defense mechanisms can be activated simultaneously
    to test layered security approaches and identify potential conflicts or
    synergistic effects between different protection strategies.
    
    Available defenses: multi-factor authentication (MFA), IP-based rate limiting,
    account lockout mechanisms, and CAPTCHA.
    
    Args:
        *args: Variable number of defense configuration objects. Supported types:
            - MFADefenseConfig: Enables TOTP-based multifactor authentication
            - RateLimitDefenseConfig: Configures IP-based request throttling  
            - AccountLockoutDefenseConfig: Sets account lockout policies
            - CaptchaDefenseConfig: Enables CAPTCHA challenges after failed attempts
            
    Note:
        Calling this method overrides any existing defenses. Passing no arguments
        disables all defenses. Defense activation is immediate and affects all
        subsequent authentication requests without requiring server restart.
        
    Example:
        # Enable MFA with rate limiting
        set_defenses(
            MFADefenseConfig(),
            RateLimitDefenseConfig(rate=5, capacity=10)
        )
        
        # Disable all defenses for baseline cases
        set_defenses()
    """
    defenses_map: dict[type[DefenseConfig], type] = {
        MFADefenseConfig: MFADefense,
        RateLimitDefenseConfig: RateLimitDefense,
        AccountLockoutDefenseConfig: AccountLockoutDefense,
        CaptchaDefenseConfig: CaptchaDefense
    }
    global _defenses_config_cache
    _defenses_config_cache = args
    api.set_defenses([defenses_map[type(config)](**config.as_dict()) for config in args])


def reset_defenses() -> None:
    """
    Resets the defenses to the previously cached configuration. Equivalent to repeating
    the last call to `set_defenses` with the same arguments.

    Note:
        Calling this method before `set_defenses` is equivalent to calling it with no
        arguments.
    """
    set_defenses(*_defenses_config_cache)
