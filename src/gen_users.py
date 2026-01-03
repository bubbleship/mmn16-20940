import csv
import secrets
import string
from pathlib import Path

import pyotp

from src.config.config import PasswordConfig


def generate_password(strength, config: PasswordConfig):
    if strength == "weak":
        alphabet = config.weak_alphabet
        length = config.weak_length
    elif strength == "medium":
        alphabet = config.medium_alphabet
        length = config.medium_length
    else:  # strong
        alphabet = config.strong_alphabet
        length = config.strong_length
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_users(count: int, config: PasswordConfig) -> list[dict]:
    users = []
    levels = ["weak", "medium", "strong"]

    for i in range(1, count + 1):
        strength = levels[(i - 1) % 3]
        users.append({
            "username": f"user_{i}",
            "password": generate_password(strength, config),
            "totp_secret": pyotp.random_base32(),
            "strength_class": strength
        })

    return users


def save_users(users: list[dict], dir_path: str = "."):
    path = Path(dir_path) / "users.csv"
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["username", "password", "totp_secret", "strength_class"])
        writer.writeheader()
        writer.writerows(users)


def main():
    # Generate 50 mock users
    config = PasswordConfig(
        weak_alphabet=string.ascii_lowercase,
        weak_length=6,
        medium_alphabet=string.ascii_lowercase + string.digits,
        medium_length=8,
        strong_alphabet=string.ascii_letters + string.digits + string.punctuation,
        strong_length=12
    )

    users = generate_users(50, config)
    save_users(users)
    print(f"Generated 'users.csv' with 50 users.")


if __name__ == "__main__":
    main()
