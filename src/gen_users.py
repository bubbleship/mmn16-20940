import csv
import random
import secrets

import pyotp

# Research-based categories for the dictionary
dictionary_data = {
    "sports": ["football", "soccer", "chelsea", "liverpool", "basketball", "baseball", "jordan"],
    "nature_positivity": ["sunshine", "freedom", "summer", "winter", "spring", "dragon", "monkey"],
    "common_names": ["michael", "daniel", "jessica", "charlie", "ashley", "michelle"],
    "cities_places": ["rome", "lima", "austin", "london", "tokyo", "york", "antonio"],
    "food_drink": ["chocolate", "coffee", "pizza", "cookie", "honey", "whiskey", "ice"],
    "culture_fiction": ["superman", "pokemon", "starwars", "naruto", "matrix", "batman"],
    "system_defaults": ["admin", "password", "secret", "welcome", "guest", "root"]
}
all_words = [word for cat in dictionary_data.values() for word in cat]


def save_words():
    # Flatten and create words.txt
    with open("words.txt", "w") as f:
        f.write("\n".join(all_words))


def generate_password(word, strength):
    if strength == "weak":
        # Pattern: Word + single digit or simple sequence
        return f"{word}{random.choice(['1', '123', '2024', '2025'])}"
    elif strength == "medium":
        # Pattern: Capitalized + 2 digits + symbol (the "Corporate Standard")
        return f"{word.capitalize()}{random.randint(10, 99)}!"
    else:  # strong
        # Pattern: High entropy random string (simulating Password Manager use)
        return secrets.token_urlsafe(12)


def main():
    save_words()
    # Generate 50 mock users
    users = []
    levels = ["weak", "medium", "strong"]

    for i in range(1, 51):
        strength = levels[(i - 1) % 3]
        word = random.choice(all_words)
        users.append({
            "username": f"user_{i}",
            "password": generate_password(word, strength),
            "totp_secret": pyotp.random_base32(),
            "strength_class": strength
        })

    with open("users.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["username", "password", "totp_secret", "strength_class"])
        writer.writeheader()
        writer.writerows(users)

    print(f"Generated 'words.txt' with {len(all_words)} words and 'users.csv' with 50 users.")


if __name__ == "__main__":
    main()
