
import secrets
import string

def generate_password(length=16, use_symbols=True, use_numbers=True, use_upper=True, use_lower=True):
    """
    Generate a cryptographically strong random password.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4")

    chars = ""
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_numbers:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation

    if not chars:
        raise ValueError("At least one character type must be selected")

    # Ensure at least one character from each selected category
    password = []
    if use_lower:
        password.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_numbers:
        password.append(secrets.choice(string.digits))
    if use_symbols:
        password.append(secrets.choice(string.punctuation))

    # Fill the rest
    remaining_length = length - len(password)
    for _ in range(remaining_length):
        password.append(secrets.choice(chars))

    # Shuffle the result
    secrets.SystemRandom().shuffle(password)

    return "".join(password)

if __name__ == "__main__":
    print("Generated Password:", generate_password())
