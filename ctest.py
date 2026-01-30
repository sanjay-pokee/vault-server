import os
import json
import requests
from argon2.low_level import hash_secret_raw, Type
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)
from nacl.utils import random as nacl_random

BASE_URL = "https://diaphragmatically-scimitared-oda.ngrok-free.dev"

def derive_auth_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=128 * 1024,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )

def derive_vault_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=256 * 1024,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )

def encrypt_vault(vault: dict, password: str) -> dict:
    vault_salt = os.urandom(16)
    key = derive_vault_key(password, vault_salt)

    nonce = nacl_random(24)  # XChaCha20 nonce size
    plaintext = json.dumps(vault).encode()

    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        aad=None,
        nonce=nonce,
        key=key,
    )

    return {
        "vault_salt": vault_salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }

def decrypt_vault(blob: dict, password: str) -> dict:
    vault_salt = bytes.fromhex(blob["vault_salt"])
    nonce = bytes.fromhex(blob["nonce"])
    ciphertext = bytes.fromhex(blob["ciphertext"])

    key = derive_vault_key(password, vault_salt)

    plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext,
        aad=None,
        nonce=nonce,
        key=key,
    )

    return json.loads(plaintext)

def register():
    username = input("New username: ").strip().lower()
    password = input("New password: ")

    r = requests.get(f"{BASE_URL}/auth_salt/{username}")
    if r.status_code == 200:
        print("Username already exists.")
        return

    salt = os.urandom(16)
    verifier = derive_auth_key(password, salt)

    r = requests.post(
        f"{BASE_URL}/register",
        json={
            "username": username,
            "salt": salt.hex(),
            "verifier": verifier.hex(),
        },
    )

    print("Registration successful." if r.status_code == 200 else "Registration failed.")

def login():
    username = input("Username: ").strip().lower()
    password = input("Password: ")

    r = requests.get(f"{BASE_URL}/auth_salt/{username}")
    if r.status_code == 404:
        print("User does not exist.")
        return None, None

    salt = bytes.fromhex(r.json()["salt"])
    verifier = derive_auth_key(password, salt)

    r = requests.post(
        f"{BASE_URL}/login",
        json={"username": username, "verifier": verifier.hex()},
    )

    if r.status_code != 200:
        print("Wrong credentials.")
        return None, None

    return r.json()["token"], password

def load_vault(token, password):
    r = requests.get(f"{BASE_URL}/vault", headers={"Authorization": token})
    if not r.json()["blob"]:
        return {"entries": []}

    return decrypt_vault(r.json()["blob"], password)

def save_vault(token, vault, password):
    encrypted = encrypt_vault(vault, password)
    requests.post(
        f"{BASE_URL}/vault",
        headers={"Authorization": token},
        json={"blob": encrypted},
    )

def vault_menu(token, password):
    vault = load_vault(token, password)

    while True:
        print("""
1. View entries
2. Add entry
3. Logout
""")
        c = input("Choice: ").strip()

        if c == "1":
            for i, e in enumerate(vault["entries"], 1):
                print(f"{i}. {e['site']} | {e['username']} | {e['password']}")

        elif c == "2":
            vault["entries"].append({
                "site": input("Site: "),
                "username": input("Username: "),
                "password": input("Password: "),
            })
            save_vault(token, vault, password)
            print("Saved.")

        elif c == "3":
            break

while True:
    print("""
1. Register
2. Login
3. Exit
""")
    c = input("Choice: ").strip()

    if c == "1":
        register()
    elif c == "2":
        token, password = login()
        if token:
            vault_menu(token, password)
    elif c == "3":
        break
