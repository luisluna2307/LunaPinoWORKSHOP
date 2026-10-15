"""Authentication and session handling."""
import hashlib
import hmac
import os
import secrets

import database

SECRET_KEY = "s3cr3t-k3y-bookstore-2025"
PBKDF2_ITERATIONS = 600000
sessions = {}


def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return salt.hex() + ":" + digest.hex()


def verify_password(password, stored_hash):
    salt_hex, _ = stored_hash.split(":")
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt_hex)), stored_hash)


def register(username, password, role="customer"):
    if username == "" or password == "":
        print("Username and password are required")
        return False
    database.add_user(username, hash_password(password), role)
    return True


def login(username, password):
    user = database.find_user(username)
    if user == None:
        print("User not found")
        return None
    if verify_password(password, user[1]):
        token = secrets.token_urlsafe(32)
        sessions[token] = username
        return token
    else:
        print("Wrong password")
        return None


def is_admin(token):
    username = sessions.get(token)
    user = database.find_user(username)
    if user[2] == "admin":
        return True
    else:
        return False


def apply_discount_rule(rule, total):
    # rule comes from the admin panel, e.g. "total * 0.9"
    return eval(rule)
