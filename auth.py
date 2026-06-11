"""Lightweight authentication + role-based access control.

Users are stored in users.json with salted password hashes (werkzeug). Each user
has a set of privileges; an admin can create/edit/delete users. Sessions use
Flask's signed cookie. This is intended for a self-hosted internal tool — do not
expose it to the public internet without TLS and a hardened deployment.
"""
from __future__ import annotations

import functools
import json
import logging
import os
import re
import secrets

from flask import abort, jsonify, redirect, request, session
from werkzeug.security import check_password_hash, generate_password_hash

log = logging.getLogger("auth")

USERS_FILE = os.getenv("USERS_FILE", "users.json")
SECRET_FILE = os.getenv("FLASK_SECRET_FILE", ".flask_secret")

# (key, human label) — admin implies all of these.
PRIVILEGES = [
    ("generate", "Generate briefings"),
    ("analyze", "Analyze files"),
    ("scan", "Scan networks"),
    ("schedule", "Manage email schedule"),
    ("delete", "Delete history"),
    ("admin", "Administer users"),
]
PRIV_KEYS = [p[0] for p in PRIVILEGES]


# ── secret key ───────────────────────────────────────────────────────────────
def get_secret_key() -> str:
    env = os.getenv("FLASK_SECRET_KEY")
    if env:
        return env
    try:
        with open(SECRET_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except FileNotFoundError:
        key = secrets.token_hex(32)
        try:
            with open(SECRET_FILE, "w", encoding="utf-8") as fh:
                fh.write(key)
        except OSError:
            pass
        return key


# ── user store ───────────────────────────────────────────────────────────────
def _load() -> dict:
    try:
        with open(USERS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(users: dict) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2)


def ensure_admin() -> None:
    """Seed an initial admin account on first run."""
    users = _load()
    if users:
        return
    username = os.getenv("ADMIN_USER", "admin")
    password = os.getenv("ADMIN_PASSWORD", "admin")
    users[username] = {
        "password_hash": generate_password_hash(password),
        "privileges": ["admin"],
    }
    _save(users)
    log.warning("Created initial admin user '%s'. CHANGE THE PASSWORD after first login.", username)


PASSWORD_RULE = ("At least 8 characters with uppercase, lowercase, a number, "
                 "and a special character.")


def validate_password(pw: str) -> tuple[bool, str]:
    pw = pw or ""
    if len(pw) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", pw):
        return False, "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", pw):
        return False, "Password must contain a lowercase letter."
    if not re.search(r"\d", pw):
        return False, "Password must contain a number."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return False, "Password must contain a special character."
    return True, ""


def list_users() -> list[dict]:
    users = _load()
    return [{"username": u, "privileges": d.get("privileges", [])}
            for u, d in sorted(users.items())]


def create_user(username: str, password: str, privileges: list[str]) -> tuple[bool, str]:
    username = (username or "").strip()
    if not username or not password:
        return False, "Username and password are required."
    ok, msg = validate_password(password)
    if not ok:
        return False, msg
    users = _load()
    if username in users:
        return False, "That username already exists."
    privs = [p for p in privileges if p in PRIV_KEYS]
    users[username] = {"password_hash": generate_password_hash(password), "privileges": privs}
    _save(users)
    return True, "User created."


def update_privileges(username: str, privileges: list[str]) -> tuple[bool, str]:
    users = _load()
    if username not in users:
        return False, "No such user."
    privs = [p for p in privileges if p in PRIV_KEYS]
    # Don't allow removing the last admin.
    if "admin" not in privs and _is_last_admin(users, username):
        return False, "Cannot remove admin from the last administrator."
    users[username]["privileges"] = privs
    _save(users)
    return True, "Privileges updated."


def set_password(username: str, password: str) -> tuple[bool, str]:
    ok, msg = validate_password(password)
    if not ok:
        return False, msg
    users = _load()
    if username not in users:
        return False, "No such user."
    users[username]["password_hash"] = generate_password_hash(password)
    _save(users)
    return True, "Password updated."


def delete_user(username: str) -> tuple[bool, str]:
    users = _load()
    if username not in users:
        return False, "No such user."
    if _is_last_admin(users, username):
        return False, "Cannot delete the last administrator."
    del users[username]
    _save(users)
    return True, "User deleted."


def _is_last_admin(users: dict, username: str) -> bool:
    admins = [u for u, d in users.items() if "admin" in d.get("privileges", [])]
    return admins == [username]


def verify(username: str, password: str) -> bool:
    user = _load().get(username)
    return bool(user and check_password_hash(user.get("password_hash", ""), password))


# ── session helpers ──────────────────────────────────────────────────────────
def current_user() -> dict | None:
    username = session.get("user")
    if not username:
        return None
    data = _load().get(username)
    if not data:
        return None
    return {"username": username, "privileges": data.get("privileges", [])}


def has_perm(user: dict | None, perm: str) -> bool:
    if not user:
        return False
    privs = user.get("privileges", [])
    return "admin" in privs or perm in privs


def _deny():
    # API/non-GET callers get JSON 401/403; browsers get redirected to login.
    if request.method != "GET":
        abort(401)
    return redirect("/login?next=" + request.path)


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return _deny()
        return fn(*args, **kwargs)
    return wrapper


def require_perm(perm: str):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return _deny()
            if not has_perm(user, perm):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator
