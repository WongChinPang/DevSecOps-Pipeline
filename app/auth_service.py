import sqlite3
import hashlib
import secrets
import os
import time
from datetime import datetime, timezone

import jwt

DB_PATH = os.environ.get("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "users.db"))
import hashlib as _hashlib

_MASTER = os.environ.get("JWT_MASTER_SECRET", "devsecops-jwt-master-key-2026")
JWT_SECRET = _hashlib.sha256(_MASTER.encode()).hexdigest()
del _hashlib, _MASTER
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 86400  # 24 hours


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    seed_default_user(conn)
    conn.close()


def seed_default_user(conn: sqlite3.Connection | None = None) -> None:
    should_close = conn is None
    if conn is None:
        conn = _get_db()

    existing = conn.execute("SELECT id FROM users WHERE username = ?", ("alan",)).fetchone()
    if not existing:
        pw_hash = hash_password("123456789")
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            ("alan", pw_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    if should_close:
        conn.close()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    return salt + ":" + hashlib.sha256((salt + password).encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    salt, expected = stored_hash.split(":", 1)
    actual = hashlib.sha256((salt + password).encode()).hexdigest()
    return secrets.compare_digest(actual, expected)


def authenticate(username: str, password: str) -> str | None:
    conn = _get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if not row:
        return None

    if not verify_password(password, row["password_hash"]):
        return None

    now = int(time.time())
    payload = {
        "sub": row["username"],
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def validate_token(token: str) -> bool:
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
