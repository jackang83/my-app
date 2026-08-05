"""Password hashing and JWT helpers for the authentication endpoints."""

from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Callable

import jwt
from flask import current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_TTL_MINUTES = 60
MIN_PASSWORD_LENGTH = 8
MIN_JWT_SECRET_KEY_LENGTH = 32  # bytes; RFC 7518 minimum recommended for HS256


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


def _secret_key() -> str:
    secret = current_app.config.get("JWT_SECRET_KEY")
    if not secret:
        raise RuntimeError("JWT_SECRET_KEY is not configured")
    return secret


def generate_token(user_id: str, ttl_minutes: int = DEFAULT_TOKEN_TTL_MINUTES) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(payload, _secret_key(), algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, _secret_key(), algorithms=[JWT_ALGORITHM])


def token_required(view: Callable) -> Callable:
    """Decorator that rejects requests without a valid, unexpired Bearer token."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.removeprefix("Bearer ")
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        g.user_id = payload["sub"]
        return view(*args, **kwargs)

    return wrapper
