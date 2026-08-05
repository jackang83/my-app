import os
from typing import Optional, Tuple

from flask import Flask, g, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from src.auth import MIN_JWT_SECRET_KEY_LENGTH, MIN_PASSWORD_LENGTH, generate_token, token_required
from src.users import users


def _resolve_jwt_secret_key() -> str:
    secret = os.environ.get("JWT_SECRET_KEY")
    if secret:
        if len(secret.encode("utf-8")) < MIN_JWT_SECRET_KEY_LENGTH:
            raise RuntimeError(
                f"JWT_SECRET_KEY must be at least {MIN_JWT_SECRET_KEY_LENGTH} bytes long "
                "(RFC 7518 minimum for HS256). See docs/authentication.md."
            )
        return secret
    if os.environ.get("FLASK_ENV") == "development" or os.environ.get("FLASK_DEBUG") == "1":
        # Dev convenience only: tokens won't survive a restart or be valid
        # across multiple worker processes. Never rely on this in production.
        return os.urandom(32).hex()
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable must be set. "
        "See docs/authentication.md."
    )


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = _resolve_jwt_secret_key()
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KiB is ample for auth payloads

limiter = Limiter(get_remote_address, app=app, default_limits=[])


def _extract_credentials(data: dict) -> Optional[Tuple[str, str]]:
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    if not username or not password:
        return None
    return username, password


@app.route("/")
def index():
    return {"message": "Hello, Flask!"}


@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json(silent=True) or {}
    credentials = _extract_credentials(data)
    if credentials is None:
        return jsonify({"error": "username and password are required"}), 400
    username, password = credentials

    if len(password) < MIN_PASSWORD_LENGTH:
        return (
            jsonify({"error": f"password must be at least {MIN_PASSWORD_LENGTH} characters"}),
            400,
        )

    try:
        users.create(username, password)
    except ValueError:
        return jsonify({"error": "User already exists"}), 409

    return jsonify({"message": "User registered"}), 201


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    credentials = _extract_credentials(data)
    if credentials is None:
        return jsonify({"error": "username and password are required"}), 400
    username, password = credentials

    user = users.authenticate(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user.username)
    return jsonify({"access_token": token, "token_type": "bearer"}), 200


@app.route("/protected")
@token_required
def protected():
    return jsonify({"message": f"Hello, {g.user_id}!"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
