"""Unit tests for src/auth.py, isolated from the Flask app in app.py."""

import jwt
import pytest
from flask import Flask, g

from src.auth import (
    DEFAULT_TOKEN_TTL_MINUTES,
    JWT_ALGORITHM,
    decode_token,
    generate_token,
    hash_password,
    token_required,
    verify_password,
)


@pytest.fixture
def app():
    """A minimal Flask app, independent of app.py, just to give auth.py the
    application context and request context it needs."""
    flask_app = Flask(__name__)
    flask_app.config["JWT_SECRET_KEY"] = "unit-test-secret"

    @flask_app.route("/whoami")
    @token_required
    def whoami():
        return {"user_id": g.user_id}

    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


# -- password hashing ---------------------------------------------------


def test_hash_password_does_not_store_plaintext():
    hashed = hash_password("s3cret-pw")
    assert hashed != "s3cret-pw"


def test_hash_password_salts_each_call_differently():
    assert hash_password("s3cret-pw") != hash_password("s3cret-pw")


def test_verify_password_accepts_correct_password():
    hashed = hash_password("s3cret-pw")
    assert verify_password("s3cret-pw", hashed) is True


def test_verify_password_rejects_incorrect_password():
    hashed = hash_password("s3cret-pw")
    assert verify_password("wrong-pw", hashed) is False


# -- token generation/decoding -------------------------------------------


def test_generate_token_returns_a_string(app):
    with app.app_context():
        token = generate_token("alice")
    assert isinstance(token, str)


def test_generate_token_defaults_to_configured_ttl(app):
    with app.app_context():
        token = generate_token("alice")
        payload = decode_token(token)
    expected_ttl_seconds = DEFAULT_TOKEN_TTL_MINUTES * 60
    assert payload["exp"] - payload["iat"] == pytest.approx(expected_ttl_seconds, abs=1)


def test_decode_token_round_trips_the_subject(app):
    with app.app_context():
        token = generate_token("alice")
        payload = decode_token(token)
    assert payload["sub"] == "alice"


def test_decode_token_raises_when_expired(app):
    with app.app_context():
        token = generate_token("alice", ttl_minutes=-1)
        with pytest.raises(jwt.ExpiredSignatureError):
            decode_token(token)


def test_decode_token_raises_on_tampered_payload(app):
    with app.app_context():
        token = generate_token("alice")
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}x.{signature}"
    with app.app_context(), pytest.raises(jwt.InvalidTokenError):
        decode_token(tampered)


def test_decode_token_raises_when_signed_with_different_secret(app):
    other_app = Flask(__name__)
    other_app.config["JWT_SECRET_KEY"] = "a-different-secret"
    with other_app.app_context():
        token = generate_token("alice")
    with app.app_context(), pytest.raises(jwt.InvalidTokenError):
        decode_token(token)


def test_generate_token_uses_hs256(app):
    with app.app_context():
        token = generate_token("alice")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == JWT_ALGORITHM


# -- token_required decorator --------------------------------------------


def test_token_required_rejects_missing_authorization_header(client):
    response = client.get("/whoami")
    assert response.status_code == 401


def test_token_required_rejects_header_without_bearer_prefix(client, app):
    with app.app_context():
        token = generate_token("alice")
    response = client.get("/whoami", headers={"Authorization": token})
    assert response.status_code == 401


def test_token_required_rejects_expired_token(client, app):
    with app.app_context():
        token = generate_token("alice", ttl_minutes=-1)
    response = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_token_required_rejects_malformed_token(client):
    response = client.get("/whoami", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


def test_token_required_sets_g_user_id_and_calls_view(client, app):
    with app.app_context():
        token = generate_token("alice")
    response = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.get_json() == {"user_id": "alice"}
