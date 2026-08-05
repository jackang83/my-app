"""Integration tests for the Flask routes in app.py."""

import pytest

from app import _extract_credentials, _resolve_jwt_secret_key
from app import app as flask_app
from src.auth import generate_token


def register(client, username="alice", password="s3cret-pw"):
    return client.post("/register", json={"username": username, "password": password})


def login(client, username="alice", password="s3cret-pw"):
    return client.post("/login", json={"username": username, "password": password})


def test_index_returns_hello_message(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.get_json() == {"message": "Hello, Flask!"}


# -- /register -----------------------------------------------------------


def test_register_creates_user(client):
    response = register(client)
    assert response.status_code == 201


def test_register_rejects_duplicate_username(client):
    register(client)
    response = register(client)
    assert response.status_code == 409


def test_register_requires_username_and_password(client):
    response = client.post("/register", json={"username": "alice"})
    assert response.status_code == 400


def test_register_rejects_non_string_username(client):
    response = client.post("/register", json={"username": ["alice"], "password": "s3cret-pw"})
    assert response.status_code == 400


def test_register_rejects_non_string_password(client):
    response = client.post("/register", json={"username": "alice", "password": 12345678})
    assert response.status_code == 400


def test_register_rejects_short_password(client):
    response = client.post("/register", json={"username": "alice", "password": "short"})
    assert response.status_code == 400


def test_register_rejects_body_over_max_content_length(client):
    oversized_password = "a" * (flask_app.config["MAX_CONTENT_LENGTH"] + 1)
    response = client.post("/register", json={"username": "alice", "password": oversized_password})
    assert response.status_code == 413


# -- /login ----------------------------------------------------------------


def test_login_returns_token_for_valid_credentials(client):
    register(client)
    response = login(client)
    assert response.status_code == 200
    assert "access_token" in response.get_json()


def test_login_rejects_invalid_password(client):
    register(client)
    response = login(client, password="wrong-pw")
    assert response.status_code == 401


def test_login_rejects_unknown_user(client):
    response = login(client, username="ghost")
    assert response.status_code == 401


def test_login_rejects_non_string_credentials(client):
    response = client.post("/login", json={"username": "alice", "password": ["not-a-string"]})
    assert response.status_code == 400


def test_login_rate_limited_after_repeated_attempts(client):
    for _ in range(5):
        response = login(client, password="wrong-pw")
        assert response.status_code == 401

    response = login(client, password="wrong-pw")
    assert response.status_code == 429


# -- /protected --------------------------------------------------------------


def test_protected_route_requires_token(client):
    response = client.get("/protected")
    assert response.status_code == 401


def test_protected_route_accepts_valid_token(client):
    register(client)
    token = login(client).get_json()["access_token"]
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert "alice" in response.get_json()["message"]


def test_protected_route_rejects_expired_token(client):
    with flask_app.app_context():
        token = generate_token("alice", ttl_minutes=-1)
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_protected_route_rejects_garbage_token(client):
    response = client.get("/protected", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


# -- _extract_credentials helper ---------------------------------------------


def test_extract_credentials_returns_username_and_password():
    assert _extract_credentials({"username": "alice", "password": "s3cret-pw"}) == (
        "alice",
        "s3cret-pw",
    )


def test_extract_credentials_returns_none_when_password_missing():
    assert _extract_credentials({"username": "alice"}) is None


def test_extract_credentials_returns_none_for_non_string_values():
    assert _extract_credentials({"username": 123, "password": "s3cret-pw"}) is None


def test_extract_credentials_returns_none_for_empty_strings():
    assert _extract_credentials({"username": "", "password": "s3cret-pw"}) is None


# -- _resolve_jwt_secret_key helper -------------------------------------------


def test_resolve_jwt_secret_key_uses_env_value(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "explicit-secret-that-is-long-enough-1234")
    assert _resolve_jwt_secret_key() == "explicit-secret-that-is-long-enough-1234"


def test_resolve_jwt_secret_key_falls_back_in_dev_mode(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.setenv("FLASK_ENV", "development")
    key = _resolve_jwt_secret_key()
    assert isinstance(key, str) and len(key) == 64


def test_resolve_jwt_secret_key_raises_without_env_or_dev_flag(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("FLASK_ENV", raising=False)
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    with pytest.raises(RuntimeError):
        _resolve_jwt_secret_key()


def test_resolve_jwt_secret_key_rejects_short_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "too-short")
    with pytest.raises(RuntimeError):
        _resolve_jwt_secret_key()
