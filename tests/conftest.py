import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-0123456789abcdef")

import pytest

from app import app as flask_app, limiter
from src.users import users


@pytest.fixture
def client():
    flask_app.config.update(TESTING=True, JWT_SECRET_KEY="test-secret-key-0123456789abcdef")
    users.clear()
    limiter.reset()
    with flask_app.test_client() as test_client:
        yield test_client
    users.clear()
    limiter.reset()
