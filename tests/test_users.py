"""Unit tests for src/users.py, independent of Flask."""

from unittest.mock import patch

import pytest

import src.users as users_module
from src.users import UserStore


@pytest.fixture
def store():
    return UserStore()


def test_create_stores_a_hashed_password_not_plaintext(store):
    user = store.create("alice", "s3cret-pw")
    assert user.username == "alice"
    assert user.password_hash != "s3cret-pw"


def test_create_raises_on_duplicate_username(store):
    store.create("alice", "s3cret-pw")
    with pytest.raises(ValueError):
        store.create("alice", "another-pw")


def test_find_returns_none_for_unknown_user(store):
    assert store.find("ghost") is None


def test_find_returns_the_created_user(store):
    created = store.create("alice", "s3cret-pw")
    assert store.find("alice") is created


def test_authenticate_returns_user_for_correct_credentials(store):
    store.create("alice", "s3cret-pw")
    assert store.authenticate("alice", "s3cret-pw").username == "alice"


def test_authenticate_returns_none_for_wrong_password(store):
    store.create("alice", "s3cret-pw")
    assert store.authenticate("alice", "wrong-pw") is None


def test_authenticate_returns_none_for_unknown_user(store):
    assert store.authenticate("ghost", "whatever-pw") is None


def test_authenticate_checks_a_password_hash_even_for_unknown_users(store):
    """Regression test for the timing side-channel: authenticate() must not
    short-circuit before hashing when the username doesn't exist, or an
    attacker can distinguish 'no such user' from 'wrong password' by
    response time."""
    with patch("src.users.verify_password", wraps=users_module.verify_password) as spy:
        store.authenticate("ghost", "whatever-pw")
    spy.assert_called_once()


def test_clear_removes_all_users(store):
    store.create("alice", "s3cret-pw")
    store.clear()
    assert store.find("alice") is None


def test_store_instances_do_not_share_state():
    store_a = UserStore()
    store_b = UserStore()
    store_a.create("alice", "s3cret-pw")
    assert store_b.find("alice") is None
