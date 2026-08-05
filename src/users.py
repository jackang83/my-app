"""Minimal in-memory user store used by the authentication endpoints."""

from dataclasses import dataclass
from threading import Lock
from typing import Optional

from src.auth import hash_password, verify_password


@dataclass
class User:
    username: str
    password_hash: str


# Used to give the "unknown username" path a hash to check against, so it
# costs roughly the same as the "wrong password" path and doesn't leak valid
# usernames via response timing.
_DUMMY_PASSWORD_HASH = hash_password("dummy-password-for-constant-time-check")


class UserStore:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._lock = Lock()

    def create(self, username: str, password: str) -> User:
        with self._lock:
            if username in self._users:
                raise ValueError("User already exists")
            user = User(username=username, password_hash=hash_password(password))
            self._users[username] = user
            return user

    def find(self, username: str) -> Optional[User]:
        return self._users.get(username)

    def authenticate(self, username: str, password: str) -> Optional[User]:
        user = self.find(username)
        password_hash = user.password_hash if user else _DUMMY_PASSWORD_HASH
        password_ok = verify_password(password, password_hash)
        if user and password_ok:
            return user
        return None

    def clear(self) -> None:
        with self._lock:
            self._users.clear()


users = UserStore()
