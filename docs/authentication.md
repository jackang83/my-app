# Authentication

The API uses JWT (JSON Web Token) bearer authentication.

## Configuration

Set `JWT_SECRET_KEY` in the environment before starting the app:

```bash
export JWT_SECRET_KEY="a long, random, secret value"
```

The app refuses to start without it, **unless** `FLASK_ENV=development` or
`FLASK_DEBUG=1` is set, in which case it falls back to a random per-process
key purely for local convenience. Don't rely on that fallback beyond a quick
local check — the key is different every restart and every worker process,
so tokens won't validate across either.

The key must also be at least 32 bytes (RFC 7518's recommended minimum for
HS256); a shorter value is rejected at startup with a `RuntimeError` rather
than silently producing a weakly-signed token.

## Endpoints

### `POST /register`

Creates a user. Passwords are hashed with Werkzeug's salted PBKDF2 hasher
(`werkzeug.security.generate_password_hash`) before storage — plaintext
passwords are never persisted. Password must be at least 8 characters.
Limited to 5 requests per minute per IP.

Request body:

```json
{ "username": "alice", "password": "s3cret-pw" }
```

Responses:

* `201` — user created.
* `400` — `username`/`password` missing, not strings, or password shorter than 8 characters.
* `409` — username already exists.
* `429` — rate limit exceeded.

### `POST /login`

Authenticates a user and returns a signed JWT. Limited to 5 requests per
minute per IP.

Request body:

```json
{ "username": "alice", "password": "s3cret-pw" }
```

Responses:

* `200` — returns `{"access_token": "<jwt>", "token_type": "bearer"}`.
* `400` — `username`/`password` missing or not strings.
* `401` — invalid username or password.
* `429` — rate limit exceeded.

The error message is the same generic `"Invalid credentials"` whether the
username or the password was wrong, and the comparison against a nonexistent
user still runs a password hash check (against a fixed dummy hash) so the
response time doesn't leak which one it was.

The token is signed with HS256 and expires 60 minutes after issuance (`exp`
claim). Expiration is enforced on every request to a protected route.

### `GET /protected`

Example of a route guarded by the `token_required` decorator
(`src/auth.py`). Send the token from `/login` as a bearer token:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:5000/protected
```

Responses:

* `200` — valid, unexpired token.
* `401` — missing, invalid, or expired token.

## Notes

* User storage (`src/users.py`) is an in-memory store for this stage of the
  project — it resets on every restart and isn't shared across processes.
  Swap it for a real database-backed store before running multiple workers
  or persisting users across deploys.
* Rate limiting (`Flask-Limiter`) also defaults to in-memory storage, so
  limits are tracked per worker process, not globally. Fine for a single
  process; point it at Redis (or similar) via `storage_uri` before running
  multiple workers, or the effective limit multiplies by worker count.
