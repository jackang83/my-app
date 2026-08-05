# Architecture: Authentication

Summary of how the JWT authentication feature is put together. For the
request/response contract of each endpoint, see [authentication.md](authentication.md).

## Components

```
app.py            Flask app, routes, request parsing, rate limiting, secret-key
                   resolution at startup
src/auth.py        Password hashing, JWT encode/decode, the token_required
                   decorator — no Flask routing, no user storage
src/users.py       In-memory user store (UserStore) — no Flask, no JWT
```

The split is by responsibility, not by layer thickness: `app.py` owns HTTP
concerns (parsing, status codes, rate limits), `src/auth.py` owns
cryptographic concerns (hashing, signing, verifying), and `src/users.py`
owns identity storage. Each module is importable and testable without
the other two — `src/auth.py` and `src/users.py` have no dependency on
`app.py`, which is why they're covered by isolated unit tests
(`tests/test_auth.py`, `tests/test_users.py`) rather than only through
the Flask test client.

## Request flow

**Register** (`POST /register`)

```
request → _extract_credentials() → length check → UserStore.create()
              │                                         │
              400 if missing/wrong-type              409 if username taken
                                                          │
                                                     hash_password()
                                                          │
                                                    stored in memory
```

**Login** (`POST /login`)

```
request → _extract_credentials() → UserStore.authenticate() → generate_token()
              │                          │                          │
          400 if missing/wrong-type   401 if no match          signs a JWT
                                                                (HS256, 60 min exp)
```

**Access a protected route** (`GET /protected`, or any route wrapped in
`@token_required`)

```
request → token_required reads Authorization header → decode_token()
              │                                             │
     401 if missing/malformed                    401 if invalid/expired
                                                             │
                                                   g.user_id = payload["sub"]
                                                             │
                                                        view runs
```

Authentication is stateless after login: the server verifies the JWT's
signature and expiration on every request and never looks anything up in
`UserStore` to do so. `UserStore` is only consulted during `/register` and
`/login`; it is not in the critical path of `/protected`.

## Key design decisions

- **Stateless tokens, no server-side session table.** Simpler to reason
  about and horizontally scale, at the cost of no way to revoke a token
  before it expires (mitigated by a short 60-minute TTL).
- **In-memory user store.** Appropriate for this stage of the project only;
  it resets on restart and doesn't share state across processes. Swapping
  in a real database means changing `src/users.py` — nothing in `app.py`
  or `src/auth.py` assumes an in-memory backend.
- **Auth logic is Flask-app-independent.** `src/auth.py` reads
  `current_app.config["JWT_SECRET_KEY"]` rather than a module-level
  constant, so it works against any Flask app instance — this is what
  lets the unit tests spin up a throwaway Flask app instead of importing
  the real one.
- **Timing-safe lookup.** `UserStore.authenticate()` always runs a password
  hash comparison, even for a username that doesn't exist (against a fixed
  dummy hash), so response time doesn't reveal whether a username is
  registered.
- **Fail fast on weak configuration.** The app refuses to start without a
  `JWT_SECRET_KEY` of at least 32 bytes, unless explicitly running in a
  dev mode (`FLASK_ENV=development` / `FLASK_DEBUG=1`), rather than
  falling back to something insecure silently.

## Known limitations / not yet built

- No token revocation, refresh tokens, or logout — a leaked token is valid
  until it expires.
- No password reset or account-recovery flow.
- Rate limiting (`Flask-Limiter`) is keyed on the raw socket IP address; it
  will misbehave behind a reverse proxy unless reconfigured to trust a
  specific forwarding hop.
- Both the user store and the rate limiter use in-memory storage, so
  neither is consistent across multiple worker processes. See the "Notes"
  section of [authentication.md](authentication.md) for the operational
  detail.

## Where to look for more

- Endpoint contracts, status codes, request/response bodies:
  [authentication.md](authentication.md)
- Cryptographic and token logic: `src/auth.py`
- User storage: `src/users.py`
- Route wiring and startup configuration: `app.py`
