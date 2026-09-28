# RelayGuard

A Django API gateway that authenticates clients with API keys, enforces per-key rate limits in Redis, forwards requests to an allowlisted upstream over async HTTP, and records request metrics outside the request path.

## Architecture

```text
Client ──X-API-KEY──▶ RateLimitingMiddleware ──▶ ProxyGatewayView ──▶ upstream
                      │  key lookup (cached)      pooled AsyncClient    (allowlisted)
                      │  atomic window counter     streamed, size-capped
                      └─ method / body-size checks
                                                        │
                      Celery ◀── enqueue ───────────────┘
                        └─▶ RequestLog

PostgreSQL   API keys, request logs
Redis        key cache, rate-limit counters, Celery broker
```

Middleware resolves `X-API-KEY` to cached metadata, increments that key's window counter, and checks method and body size; the view then relays the upstream status, body, and safe headers. Health probes, `/schema/`, and the management API sit behind `GATEWAY_EXEMPT_PATH_PREFIXES` — no API key, never proxied — and the catch-all route matches last.

## Design notes

**Hashed API keys.** `proxy_live_` plus 32 random URL-safe bytes, stored as a SHA-256 digest beside a 20-character indexed prefix for display, so authentication is one indexed equality lookup. A slow KDF would buy nothing against a token of that entropy; the raw secret is shown once, and nothing in the database can be replayed as a credential.

**Cache keyed by the secret.** Resolved metadata is cached under the token's digest, never under its visible prefix — the list endpoint publishes that prefix, and the cached path does not re-verify the secret. Revocation and rotation evict the entry immediately and again on commit, so a revoked key fails on its next request and a mid-transaction reader cannot re-populate it.

**Atomic rate limiting.** The fixed 60-second counter runs on Redis as a single Lua `INCR` + conditional `EXPIRE`, so workers cannot interleave and a crash cannot leave a counter without a TTL. Responses carry `X-RateLimit-*`; a `429` adds `Retry-After`.

**Async request path.** The middleware is async-capable, so under ASGI the proxy view runs on the event loop and only the key lookup and counter update take a thread hop. Forwarding goes through one pooled `httpx.AsyncClient` per event loop, reusing TCP and TLS connections instead of handshaking per request.

**Upstream allowlisting.** The allowlist is checked against the resolved URL, not just `PROXY_UPSTREAM`: a path like `/../admin` would normalise away the base path an operator meant to expose, so dot segments are refused and the host and scheme are re-verified. Redirects are returned to the caller rather than followed, and exempt prefixes are excluded from the catch-all pattern, so `/auth/nonsense` is a `404` rather than an unauthenticated proxy hop.

**Header hygiene.** Hop-by-hop headers are dropped in both directions. Inbound `Host`, `Content-Length`, `X-API-KEY`, and `Cookie` never reach the upstream, and `X-Forwarded-For` / `-Proto` / `-Host` are rebuilt from the real connection rather than trusted from the client; outbound `Content-Encoding`, `Content-Length`, and `Set-Cookie` are stripped.

**Size limits.** Requests are capped at `PROXY_MAX_BODY_BYTES` twice — from `Content-Length` in the middleware, then on the bytes actually received, since a chunked request declares no length. Upstream responses are streamed and abandoned the moment they pass `PROXY_MAX_RESPONSE_BYTES`, so an oversized body is never buffered whole.

**Async logging.** Every request is logged whatever the outcome, via Celery and off the event loop, so persistence never sits between the upstream response and the client. Publishing fails fast and an unreachable broker falls back to a bounded thread pool; Beat purges logs past `REQUEST_LOG_RETENTION_DAYS` at 03:00, in batches.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env                                # then set DJANGO_SECRET_KEY
python manage.py migrate && python manage.py createsuperuser
python manage.py runserver
```

`DJANGO_SECRET_KEY` must be at least 50 random characters unless `DJANGO_DEBUG=1`, where an ephemeral key is generated per process; a placeholder value refuses to boot. PostgreSQL is required. Redis is optional in development, where the cache falls back to a process-local backend whose counters are not shared between workers.

`docker compose up --build` brings up Django, PostgreSQL, Redis, a Celery worker, and Beat. The gateway runs under ASGI: `gunicorn config.asgi:application --worker-class uvicorn_worker.UvicornWorker`.

## API

Management endpoints use HTTP Basic or session auth, never an API key, and keys are scoped to their owner.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/auth/keys` | List the caller's keys (metadata only) |
| `POST` | `/auth/keys` | Issue a key; returns the raw secret once |
| `POST` | `/auth/keys/{id}/rotate` | Revoke and replace, preserving name and limit |
| `DELETE` | `/auth/keys/{id}` | Revoke |
| `GET` | `/health/live`, `/health/ready` | Liveness; readiness also checks DB and cache |
| `GET` | `/schema/` | OpenAPI schema for the endpoints above |
| `*` | everything else | Proxied upstream |

Issuance is bounded by `MAX_API_KEYS_PER_USER`, counted under a row lock so the cap cannot be raced past; keys expire after `API_KEY_MAX_AGE_DAYS` (`0` disables expiry). Errors are always JSON, including `404` and `500`.

```bash
# Path and query are appended to PROXY_UPSTREAM
curl -i -H 'X-API-KEY: YOUR_KEY' 'http://127.0.0.1:8000/anything?message=hello'
```

## Configuration

`.env.example` is the full reference; the variables that matter most:

| Variable | Purpose |
|---|---|
| `DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS` | Standard Django hardening |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` | PostgreSQL connection (required) |
| `REDIS_URL`, `CELERY_BROKER_URL` | Cache, rate-limit backend, and broker; empty `REDIS_URL` selects LocMem |
| `PROXY_UPSTREAM`, `PROXY_ALLOWED_HOSTS`, `PROXY_TIMEOUT_SECONDS` | Upstream target, allowlist, timeout |
| `PROXY_MAX_BODY_BYTES`, `PROXY_MAX_RESPONSE_BYTES` | Request and response ceilings |
| `API_KEY_MAX_AGE_DAYS`, `API_KEY_CACHE_SECONDS`, `MAX_API_KEYS_PER_USER` | Key expiry, cache TTL, per-user cap |
| `SECURE_SSL_REDIRECT`, `USE_X_FORWARDED_PROTO` | TLS behind a terminating proxy |

## Security and reliability

Cache or rate-limiter failures fail closed with a `503` rather than admitting unmetered traffic, and upstream errors map to `504`/`502` with detail logged rather than returned. The rate limiter runs directly behind `SecurityMiddleware`, so unauthenticated or over-quota traffic is rejected before session, CSRF, and auth do any work; the gateway route is CSRF-exempt because it authenticates by header. `django.contrib.admin` is deliberately not installed — this is a JSON-only service with no server-rendered surface.

### Known trade-offs

- **Fixed windows, not sliding.** Up to `2 × limit` requests can land across a window boundary; the fixed window is one Redis round trip and easy to reason about.
- **Cached key metadata is up to `API_KEY_CACHE_SECONDS` stale.** Revocation and rotation evict explicitly, so the staleness applies to rate-limit changes and expiry, not to revocation.
- **`Authorization` is forwarded, `Cookie` is not.** Clients often need to authenticate to the upstream as well; RelayGuard's own session cookie must not leak to it.
- **`REMOTE_ADDR` is logged as the client address.** Behind a load balancer that is the balancer — `X-Forwarded-For` is deliberately not trusted here, because a client can set it.
- **The upstream host is trusted once allowlisted.** Its DNS is not checked against private ranges, since the upstream is operator-configured rather than caller-supplied.
- **A response within the limit is still buffered.** Bodies up to `PROXY_MAX_RESPONSE_BYTES` are assembled in memory so Django can set `Content-Length`; size that setting against expected concurrency.

## Testing

```bash
pytest --cov                                     # 133 tests, 100% coverage
ruff check . && ruff format --check .
bandit -c pyproject.toml -r config proxyapi
pip-audit -r requirements.txt
python manage.py check --deploy
```

Tests run against real PostgreSQL and Redis, covering both rate-limiter backends, the sync and async middleware paths, header stripping, streamed size limits, database constraints, the Celery fallback, and the key lifecycle. Regression tests pin the properties that are easiest to lose: exempt prefixes must not be proxiable, a key's visible prefix must not authenticate, no stored column may be replayable, and dot segments must not reach the upstream. CI adds a missing-migration check and runs on Python 3.12 and 3.13.

## Production notes

- PostgreSQL and shared Redis on private networks
- Strong `DJANGO_SECRET_KEY`, restricted `DJANGO_ALLOWED_HOSTS`, narrow upstream allowlist
- TLS terminated at a reverse proxy, with `USE_X_FORWARDED_PROTO` and `SECURE_SSL_REDIRECT` set; absolute request-size limits belong there too
- Celery worker and Beat as separate processes; never commit `.env`
- The web container migrates on start: fine for one replica, but scale-out wants migrations as a separate step

## License

MIT — see [LICENSE](LICENSE).
