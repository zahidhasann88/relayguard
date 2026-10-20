# RelayGuard

RelayGuard is an API gateway built with Django. It sits between your clients and another API (the "upstream") and:

- **Checks API keys.** Every request needs a valid `X-API-KEY` header.
- **Limits traffic.** Each key gets a set number of requests per minute, tracked in Redis.
- **Forwards requests.** Allowed requests are passed to the upstream API, and the response comes back to the client.
- **Logs requests.** Every request is saved in the background with Celery, so logging doesn't slow anything down.

```text
Client ──(X-API-KEY)──▶ RelayGuard ──▶ Upstream API
                            │
                            └─▶ Celery ──▶ Request logs (PostgreSQL)
```

## Run with Docker (easiest)

To make a secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Then:

```bash
cp .env.example .env        # then set DJANGO_SECRET_KEY
docker compose up --build
```

This starts the gateway, PostgreSQL, Redis, a Celery worker and Celery Beat. The gateway runs at http://localhost:8000.

Create a user so you can make API keys:

```bash
docker compose exec web python manage.py createsuperuser
```

## Run locally

You need Python 3.12+ and PostgreSQL. Redis is optional in development.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env               # then edit DB settings and DJANGO_SECRET_KEY
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

## How to use it

**1. Create an API key.** Log in with the user you just created (HTTP Basic auth):

```bash
curl -u admin:yourpassword -X POST http://localhost:8000/auth/keys \
  -H "Content-Type: application/json" -d '{"name": "my-app", "rate_limit_per_minute": 60}'
```

The response shows the key **only once**, so copy it somewhere safe.

**2. Call the upstream through the gateway:**

```bash
curl -H "X-API-KEY: YOUR_KEY" "http://localhost:8000/anything?message=hello"
```

The path and query are added to `PROXY_UPSTREAM`, so this request goes to `https://httpbin.org/anything?message=hello`.

## Endpoints

| Method | Path | What it does |
|---|---|---|
| `GET` | `/auth/keys` | List your keys |
| `POST` | `/auth/keys` | Create a key |
| `POST` | `/auth/keys/{id}/rotate` | Replace a key with a new one |
| `DELETE` | `/auth/keys/{id}` | Revoke a key |
| `GET` | `/health/live`, `/health/ready` | Health checks |
| `GET` | `/schema/` | OpenAPI schema |
| any | anything else | Forwarded to the upstream |

The `/auth/keys` endpoints use your username and password, not an API key.

## Main settings

All settings are in `.env`. See `.env.example` for the full list.

| Setting | What it does |
|---|---|
| `DJANGO_SECRET_KEY` | Required. A long random string |
| `DB_*` | PostgreSQL connection |
| `REDIS_URL` | Redis for caching and rate limits. Leave it empty in development to skip Redis |
| `PROXY_UPSTREAM` | The API to forward requests to |
| `PROXY_ALLOWED_HOSTS` | Hosts the gateway is allowed to call |
| `MAX_API_KEYS_PER_USER` | How many keys each user can have |
| `API_KEY_MAX_AGE_DAYS` | When keys expire (`0` means never) |

## How it works

- **Keys are stored as hashes.** Only a SHA-256 hash of each key is saved, so a leaked database can't be used to make requests.
- **Rate limits can't be raced.** The per-minute counter is updated in Redis in one atomic step, so parallel requests can't slip past the limit.
- **Size limits are enforced early.** Oversized requests are rejected, and upstream responses are streamed and cut off as soon as they get too big.
- **Only allowed upstreams are called.** Tricks like `/../admin` in the path are blocked, and redirects are not followed.
- **It fails safe.** If Redis is down, the gateway returns `503` instead of letting unlimited traffic through.
- **Logging never slows responses.** Request logs are written in the background by Celery.

**Known limit:** rate limits use fixed one-minute windows, so a client can send up to 2× the limit around the moment one window ends and the next begins.

## Running the tests

```bash
pytest --cov
ruff check .
```

The tests need PostgreSQL and Redis running.

## License

MIT. See [LICENSE](LICENSE).
