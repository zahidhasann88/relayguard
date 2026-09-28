"""Django settings for RelayGuard.

All deployment-specific values are read from environment variables. During local
development they are loaded from a ``.env`` file in the project root (see
``.env.example``); in containers and CI they come from the real environment.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from celery.schedules import crontab
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    """Populate os.environ from .env without overriding real environment vars."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - python-dotenv is a declared dependency
        return
    load_dotenv(BASE_DIR / ".env", override=False)


_load_dotenv()


# A variable present but empty (``REDIS_URL=`` in a .env file) is treated as
# unset throughout, so commenting a value out and blanking it behave the same.
def env_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None or not value.strip() else value


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    try:
        return int(value) if value not in (None, "") else default
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    try:
        return float(value) if value not in (None, "") else default
    except ValueError:
        return default


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in env_str(name, default).split(",") if item.strip()]


# Core
DEBUG = env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

_PLACEHOLDER_SECRETS = {"", "replace-with-a-long-random-secret", "dev-only-change-me"}
SECRET_KEY = env_str("DJANGO_SECRET_KEY")

if SECRET_KEY in _PLACEHOLDER_SECRETS or len(SECRET_KEY) < 50:
    if not DEBUG:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY must be set to at least 50 random characters when DJANGO_DEBUG is off. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(64))"'
        )
    # A throwaway key per process, so no weak constant can reach production.
    SECRET_KEY = secrets.token_urlsafe(64)

ROOT_URLCONF = "config.urls"
ASGI_APPLICATION = "config.asgi.application"
WSGI_APPLICATION = "config.wsgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# The gateway forwards the request path verbatim, so Django must not rewrite it.
APPEND_SLASH = False

USE_TZ = True
USE_I18N = False
TIME_ZONE = env_str("DJANGO_TIME_ZONE", "UTC")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "drf_spectacular",
    "proxyapi",
]

# The rate limiter sits directly behind SecurityMiddleware, so unauthenticated or
# over-quota traffic is rejected before sessions, CSRF and auth do any work while
# those responses still get their security headers. Every entry here is
# async-capable, which keeps the proxy view on the event loop.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "proxyapi.middleware.RateLimitingMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# JSON-only service: no templates are shipped. The backend is declared only so
# Django can render debug pages.
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": False,
        "OPTIONS": {"context_processors": []},
    }
]

# PostgreSQL is required; the engine is fixed so the Postgres-only options below
# can never be handed to another backend.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env_str("DB_NAME", "relayguard_db"),
        "USER": env_str("DB_USER", "postgres"),
        "PASSWORD": env_str("DB_PASSWORD", ""),
        "HOST": env_str("DB_HOST", "localhost"),
        "PORT": env_str("DB_PORT", "5432"),
        "CONN_MAX_AGE": env_int("DB_CONN_MAX_AGE", 60),
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {"connect_timeout": env_int("DB_CONNECT_TIMEOUT", 10)},
    }
}

# Cache and rate-limit backend
REDIS_URL = env_str("REDIS_URL", "")

if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
        }
    }
else:
    # Process-local fallback: fine for development and single-process runs, but
    # counters are not shared between workers.
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "relayguard-rate-limits",
            "TIMEOUT": 60,
            "OPTIONS": {"MAX_ENTRIES": 100_000},
        }
    }

# Authentication
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Gateway behaviour
PROXY_UPSTREAM = env_str("PROXY_UPSTREAM", "https://httpbin.org")
PROXY_ALLOWED_HOSTS = {h.lower() for h in env_list("PROXY_ALLOWED_HOSTS", "httpbin.org")}
PROXY_TIMEOUT_SECONDS = env_float("PROXY_TIMEOUT_SECONDS", 15.0)
PROXY_MAX_BODY_BYTES = env_int("PROXY_MAX_BODY_BYTES", 10 * 1024 * 1024)
PROXY_MAX_RESPONSE_BYTES = env_int("PROXY_MAX_RESPONSE_BYTES", 25 * 1024 * 1024)
PROXY_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

# Paths served by RelayGuard itself: never proxied, and never requiring an
# X-API-KEY header. config.urls builds the catch-all pattern from this tuple, so a
# prefix exempted here cannot fall through to the proxy.
GATEWAY_EXEMPT_PATH_PREFIXES = ("/health/", "/schema/", "/auth/")

# Issued keys are 54 characters; the ceiling stops an oversized header from being
# hashed at all.
API_KEY_MAX_LENGTH = 256

# request.body must be readable up to the gateway's own body limit, otherwise
# Django raises RequestDataTooBig before the proxy ever sees the request.
DATA_UPLOAD_MAX_MEMORY_SIZE = PROXY_MAX_BODY_BYTES

MAX_API_KEYS_PER_USER = env_int("MAX_API_KEYS_PER_USER", 20)
API_KEY_MAX_AGE_DAYS = env_int("API_KEY_MAX_AGE_DAYS", 365)
API_KEY_CACHE_SECONDS = env_int("API_KEY_CACHE_SECONDS", 60)
REQUEST_LOG_RETENTION_DAYS = env_int("REQUEST_LOG_RETENTION_DAYS", 90)

# Django REST framework and OpenAPI
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "RelayGuard",
    "DESCRIPTION": "API-key authenticated gateway with per-key rate limiting.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

# Celery
CELERY_BROKER_URL = env_str("CELERY_BROKER_URL", "") or REDIS_URL or "redis://127.0.0.1:6379/2"
CELERY_RESULT_BACKEND = env_str("CELERY_RESULT_BACKEND", "") or CELERY_BROKER_URL
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_TIME_LIMIT = env_int("CELERY_TASK_TIME_LIMIT", 60)
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
# Fail fast when the broker is down, so the request path falls back to the local
# writer instead of stalling for tens of seconds on connection retries.
CELERY_BROKER_TRANSPORT_OPTIONS = {"max_retries": 1}
CELERY_BROKER_CONNECTION_TIMEOUT = env_float("CELERY_BROKER_CONNECTION_TIMEOUT", 2.0)
CELERY_TASK_PUBLISH_RETRY = False
CELERY_TASK_ALWAYS_EAGER = env_bool("CELERY_TASK_ALWAYS_EAGER", False)
CELERY_BEAT_SCHEDULE = {
    "purge-old-request-logs": {
        "task": "proxyapi.tasks.purge_old_request_logs",
        "schedule": crontab(hour=3, minute=0),
        "kwargs": {"days": REQUEST_LOG_RETENTION_DAYS},
    }
}

# Security
SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", False)
SESSION_COOKIE_SECURE = SECURE_SSL_REDIRECT
CSRF_COOKIE_SECURE = SECURE_SSL_REDIRECT
SECURE_HSTS_SECONDS = 31_536_000 if SECURE_SSL_REDIRECT else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = SECURE_SSL_REDIRECT
SECURE_HSTS_PRELOAD = SECURE_SSL_REDIRECT
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS")

if env_bool("USE_X_FORWARDED_PROTO", False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Logging
LOG_LEVEL = env_str("DJANGO_LOG_LEVEL", "INFO").upper()

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
    },
    "root": {"handlers": ["console"], "level": "WARNING"},
    "loggers": {
        "django": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        "proxyapi": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
    },
}
