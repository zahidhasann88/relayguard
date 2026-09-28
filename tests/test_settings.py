"""Tests for the boot path in config.settings.

A typo in .env should fall back to a sane default rather than crash the process or
silently select the wrong backend, and a deployment must not be able to start on a
placeholder secret key.
"""

import importlib.util
from pathlib import Path

import pytest
from django.core.exceptions import ImproperlyConfigured

from config.settings import env_bool, env_float, env_int, env_list, env_str

VAR = "RELAYGUARD_TEST_VAR"
SETTINGS_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.py"


def boot_settings():
    """Execute config/settings.py as a fresh process would.

    Loaded outside sys.modules, so the settings Django is already running under are
    left untouched.
    """
    spec = importlib.util.spec_from_file_location("relayguard_settings_probe", SETTINGS_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- environment helpers ---------------------------------------------------


def test_env_str_returns_the_default_when_unset(monkeypatch):
    monkeypatch.delenv(VAR, raising=False)
    assert env_str(VAR, "fallback") == "fallback"


def test_empty_and_whitespace_values_count_as_unset(monkeypatch):
    """Blanking a variable in .env must behave the same as commenting it out."""
    for value in ("", "   "):
        monkeypatch.setenv(VAR, value)
        assert env_str(VAR, "fallback") == "fallback"
        assert env_bool(VAR, True) is True
        assert env_int(VAR, 5) == 5
        assert env_float(VAR, 1.5) == 1.5


def test_env_bool_accepts_the_usual_truthy_spellings(monkeypatch):
    for value in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv(VAR, value)
        assert env_bool(VAR) is True
    for value in ("0", "false", "no", "off", "anything-else"):
        monkeypatch.setenv(VAR, value)
        assert env_bool(VAR) is False


def test_env_int_falls_back_on_a_non_numeric_value(monkeypatch):
    monkeypatch.setenv(VAR, "not-a-number")
    assert env_int(VAR, 7) == 7


def test_env_float_falls_back_on_a_non_numeric_value(monkeypatch):
    monkeypatch.setenv(VAR, "not-a-number")
    assert env_float(VAR, 2.5) == 2.5


def test_env_list_splits_and_strips(monkeypatch):
    monkeypatch.setenv(VAR, " a , b ,, c ")
    assert env_list(VAR) == ["a", "b", "c"]


# --- secret key ------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    ["", "replace-with-a-long-random-secret", "dev-only-change-me", "too-short"],
)
def test_a_weak_secret_key_refuses_to_boot_outside_debug(monkeypatch, secret):
    monkeypatch.setenv("DJANGO_DEBUG", "0")
    monkeypatch.setenv("DJANGO_SECRET_KEY", secret)

    with pytest.raises(ImproperlyConfigured, match="DJANGO_SECRET_KEY"):
        boot_settings()


def test_debug_generates_an_ephemeral_secret_key(monkeypatch):
    """Development stays frictionless, and no weak constant can reach production."""
    monkeypatch.setenv("DJANGO_DEBUG", "1")
    monkeypatch.setenv("DJANGO_SECRET_KEY", "")

    first = boot_settings().SECRET_KEY
    second = boot_settings().SECRET_KEY

    assert len(first) >= 50
    assert first != second


def test_a_real_secret_key_is_used_as_given(monkeypatch):
    secret = "s" * 60
    monkeypatch.setenv("DJANGO_DEBUG", "0")
    monkeypatch.setenv("DJANGO_SECRET_KEY", secret)

    assert boot_settings().SECRET_KEY == secret


# --- consistency between settings and routing ------------------------------


def test_every_exempt_prefix_is_actually_served(settings):
    """A prefix waved past the middleware but not served here would be a path
    nobody answers and nobody may proxy."""
    from django.urls import get_resolver

    patterns = {str(pattern.pattern) for pattern in get_resolver().url_patterns}
    for prefix in settings.GATEWAY_EXEMPT_PATH_PREFIXES:
        stem = prefix.strip("/")
        assert any(pattern.lstrip("^").startswith(stem) for pattern in patterns), prefix


def test_the_body_limit_is_not_capped_below_by_django(settings):
    """request.body must be readable up to the gateway's own limit."""
    assert settings.DATA_UPLOAD_MAX_MEMORY_SIZE >= settings.PROXY_MAX_BODY_BYTES


def test_the_rate_limiter_runs_before_session_and_csrf_work(settings):
    order = settings.MIDDLEWARE
    limiter = order.index("proxyapi.middleware.RateLimitingMiddleware")
    assert order.index("django.middleware.security.SecurityMiddleware") < limiter
    assert limiter < order.index("django.middleware.csrf.CsrfViewMiddleware")
    assert limiter < order.index("django.contrib.sessions.middleware.SessionMiddleware")


# --- backend selection -----------------------------------------------------


def test_an_empty_redis_url_selects_the_process_local_cache(monkeypatch):
    """The documented development default: one fewer service to run."""
    monkeypatch.setenv("DJANGO_DEBUG", "1")
    monkeypatch.setenv("REDIS_URL", "")

    settings_module = boot_settings()
    assert "LocMemCache" in settings_module.CACHES["default"]["BACKEND"]
    # Celery still needs a broker, so it falls back to a conventional address.
    assert settings_module.CELERY_BROKER_URL.startswith("redis://")


def test_a_redis_url_selects_the_shared_cache(monkeypatch):
    monkeypatch.setenv("DJANGO_DEBUG", "1")
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6379/9")

    settings_module = boot_settings()
    assert settings_module.CACHES["default"]["BACKEND"] == "django_redis.cache.RedisCache"
    assert settings_module.CACHES["default"]["LOCATION"] == "redis://127.0.0.1:6379/9"


def test_forwarded_proto_is_only_trusted_when_asked_for(monkeypatch):
    """Trusting X-Forwarded-Proto unconditionally lets a client claim HTTPS."""
    monkeypatch.setenv("DJANGO_DEBUG", "1")

    monkeypatch.setenv("USE_X_FORWARDED_PROTO", "0")
    assert not hasattr(boot_settings(), "SECURE_PROXY_SSL_HEADER")

    monkeypatch.setenv("USE_X_FORWARDED_PROTO", "1")
    assert boot_settings().SECURE_PROXY_SSL_HEADER == ("HTTP_X_FORWARDED_PROTO", "https")


def test_enabling_tls_redirect_turns_on_the_rest_of_the_tls_hardening(monkeypatch):
    monkeypatch.setenv("DJANGO_DEBUG", "1")
    monkeypatch.setenv("SECURE_SSL_REDIRECT", "1")

    settings_module = boot_settings()
    assert settings_module.SESSION_COOKIE_SECURE is True
    assert settings_module.CSRF_COOKIE_SECURE is True
    assert settings_module.SECURE_HSTS_SECONDS > 0
