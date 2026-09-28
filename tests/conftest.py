"""Shared pytest fixtures and test-wide settings overrides."""

import os

# Set before config.settings is imported, so a checkout with no .env can still run
# the suite; setdefault, so a real environment such as CI still wins.
os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-secret-key-" + "0" * 40)
os.environ.setdefault("DJANGO_DEBUG", "0")

import pytest  # noqa: E402
from django.core.cache import cache  # noqa: E402

# User passwords go through PBKDF2 on every Basic-auth request here, which would
# dominate the suite's runtime. API keys are digested, not password-hashed, so they
# are unaffected.
FAST_PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


@pytest.fixture(autouse=True)
def fast_password_hashing(settings):
    settings.PASSWORD_HASHERS = FAST_PASSWORD_HASHERS


@pytest.fixture(autouse=True)
def clear_cache():
    """Keep rate-limit counters and key caches from leaking between tests."""
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def user(fast_password_hashing, db, django_user_model):
    return django_user_model.objects.create_user(username="tester", password="pw-for-tests-1")


@pytest.fixture
def issued_key(user):
    """A key and its raw secret: ``(instance, raw_secret)``."""
    from proxyapi.api_keys import issue_key

    return issue_key(user, "issued", 5)


@pytest.fixture
def raw_key(issued_key):
    """Just the raw secret, usable directly as an X-API-KEY value."""
    return issued_key[1]


@pytest.fixture
def make_key(user):
    """Factory for extra keys: ``make_key(name, limit) -> (instance, raw)``."""
    from proxyapi.api_keys import issue_key

    def factory(name="extra", limit=60, owner=None):
        return issue_key(owner or user, name, limit)

    return factory
