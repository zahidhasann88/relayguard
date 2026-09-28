"""API-key secret handling: generation, digesting and cache-key derivation.

Why SHA-256 and not ``make_password``: the token is 32 random bytes, so there is
no low-entropy guess for a slow KDF to frustrate, and a plain digest buys two
things a password hash cannot. Authentication becomes one indexed equality lookup
rather than a prefix scan plus a PBKDF2 verification per candidate (~100 ms of CPU
per cache miss), and the digest is reproducible from the token, which is what lets
the metadata cache be keyed by the secret itself instead of by a guessable prefix.
"""

import hashlib
import secrets

KEY_NAMESPACE = "proxy_live_"
KEY_PREFIX_LENGTH = 20
TOKEN_BYTES = 32


def generate_key() -> str:
    """Return a fresh raw API key. Shown to the caller once and never stored."""
    return KEY_NAMESPACE + secrets.token_urlsafe(TOKEN_BYTES)


def hash_key(raw: str) -> str:
    """Return the digest stored in ``APIKey.key_hash`` for a raw token."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def api_key_cache_key(key_hash: str) -> str:
    """Cache key for resolved API-key metadata.

    Keyed by the digest, never by the visible prefix: the cached branch does not
    re-check the secret, so a prefix-keyed entry would authenticate anyone who
    knows the leading characters the list endpoint publishes.
    """
    return f"api_key_{key_hash}"
