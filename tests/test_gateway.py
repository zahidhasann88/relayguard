"""Tests for the proxy gateway: authentication, forwarding and rate limiting."""

from datetime import timedelta
from unittest.mock import patch

import httpx
import pytest
from asgiref.sync import async_to_sync
from django.test import RequestFactory, override_settings
from django.utils import timezone

from proxyapi.models import RequestLog
from proxyapi.views import ProxyGatewayView

from .fakes import FakeUpstream, fake_upstream

pytestmark = pytest.mark.django_db


# --- authentication ---------------------------------------------------------


def test_missing_api_key_is_401(client):
    response = client.get("/anything")
    assert response.status_code == 401
    assert response.json()["error"] == "missing_api_key"


def test_malformed_api_key_is_403(client):
    """A token that matches nothing must be rejected, not reported as a 503."""
    response = client.get("/anything", headers={"x-api-key": "not-a-real-key"})
    assert response.status_code == 403
    assert response.json()["error"] == "invalid_api_key"


def test_absurdly_long_api_key_is_rejected_without_hashing(client):
    with patch("proxyapi.middleware.hash_key") as hashed:
        response = client.get("/anything", headers={"x-api-key": "x" * 5000})
    assert response.status_code == 403
    assert not hashed.called


def test_inactive_key_is_403(client, issued_key):
    item, raw = issued_key
    item.is_active = False
    item.save(update_fields=["is_active"])
    assert client.get("/anything", headers={"x-api-key": raw}).status_code == 403


def test_valid_key_is_accepted(client, raw_key):
    with fake_upstream(content=b"ok"):
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 200


def test_the_visible_prefix_alone_does_not_authenticate(client, issued_key):
    """Regression: the metadata cache must be keyed by the secret, not its prefix.

    ``key_prefix`` is published by the list endpoint, so a prefix-keyed entry would
    let the first 20 characters plus any filler authenticate for the cache TTL.
    """
    item, raw = issued_key
    with fake_upstream():
        assert client.get("/anything", headers={"x-api-key": raw}).status_code == 200
        forged = item.key_prefix + "filler-that-is-not-the-real-secret"
        assert client.get("/anything", headers={"x-api-key": forged}).status_code == 403


def test_nothing_in_the_database_can_be_replayed_as_a_credential(issued_key):
    """Regression: no stored column may be a usable secret."""
    item, raw = issued_key
    item.refresh_from_db()
    stored = {value for value in vars(item).values() if isinstance(value, str)}
    assert raw not in stored
    assert item.key_hash != raw


def test_successful_request_records_last_used_at(client, issued_key):
    item, raw = issued_key
    assert item.last_used_at is None
    with fake_upstream():
        client.get("/anything", headers={"x-api-key": raw})
    item.refresh_from_db()
    assert item.last_used_at is not None


@override_settings(API_KEY_MAX_AGE_DAYS=30)
def test_key_older_than_the_maximum_age_is_rejected(client, issued_key):
    from proxyapi.models import APIKey

    item, raw = issued_key
    APIKey.objects.filter(pk=item.pk).update(created_at=timezone.now() - timedelta(days=31))
    assert client.get("/anything", headers={"x-api-key": raw}).status_code == 403


@override_settings(API_KEY_MAX_AGE_DAYS=0)
def test_zero_maximum_age_disables_expiry(client, issued_key):
    from proxyapi.models import APIKey

    item, raw = issued_key
    APIKey.objects.filter(pk=item.pk).update(created_at=timezone.now() - timedelta(days=4000))
    with fake_upstream():
        assert client.get("/anything", headers={"x-api-key": raw}).status_code == 200


# --- routing ---------------------------------------------------------------


@pytest.mark.parametrize("path", ["/auth/nonsense", "/health/nonsense", "/schema/nonsense"])
def test_exempt_prefixes_are_never_proxied(client, path):
    """Regression: an exempt prefix that still reached the catch-all would let
    anyone proxy to the upstream with no key and no rate limit."""
    with fake_upstream() as upstream:
        response = client.get(path)
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"
    assert not upstream.called


def test_unsupported_method_is_405_with_an_allow_header(client, raw_key):
    response = client.generic("TRACE", "/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 405
    assert "GET" in response["Allow"]


@pytest.mark.parametrize("path", ["/../admin", "/v1/../../etc/passwd", "/a/./b"])
def test_relative_path_segments_are_refused(client, raw_key, path):
    """A dot segment normalises away in the resolved URL, so it can escape the
    base path an operator meant to expose."""
    with fake_upstream() as upstream:
        response = client.get(path, headers={"x-api-key": raw_key})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_path"
    assert not upstream.called


# --- forwarding ------------------------------------------------------------


def test_proxies_status_body_and_headers(client, raw_key):
    upstream = FakeUpstream(
        content=b'{"ok":true}',
        status_code=201,
        headers={"content-type": "application/json", "x-upstream": "yes"},
    )
    with fake_upstream(response=upstream):
        response = client.post(
            "/anything?x=1",
            data=b"abc",
            content_type="application/octet-stream",
            headers={"x-api-key": raw_key},
        )

    assert response.status_code == 201
    assert response.content == b'{"ok":true}'
    assert response["X-Upstream"] == "yes"
    assert response["Content-Type"] == "application/json"


def test_response_is_reassembled_from_every_chunk(client, raw_key):
    with fake_upstream(response=FakeUpstream(chunks=[b"one ", b"two ", b"three"])):
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.content == b"one two three"


def test_target_url_includes_path_and_query(client, raw_key):
    with fake_upstream() as upstream:
        client.get("/some/path?a=1&b=2", headers={"x-api-key": raw_key})
    assert upstream.last.url == "https://httpbin.org/some/path?a=1&b=2"


def test_request_body_is_forwarded(client, raw_key):
    with fake_upstream() as upstream:
        client.post(
            "/anything",
            data=b"payload",
            content_type="application/octet-stream",
            headers={"x-api-key": raw_key},
        )
    assert upstream.last.content == b"payload"


def test_credentials_and_hop_by_hop_headers_are_not_forwarded(client, raw_key):
    with fake_upstream() as upstream:
        client.get(
            "/anything",
            headers={"x-api-key": raw_key, "connection": "keep-alive"},
            HTTP_COOKIE="sessionid=secret",
        )

    sent = {name.lower() for name in upstream.last.headers}
    assert "x-api-key" not in sent
    assert "host" not in sent
    assert "cookie" not in sent
    assert "connection" not in sent


def test_forwarded_headers_describe_the_real_connection(client, raw_key):
    """A client-supplied X-Forwarded-For must not be relayed as if it were ours."""
    with fake_upstream() as upstream:
        client.get(
            "/anything",
            headers={"x-api-key": raw_key, "x-forwarded-for": "10.9.9.9"},
            REMOTE_ADDR="192.0.2.7",
        )

    sent = upstream.last.headers
    assert sent["X-Forwarded-For"] == "192.0.2.7"
    assert sent["X-Forwarded-Proto"] == "http"
    assert sent["X-Forwarded-Host"] == "testserver"


def test_upstream_content_encoding_is_not_relayed(client, raw_key):
    """httpx decodes the body, so a stale Content-Encoding would corrupt it."""
    upstream = FakeUpstream(b"plain", 200, {"content-encoding": "gzip", "content-type": "text/plain"})
    with fake_upstream(response=upstream):
        response = client.get("/anything", headers={"x-api-key": raw_key})

    assert response.content == b"plain"
    assert "Content-Encoding" not in response


def test_upstream_set_cookie_is_not_relayed(client, raw_key):
    """A Django response cannot carry two Set-Cookie headers, and httpx's header
    view would comma-join them into one corrupt value."""
    upstream = FakeUpstream(b"{}", 200, [("set-cookie", "a=1"), ("set-cookie", "b=2")])
    with fake_upstream(response=upstream):
        response = client.get("/anything", headers={"x-api-key": raw_key})

    assert "Set-Cookie" not in response


def test_repeated_upstream_headers_are_preserved_individually(client, raw_key):
    upstream = FakeUpstream(b"{}", 200, [("vary", "accept"), ("vary", "origin")])
    with fake_upstream(response=upstream):
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response["Vary"] == "origin"


# --- upstream policy and failure modes -------------------------------------


@override_settings(PROXY_UPSTREAM="https://not-allowed.example")
def test_disallowed_upstream_is_rejected(client, raw_key):
    with fake_upstream() as upstream:
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 500
    assert response.json()["error"] == "upstream_not_allowed"
    assert not upstream.called


@override_settings(PROXY_UPSTREAM="ftp://httpbin.org")
def test_non_http_upstream_scheme_is_rejected(client, raw_key):
    response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 500
    assert response.json()["error"] == "upstream_not_allowed"


def test_upstream_timeout_is_504(client, raw_key):
    with fake_upstream(error=httpx.ReadTimeout("slow")):
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 504
    assert response.json()["error"] == "upstream_timeout"


def test_upstream_transport_error_is_502(client, raw_key):
    with fake_upstream(error=httpx.ConnectError("down")):
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 502
    assert response.json()["error"] == "upstream_error"


def test_unexpected_error_is_502_proxy_error(client, raw_key):
    """Anything that is not an httpx error still fails closed, not as a 500."""
    with fake_upstream(error=ValueError("something odd")):
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 502
    assert response.json()["error"] == "proxy_error"


# --- size limits -----------------------------------------------------------


@override_settings(PROXY_MAX_RESPONSE_BYTES=4)
def test_oversized_upstream_response_is_502(client, raw_key):
    with fake_upstream(response=FakeUpstream(b"far too long")):
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 502
    assert response.json()["error"] == "upstream_response_too_large"


@override_settings(PROXY_MAX_RESPONSE_BYTES=8)
def test_streaming_stops_as_soon_as_the_limit_is_passed(client, raw_key):
    """The point of streaming: an oversized body must not be buffered whole."""
    upstream = FakeUpstream(chunks=[b"12345678", b"9", b"10", b"11"])
    with fake_upstream(response=upstream):
        response = client.get("/anything", headers={"x-api-key": raw_key})

    assert response.status_code == 502
    assert upstream.chunks_read == 2


@override_settings(PROXY_MAX_RESPONSE_BYTES=4)
def test_declared_oversized_response_is_rejected_before_reading(client, raw_key):
    upstream = FakeUpstream(b"tiny", 200, {"content-length": "999999"})
    with fake_upstream(response=upstream):
        response = client.get("/anything", headers={"x-api-key": raw_key})
    assert response.status_code == 502
    assert upstream.chunks_read == 0


@override_settings(PROXY_MAX_BODY_BYTES=4)
def test_oversized_request_body_is_413(client, raw_key):
    response = client.post(
        "/anything",
        data=b"much larger than four bytes",
        content_type="application/octet-stream",
        headers={"x-api-key": raw_key},
    )
    assert response.status_code == 413
    assert response.json()["error"] == "request_too_large"
    assert response["X-RateLimit-Limit"] == "5"


@override_settings(PROXY_MAX_BODY_BYTES=4)
def test_body_limit_holds_when_no_content_length_is_declared():
    """A chunked request declares no length, so the middleware cannot see its
    size; the view has to check the bytes it actually received."""
    request = RequestFactory().post("/anything", data=b"much larger", content_type="application/octet-stream")
    del request.META["CONTENT_LENGTH"]

    with fake_upstream() as upstream:
        response = async_to_sync(ProxyGatewayView()._proxy)(request)

    assert response.status_code == 413
    assert not upstream.called


def test_malformed_content_length_returns_400(client, raw_key):
    response = client.get("/anything", headers={"x-api-key": raw_key}, CONTENT_LENGTH="not-a-number")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_content_length"


# --- rate limiting ---------------------------------------------------------


def test_rate_limit_returns_429_with_retry_after(client, make_key):
    _, raw = make_key("tight", limit=2)
    headers = {"x-api-key": raw}

    with fake_upstream():
        assert client.get("/a", headers=headers).status_code == 200
        assert client.get("/b", headers=headers).status_code == 200
        limited = client.get("/c", headers=headers)

    assert limited.status_code == 429
    assert limited.json()["error"] == "rate_limit_exceeded"
    assert 1 <= int(limited["Retry-After"]) <= 60
    assert limited["X-RateLimit-Remaining"] == "0"


def test_rate_limit_headers_are_present(client, make_key):
    _, raw = make_key("headers", limit=10)
    with fake_upstream():
        response = client.get("/anything", headers={"x-api-key": raw})

    assert response["X-RateLimit-Limit"] == "10"
    assert response["X-RateLimit-Remaining"] == "9"
    assert int(response["X-RateLimit-Reset"]) > 0


def test_limits_are_tracked_per_key(client, make_key):
    _, tight = make_key("tight", limit=1)
    _, roomy = make_key("roomy", limit=10)

    with fake_upstream():
        assert client.get("/a", headers={"x-api-key": tight}).status_code == 200
        assert client.get("/a", headers={"x-api-key": tight}).status_code == 429
        assert client.get("/a", headers={"x-api-key": roomy}).status_code == 200


LOCMEM_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "test-locmem-fallback",
    }
}


@override_settings(CACHES=LOCMEM_CACHE)
def test_rate_limiting_works_on_the_locmem_fallback(client, make_key):
    """The development default has no Redis, so it uses add()/incr() instead."""
    from django.core.cache import cache as active_cache

    active_cache.clear()
    _, raw = make_key("locmem", limit=2)
    headers = {"x-api-key": raw}

    with fake_upstream():
        assert client.get("/a", headers=headers).status_code == 200
        second = client.get("/b", headers=headers)
        third = client.get("/c", headers=headers)

    assert second.status_code == 200
    assert second["X-RateLimit-Remaining"] == "0"
    assert third.status_code == 429


@override_settings(CACHES=LOCMEM_CACHE)
def test_counter_restarts_when_the_window_expires_mid_increment(client, make_key):
    """add() failing then incr() raising means the entry lapsed; restart at 1."""
    from django.core.cache import cache as active_cache

    active_cache.clear()
    _, raw = make_key("racy", limit=5)

    with patch("proxyapi.middleware.cache.add", return_value=False):
        with patch("proxyapi.middleware.cache.incr", side_effect=ValueError("expired")):
            with fake_upstream():
                response = client.get("/anything", headers={"x-api-key": raw})

    assert response.status_code == 200
    assert response["X-RateLimit-Remaining"] == "4"


def test_redis_counter_is_incremented_atomically(client, raw_key):
    """The Lua script is what makes INCR and EXPIRE inseparable."""
    with fake_upstream():
        client.get("/anything", headers={"x-api-key": raw_key})

    from django.core.cache import cache as active_cache

    redis_client = active_cache.client.get_client(write=True)
    keys = redis_client.keys("*rate_limit_key_*")
    assert keys, "no counter was written to Redis"
    assert redis_client.ttl(keys[0]) > 0, "counter has no TTL"


def test_counter_failure_returns_503(client, raw_key):
    target = "proxyapi.middleware.RateLimitingMiddleware._increment"
    with patch(target, side_effect=RuntimeError("redis down")):
        response = client.get("/anything", headers={"x-api-key": raw_key})

    assert response.status_code == 503
    assert response.json()["error"] == "rate_limiter_unavailable"


def test_key_lookup_failure_returns_503(client, raw_key):
    with patch("proxyapi.middleware.cache.get", side_effect=RuntimeError("cache down")):
        response = client.get("/anything", headers={"x-api-key": raw_key})

    assert response.status_code == 503
    assert response.json()["error"] == "rate_limiter_unavailable"


def test_touch_swallows_database_errors(issued_key):
    """_touch is best-effort bookkeeping; it must never raise into the request."""
    from proxyapi.middleware import RateLimitingMiddleware

    item, _ = issued_key
    with patch("proxyapi.middleware.APIKey.objects.filter", side_effect=RuntimeError("db hiccup")):
        RateLimitingMiddleware._touch(item)


def test_health_probes_skip_the_middleware_entirely(client):
    response = client.get("/health/live")
    assert response.status_code == 200
    assert "X-RateLimit-Limit" not in response


# --- CSRF and the async path ----------------------------------------------


def test_proxy_post_does_not_require_a_csrf_token(raw_key):
    """The gateway authenticates by header, so CSRF enforcement must not apply."""
    from django.test import Client

    strict = Client(enforce_csrf_checks=True)
    with fake_upstream(content=b"ok"):
        response = strict.post(
            "/anything",
            data=b"payload",
            content_type="application/octet-stream",
            headers={"x-api-key": raw_key},
        )
    assert response.status_code == 200


def test_middleware_runs_natively_on_the_async_handler(raw_key):
    """Under ASGI the middleware must take its async branch, so the proxy view
    stays on the event loop instead of being run through a worker thread."""
    from django.test import AsyncClient

    with fake_upstream(content=b"async ok") as upstream:
        response = async_to_sync(AsyncClient().get)("/anything", headers={"x-api-key": raw_key})

    assert response.status_code == 200
    assert response.content == b"async ok"
    assert response["X-RateLimit-Limit"] == "5"
    assert upstream.called


def test_async_path_enforces_the_rate_limit(make_key):
    from django.test import AsyncClient

    _, raw = make_key("async-tight", limit=1)
    aclient = AsyncClient()
    with fake_upstream():
        assert async_to_sync(aclient.get)("/a", headers={"x-api-key": raw}).status_code == 200
        assert async_to_sync(aclient.get)("/b", headers={"x-api-key": raw}).status_code == 429


# --- logging ---------------------------------------------------------------


def test_request_is_logged(client, issued_key):
    """End-to-end: a proxied request reaches the RequestLog writer.

    The broker is stubbed so the task body runs inline instead of reaching Redis.
    """
    from proxyapi.request_log import write_request_log

    item, raw = issued_key
    with patch("proxyapi.tasks.persist_request_log.delay", side_effect=write_request_log):
        with fake_upstream(content=b"ok"):
            client.get("/logged?q=1", headers={"x-api-key": raw})

    entry = RequestLog.objects.filter(endpoint_requested="/logged?q=1").first()
    assert entry is not None
    assert entry.response_status == 200
    assert entry.http_method == "GET"
    assert entry.api_key_id == item.id


def test_failed_request_is_logged_with_its_error_status(client, raw_key):
    from proxyapi.request_log import write_request_log

    with patch("proxyapi.tasks.persist_request_log.delay", side_effect=write_request_log):
        with fake_upstream(error=httpx.ConnectError("down")):
            client.get("/broken", headers={"x-api-key": raw_key})

    entry = RequestLog.objects.filter(endpoint_requested="/broken").first()
    assert entry is not None
    assert entry.response_status == 502


# --- the real pooled client -------------------------------------------------


def test_the_http_client_is_pooled_per_event_loop():
    """A fresh client per request would mean a new TLS handshake per request."""
    import asyncio

    from proxyapi import views

    async def two_clients_and_the_loop():
        return views.get_http_client(), views.get_http_client(), asyncio.get_running_loop()

    first, again, first_loop = asyncio.run(two_clients_and_the_loop())
    assert first is again
    assert first.follow_redirects is False

    # A connection belongs to the loop that opened it, so a second loop must get
    # its own client, and the finished loop must not be held on to.
    second, _, _ = asyncio.run(two_clients_and_the_loop())
    assert second is not first
    assert first_loop not in views._clients


def test_the_pool_is_configured_with_the_upstream_timeout(settings):
    import asyncio

    settings.PROXY_TIMEOUT_SECONDS = 3.5
    client = asyncio.run(_fresh_client())
    assert client.timeout.connect == 3.5


async def _fresh_client():
    from proxyapi import views

    return views.get_http_client()


def test_a_path_that_cannot_form_a_url_is_a_400(client, raw_key):
    """A percent-encoded NUL decodes into the path and httpx refuses it, which has
    to surface as a client error rather than an unhandled exception."""
    with fake_upstream() as upstream:
        response = client.get("/anything%00", headers={"x-api-key": raw_key})

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_path"
    assert not upstream.called


def test_exempt_paths_are_waved_through_on_the_async_path():
    from django.test import AsyncClient

    response = async_to_sync(AsyncClient().get)("/health/live")
    assert response.status_code == 200
    assert "X-RateLimit-Limit" not in response


@override_settings(ALLOWED_HOSTS=["allowed.example"])
def test_a_host_header_that_is_not_allowed_never_reaches_the_upstream(raw_key):
    """CommonMiddleware validates the Host before the gateway sees the request,
    and the rejection comes back as JSON like every other error."""
    from django.test import Client

    with fake_upstream() as upstream:
        response = Client(headers={"host": "evil.example"}).get("/anything", headers={"x-api-key": raw_key})

    assert response.status_code == 400
    assert response["Content-Type"] == "application/json"
    assert not upstream.called
