"""API-key authentication and per-key rate limiting.

Paths under ``settings.GATEWAY_EXEMPT_PATH_PREFIXES`` are passed straight
through; they authenticate by other means or need no authentication. That is only
safe because ``config.urls`` also refuses to proxy those prefixes.

Sync- and async-capable on purpose: a sync-only middleware would make Django run
the async proxy view through ``async_to_sync``, costing a thread per in-flight
request. Only the blocking work in ``_guard`` takes a thread hop.
"""

import logging
import time
from datetime import timedelta

from asgiref.sync import iscoroutinefunction, markcoroutinefunction, sync_to_async
from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone

from .credentials import api_key_cache_key, hash_key
from .models import APIKey

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60

# One round trip, so a crash between INCR and EXPIRE cannot leave a counter
# without a TTL and concurrent workers cannot interleave.
_INCR_SCRIPT = "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n"


def _error(code: str, detail: str, status: int, headers: dict | None = None) -> JsonResponse:
    return JsonResponse({"error": code, "detail": detail}, status=status, headers=headers)


class RateLimitingMiddleware:
    async_capable = True
    sync_capable = True

    def __init__(self, get_response):
        self.get_response = get_response
        self.async_mode = iscoroutinefunction(get_response)
        if self.async_mode:
            markcoroutinefunction(self)

    def __call__(self, request):
        if self.async_mode:
            return self.__acall__(request)

        if self._is_exempt(request):
            return self.get_response(request)

        error, state = self._guard(request)
        if error is not None:
            return error
        return self._annotate(self.get_response(request), state)

    async def __acall__(self, request):
        if self._is_exempt(request):
            return await self.get_response(request)

        error, state = await sync_to_async(self._guard, thread_sensitive=True)(request)
        if error is not None:
            return error
        return self._annotate(await self.get_response(request), state)

    @staticmethod
    def _is_exempt(request) -> bool:
        return request.path.startswith(settings.GATEWAY_EXEMPT_PATH_PREFIXES)

    def _guard(self, request) -> tuple[JsonResponse | None, dict | None]:
        """Authenticate and meter the request.

        Returns ``(response, None)`` to short-circuit, or ``(None, state)`` to
        continue. All blocking work is confined here so the async path needs
        exactly one thread hop.
        """
        if request.method not in settings.PROXY_ALLOWED_METHODS:
            return _error(
                "method_not_allowed",
                "HTTP method is not supported.",
                405,
                headers={"Allow": ", ".join(sorted(settings.PROXY_ALLOWED_METHODS))},
            ), None

        token = request.headers.get("X-API-KEY")
        if not token:
            return _error("missing_api_key", "X-API-KEY is required.", 401), None
        if len(token) > settings.API_KEY_MAX_LENGTH:
            # Refused before hashing; no issued key is anywhere near this long.
            return _error("invalid_api_key", "The API key is invalid or inactive.", 403), None

        try:
            key_data = self._resolve_key(token)
        except LookupError:
            return _error("invalid_api_key", "The API key is invalid or inactive.", 403), None
        except Exception:
            logger.exception("API-key lookup failed")
            return _error("rate_limiter_unavailable", "Rate limiting service is unavailable.", 503), None

        request.api_key = key_data

        now = time.time()
        window = int(now // WINDOW_SECONDS)
        try:
            count = self._increment(f"rate_limit_key_{key_data['id']}_{window}")
        except Exception:
            logger.exception("Rate-limit counter update failed")
            return _error("rate_limiter_unavailable", "Rate limiting service is unavailable.", 503), None

        state = {"limit": key_data["limit"], "count": count, "window": window}

        if count > key_data["limit"]:
            retry_after = max(1, int((window + 1) * WINDOW_SECONDS - now))
            response = _error(
                "rate_limit_exceeded", "Too many requests.", 429, headers={"Retry-After": str(retry_after)}
            )
            return self._annotate(response, state), None

        declared_length = request.META.get("CONTENT_LENGTH")
        if declared_length:
            try:
                too_large = int(declared_length) > settings.PROXY_MAX_BODY_BYTES
            except ValueError:
                return self._annotate(
                    _error("invalid_content_length", "Content-Length is not a valid integer.", 400), state
                ), None
            if too_large:
                return self._annotate(
                    _error("request_too_large", "Request body exceeds the allowed limit.", 413), state
                ), None

        return None, state

    def _resolve_key(self, token: str) -> dict:
        """Return cached metadata for ``token``, raising LookupError if unusable."""
        key_hash = hash_key(token)
        cache_key = api_key_cache_key(key_hash)

        cached = cache.get(cache_key)
        if cached:
            return cached

        key = self._find_key(key_hash)
        if key is None:
            raise LookupError("no active API key matches the presented token")

        data = {"id": key.id, "limit": key.rate_limit_per_minute}
        cache.set(cache_key, data, timeout=settings.API_KEY_CACHE_SECONDS)
        self._touch(key)
        return data

    @staticmethod
    def _find_key(key_hash: str) -> APIKey | None:
        query = APIKey.objects.filter(key_hash=key_hash, is_active=True)
        max_age = settings.API_KEY_MAX_AGE_DAYS
        if max_age > 0:  # 0 disables expiry
            query = query.filter(created_at__gte=timezone.now() - timedelta(days=max_age))
        return query.first()

    @staticmethod
    def _touch(key: APIKey) -> None:
        """Record last use. Bookkeeping must never fail a request."""
        try:
            APIKey.objects.filter(pk=key.pk).update(last_used_at=timezone.now())
        except Exception:
            logger.warning("Unable to update last_used_at for API key %s", key.pk, exc_info=True)

    @staticmethod
    def _increment(counter_key: str) -> int:
        client = getattr(cache, "client", None)
        if client is not None:
            redis_client = client.get_client(write=True)
            script = redis_client.register_script(_INCR_SCRIPT)
            return int(script(keys=[counter_key], args=[WINDOW_SECONDS + 1]))

        # LocMem fallback: add() is atomic enough within one process.
        if cache.add(counter_key, 1, timeout=WINDOW_SECONDS + 1):
            return 1
        try:
            return cache.incr(counter_key)
        except ValueError:
            # The entry expired between add() and incr(); restart the window.
            cache.set(counter_key, 1, timeout=WINDOW_SECONDS + 1)
            return 1

    @staticmethod
    def _annotate(response, state: dict):
        response["X-RateLimit-Limit"] = str(state["limit"])
        response["X-RateLimit-Remaining"] = str(max(0, state["limit"] - state["count"]))
        response["X-RateLimit-Reset"] = str((state["window"] + 1) * WINDOW_SECONDS)
        return response
