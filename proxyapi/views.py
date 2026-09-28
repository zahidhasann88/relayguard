"""The proxy gateway itself.

Forwards the request path and query string to the configured upstream and returns
the upstream status, body and safe headers. Every request is recorded
asynchronously, whatever the outcome.
"""

import asyncio
import logging
import time

import httpx
from asgiref.sync import sync_to_async
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.views import View

from .request_log import enqueue_request_log

logger = logging.getLogger(__name__)

# Connection-scoped headers must not be relayed across a proxy hop (RFC 9110).
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

# Host must match the upstream and httpx recomputes Content-Length. Cookie goes
# because RelayGuard sets its own session cookie on this origin and the upstream
# must not receive it. X-Forwarded-* is rebuilt from the connection below rather
# than trusted from the client.
_STRIP_REQUEST_HEADERS = _HOP_BY_HOP | {
    "host",
    "content-length",
    "x-api-key",
    "cookie",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}

# httpx has already decoded the body, so the upstream Content-Encoding and
# Content-Length would describe bytes we no longer have. Set-Cookie is dropped
# because a Django response cannot carry two, and joining them corrupts both.
_STRIP_RESPONSE_HEADERS = _HOP_BY_HOP | {"content-encoding", "content-length", "set-cookie"}

# Pooled to avoid a TCP and TLS handshake per proxied request. Keyed by event
# loop, because a connection belongs to the loop that opened it.
_clients: dict[asyncio.AbstractEventLoop, httpx.AsyncClient] = {}


def get_http_client() -> httpx.AsyncClient:
    """Return the pooled client for the running event loop, creating it if needed."""
    loop = asyncio.get_running_loop()
    for stale in [known for known in _clients if known.is_closed()]:
        _clients.pop(stale, None)

    client = _clients.get(loop)
    if client is None or client.is_closed:
        client = httpx.AsyncClient(
            timeout=settings.PROXY_TIMEOUT_SECONDS,
            # Following one would let the upstream steer the gateway to a host
            # that is not on the allowlist.
            follow_redirects=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
        _clients[loop] = client
    return client


class ProxyGatewayView(View):
    """Relays any supported method to the configured upstream.

    Django derives ``view_is_async`` from the handler methods, so every verb has
    to be bound to the async handler by name; overriding ``dispatch`` alone would
    leave the view running synchronously.
    """

    http_method_names = ["get", "post", "put", "patch", "delete", "head", "options"]

    async def handle(self, request, *args, **kwargs):
        started = time.monotonic()
        status = 502
        try:
            response = await self._proxy(request)
            status = response.status_code
            return response
        except httpx.TimeoutException:
            status = 504
            logger.warning("Upstream timed out for %s", request.path)
            return JsonResponse(
                {"error": "upstream_timeout", "detail": "The upstream API did not respond in time."},
                status=status,
            )
        except httpx.HTTPError:
            status = 502
            logger.warning("Upstream request failed for %s", request.path, exc_info=True)
            return JsonResponse(
                {"error": "upstream_error", "detail": "The upstream API could not be reached."},
                status=status,
            )
        except Exception:
            status = 502
            logger.exception("Unhandled error while proxying %s", request.path)
            return JsonResponse(
                {"error": "proxy_error", "detail": "The request could not be proxied."},
                status=status,
            )
        finally:
            key = getattr(request, "api_key", None) or {}
            # Touches the broker, and the ORM on the fallback path; neither is
            # safe to call from the event loop.
            await sync_to_async(enqueue_request_log, thread_sensitive=True)(
                api_key_id=key.get("id"),
                endpoint=request.get_full_path(),
                method=request.method,
                status=status,
                latency_ms=int((time.monotonic() - started) * 1000),
                ip=request.META.get("REMOTE_ADDR"),
            )

    get = post = put = patch = delete = head = options = handle

    async def _proxy(self, request) -> HttpResponse:
        target = self._build_target(request)
        if isinstance(target, HttpResponse):
            return target

        body = await sync_to_async(lambda: request.body, thread_sensitive=True)()
        # The middleware checks Content-Length, but a chunked request declares
        # none, so the real size is only knowable here.
        if len(body) > settings.PROXY_MAX_BODY_BYTES:
            return JsonResponse(
                {"error": "request_too_large", "detail": "Request body exceeds the allowed limit."},
                status=413,
            )

        client = get_http_client()
        request_headers = self._outbound_headers(request)
        limit = settings.PROXY_MAX_RESPONSE_BYTES

        async with client.stream(
            request.method,
            target,
            headers=request_headers,
            content=body,
            timeout=settings.PROXY_TIMEOUT_SECONDS,
        ) as upstream:
            declared = upstream.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > limit:
                return self._too_large()

            # Capped as it arrives: reading `.content` would buffer a 10 GB
            # upstream response in full before any limit could apply.
            chunks: list[bytes] = []
            total = 0
            async for chunk in upstream.aiter_bytes():
                total += len(chunk)
                if total > limit:
                    return self._too_large()
                chunks.append(chunk)

            response = HttpResponse(b"".join(chunks), status=upstream.status_code)
            for name, value in upstream.headers.multi_items():
                if name.lower() not in _STRIP_RESPONSE_HEADERS:
                    response[name] = value
            return response

    @staticmethod
    def _too_large() -> JsonResponse:
        return JsonResponse(
            {
                "error": "upstream_response_too_large",
                "detail": "The upstream response exceeds the allowed limit.",
            },
            status=502,
        )

    @staticmethod
    def _build_target(request) -> httpx.URL | HttpResponse:
        """Resolve the upstream URL, or return the error response to send instead.

        The allowlist is checked against the resolved URL, not against
        ``PROXY_UPSTREAM`` alone: ``https://api.example.com/v1`` plus a request
        for ``/../admin`` normalises to ``https://api.example.com/admin``,
        escaping the base path the operator meant to expose.
        """
        if any(segment in {"..", "."} for segment in request.path.split("/")):
            return JsonResponse(
                {"error": "invalid_path", "detail": "The request path may not contain relative segments."},
                status=400,
            )

        try:
            target = httpx.URL(settings.PROXY_UPSTREAM.rstrip("/") + request.path)
            query = request.META.get("QUERY_STRING")
            if query:
                target = target.copy_with(query=query.encode("utf-8"))
        except (httpx.InvalidURL, UnicodeError, ValueError):
            logger.warning("Could not build an upstream URL for %s", request.path)
            return JsonResponse(
                {"error": "invalid_path", "detail": "The request path is not a valid URL."},
                status=400,
            )

        if target.scheme not in {"http", "https"} or (target.host or "").lower() not in settings.PROXY_ALLOWED_HOSTS:
            logger.error("Refusing to proxy to %r: host or scheme is not allowed", str(target))
            return JsonResponse(
                {"error": "upstream_not_allowed", "detail": "Configured upstream host is not allowed."},
                status=500,
            )
        return target

    @staticmethod
    def _outbound_headers(request) -> dict:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _STRIP_REQUEST_HEADERS}
        # Never appended to a client-supplied value: an upstream that trusts
        # X-Forwarded-For must not be handed a spoofed one.
        remote_addr = request.META.get("REMOTE_ADDR")
        if remote_addr:
            headers["X-Forwarded-For"] = remote_addr
        headers["X-Forwarded-Proto"] = "https" if request.is_secure() else "http"
        host = request.get_host()
        if host:
            headers["X-Forwarded-Host"] = host
        return headers
