"""Request-log persistence, kept off the request path.

Preferred route is a Celery task. If the broker is unreachable the write falls
back to a small thread pool so logs are not lost in single-node or development
setups.
"""

import ipaddress
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from django.db import close_old_connections

from .models import RequestLog

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="request-log")

ENDPOINT_MAX_LENGTH = 2048
METHOD_MAX_LENGTH = 16

# With the broker down and the database slow, an unbounded queue would grow with
# every request until the process ran out of memory. Logging is the one thing here
# that may be sacrificed to keep serving traffic.
MAX_PENDING_WRITES = 1000
_pending = 0
_pending_lock = threading.Lock()


def enqueue_request_log(*, api_key_id, endpoint, method, status, latency_ms, ip):
    """Hand a log entry to Celery, falling back to a local thread on failure."""
    try:
        from .tasks import persist_request_log

        persist_request_log.delay(api_key_id, endpoint, method, status, latency_ms, ip)
    except Exception:
        logger.warning("Celery unavailable; writing request log locally", exc_info=True)
        _submit(api_key_id, endpoint, method, status, latency_ms, ip)


def _submit(*args) -> None:
    global _pending
    with _pending_lock:
        if _pending >= MAX_PENDING_WRITES:
            logger.error("Request-log fallback queue is full; dropping one entry")
            return
        _pending += 1
    _executor.submit(_write, *args).add_done_callback(_release)


def _release(_future) -> None:
    global _pending
    with _pending_lock:
        _pending -= 1


def normalise_ip(value):
    """Return ``value`` if it is a usable IP literal, else None.

    ``ip_address`` is a Postgres ``inet`` column and ``create()`` does not
    validate, so a junk ``REMOTE_ADDR`` would raise at the database and, on the
    Celery path, be retried three times before being given up on.
    """
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        logger.debug("Discarding unusable client address %r", value)
        return None


def write_request_log(api_key_id, endpoint, method, status, latency_ms, ip) -> RequestLog:
    """Create the RequestLog row. Shared by the Celery task and the fallback."""
    return RequestLog.objects.create(
        api_key_id=api_key_id,
        endpoint_requested=(endpoint or "")[:ENDPOINT_MAX_LENGTH],
        http_method=(method or "")[:METHOD_MAX_LENGTH],
        response_status=status,
        latency_ms=max(0, latency_ms),
        ip_address=normalise_ip(ip),
    )


def _write(api_key_id, endpoint, method, status, latency_ms, ip):
    try:
        close_old_connections()
        write_request_log(api_key_id, endpoint, method, status, latency_ms, ip)
    except Exception:
        logger.exception("Unable to persist request log")
    finally:
        close_old_connections()
