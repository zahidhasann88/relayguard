"""Tests for the Celery tasks and the local request-log fallback."""

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.db import OperationalError
from django.utils import timezone

from proxyapi.models import RequestLog
from proxyapi.request_log import _write, enqueue_request_log, normalise_ip, write_request_log
from proxyapi.tasks import persist_request_log, purge_old_request_logs

pytestmark = pytest.mark.django_db


def test_write_request_log_truncates_long_values():
    entry = write_request_log(None, "/" + "x" * 5000, "SOMETHINGVERYLONGMETHOD", 200, 5, "127.0.0.1")
    assert len(entry.endpoint_requested) == 2048
    assert len(entry.http_method) == 16


def test_write_request_log_clamps_negative_latency():
    entry = write_request_log(None, "/x", "GET", 200, -10, None)
    assert entry.latency_ms == 0


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("", None),
        (None, None),
        ("not-an-ip", None),
        ("127.0.0.1, 10.0.0.1", None),
    ],
)
def test_unusable_client_addresses_are_discarded(value, expected):
    """An inet column rejects junk, and on the Celery path that would be retried
    three times before being given up on."""
    assert normalise_ip(value) == expected
    assert write_request_log(None, "/x", "GET", 200, 1, value).ip_address == expected


def test_enqueue_prefers_celery():
    with patch("proxyapi.tasks.persist_request_log.delay") as delay:
        enqueue_request_log(api_key_id=None, endpoint="/via-celery", method="GET", status=200, latency_ms=1, ip=None)
    delay.assert_called_once()


def test_enqueue_falls_back_to_local_write_when_celery_is_down():
    with patch("proxyapi.tasks.persist_request_log.delay", side_effect=OSError("broker down")):
        with patch("proxyapi.request_log._executor") as executor:
            enqueue_request_log(
                api_key_id=None,
                endpoint="/fallback",
                method="GET",
                status=200,
                latency_ms=1,
                ip=None,
            )
    executor.submit.assert_called_once()


def test_fallback_queue_is_bounded():
    """Broker down and database slow at once must not grow a queue for ever."""
    from proxyapi import request_log

    with patch.object(request_log, "MAX_PENDING_WRITES", 0):
        with patch.object(request_log, "_executor") as executor:
            request_log._submit(None, "/dropped", "GET", 200, 1, None)

    assert not executor.submit.called


def test_purge_deletes_only_old_logs():
    old = write_request_log(None, "/old", "GET", 200, 1, None)
    recent = write_request_log(None, "/recent", "GET", 200, 1, None)

    # auto_now_add prevents setting timestamp on create, so backdate it here.
    RequestLog.objects.filter(pk=old.pk).update(timestamp=timezone.now() - timedelta(days=120))

    deleted = purge_old_request_logs(days=90)

    assert deleted == 1
    assert not RequestLog.objects.filter(pk=old.pk).exists()
    assert RequestLog.objects.filter(pk=recent.pk).exists()


def test_purge_returns_zero_when_nothing_is_old():
    write_request_log(None, "/recent", "GET", 200, 1, None)
    assert purge_old_request_logs(days=90) == 0


def test_purge_works_across_several_batches():
    """A single unbounded DELETE over months of traffic holds too many locks."""
    for index in range(5):
        write_request_log(None, f"/old-{index}", "GET", 200, 1, None)
    RequestLog.objects.all().update(timestamp=timezone.now() - timedelta(days=120))

    with patch("proxyapi.tasks.PURGE_BATCH_SIZE", 2):
        assert purge_old_request_logs(days=90) == 5

    assert not RequestLog.objects.exists()


def test_purge_defaults_to_the_configured_retention(settings):
    settings.REQUEST_LOG_RETENTION_DAYS = 1
    entry = write_request_log(None, "/stale", "GET", 200, 1, None)
    RequestLog.objects.filter(pk=entry.pk).update(timestamp=timezone.now() - timedelta(days=2))

    assert purge_old_request_logs() == 1


def test_celery_task_persists_the_log():
    persist_request_log(None, "/via-celery", "POST", 201, 12, "10.0.0.1")

    entry = RequestLog.objects.get(endpoint_requested="/via-celery")
    assert entry.response_status == 201
    assert entry.http_method == "POST"


def test_local_writer_persists_and_recycles_connections():
    """The broker-down fallback path: it must write, and manage its own connection."""
    with patch("proxyapi.request_log.close_old_connections") as recycle:
        _write(None, "/local-fallback", "GET", 200, 3, "127.0.0.1")

    assert RequestLog.objects.filter(endpoint_requested="/local-fallback").exists()
    assert recycle.call_count == 2


def test_local_writer_swallows_database_errors():
    """A logging failure must never surface; it is already off the request path."""
    with patch("proxyapi.request_log.write_request_log", side_effect=OperationalError("gone")):
        with patch("proxyapi.request_log.close_old_connections"):
            _write(None, "/boom", "GET", 200, 1, None)

    assert not RequestLog.objects.filter(endpoint_requested="/boom").exists()


def test_the_fallback_queue_makes_room_again_after_a_write():
    """_submit accounts for pending work, so the bound is a depth, not a total."""
    from concurrent.futures import Future

    from proxyapi import request_log

    finished = Future()
    finished.set_result(None)
    before = request_log._pending

    with patch.object(request_log._executor, "submit", return_value=finished) as submit:
        for index in range(3):
            request_log._submit(None, f"/counted-{index}", "GET", 200, 1, None)

    assert submit.call_count == 3
    assert request_log._pending == before
