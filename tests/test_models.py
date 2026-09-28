"""Tests for model-level guarantees: representations and database constraints."""

import pytest
from django.db import IntegrityError, transaction

from proxyapi.credentials import hash_key
from proxyapi.models import APIKey, RequestLog

pytestmark = pytest.mark.django_db


def test_api_key_str_identifies_it_by_prefix(user, make_key):
    item, raw = make_key("named")
    assert str(item) == f"named ({raw[:20]})"


def test_request_log_str_summarises_the_request():
    entry = RequestLog.objects.create(
        endpoint_requested="/anything?x=1",
        http_method="GET",
        response_status=200,
        latency_ms=12,
    )
    assert str(entry) == "GET /anything?x=1 -> 200"


def test_two_keys_cannot_share_a_digest(user, make_key):
    """The digest is the credential's identity, so the database enforces it."""
    item, raw = make_key("first")
    with pytest.raises(IntegrityError), transaction.atomic():
        APIKey.objects.create(user=user, name="clone", key_prefix=raw[:20], key_hash=hash_key(raw))


def test_a_zero_rate_limit_is_rejected_by_the_database(user):
    with pytest.raises(IntegrityError), transaction.atomic():
        APIKey.objects.create(
            user=user,
            name="unmetered",
            rate_limit_per_minute=0,
            key_prefix="proxy_live_zero",
            key_hash=hash_key("zero"),
        )


def test_a_revoked_key_cannot_be_left_active(user, make_key):
    """Whatever writes the row, revoked_at and is_active must agree."""
    from django.utils import timezone

    item, _ = make_key("inconsistent")
    with pytest.raises(IntegrityError), transaction.atomic():
        APIKey.objects.filter(pk=item.pk).update(revoked_at=timezone.now(), is_active=True)


def test_request_logs_survive_the_key_they_belong_to(user, make_key):
    item, _ = make_key("temporary")
    entry = RequestLog.objects.create(
        api_key=item,
        endpoint_requested="/kept",
        http_method="GET",
        response_status=200,
        latency_ms=1,
    )

    item.delete()
    entry.refresh_from_db()
    assert entry.api_key_id is None
