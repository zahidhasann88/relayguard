"""Tests for the API-key lifecycle endpoints."""

import base64

import pytest
from django.test import override_settings

from proxyapi.credentials import hash_key
from proxyapi.models import APIKey

from .fakes import fake_upstream

pytestmark = pytest.mark.django_db

PASSWORD = "pw-for-tests-1"


def basic_auth(username="tester", password=PASSWORD) -> dict:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"authorization": f"Basic {token}"}


def test_key_endpoints_do_not_require_an_api_key(client):
    """The middleware must let /auth/ through so Basic auth can be evaluated."""
    response = client.get("/auth/keys")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response


def test_key_endpoints_require_authentication(client, user):
    assert client.get("/auth/keys").status_code == 401
    assert client.get("/auth/keys", headers=basic_auth()).status_code == 200


def test_keys_are_scoped_to_their_owner(client, user, make_key, django_user_model):
    other = django_user_model.objects.create_user(username="other", password=PASSWORD)
    make_key("not yours", owner=other)
    make_key("mine")

    response = client.get("/auth/keys", headers=basic_auth())
    names = [row["name"] for row in response.json()]
    assert names == ["mine"]


def test_create_returns_the_raw_key_once(client, user):
    response = client.post(
        "/auth/keys",
        data={"name": "local client", "rate_limit_per_minute": 30},
        content_type="application/json",
        headers=basic_auth(),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["api_key"].startswith("proxy_live_")
    assert body["rate_limit_per_minute"] == 30

    listed = client.get("/auth/keys", headers=basic_auth()).json()
    assert "api_key" not in listed[0]
    assert listed[0]["prefix"] == body["api_key"][:20]


def test_created_key_is_stored_only_as_a_digest(client, user):
    response = client.post(
        "/auth/keys",
        data={"name": "hashed"},
        content_type="application/json",
        headers=basic_auth(),
    )
    raw = response.json()["api_key"]
    stored = APIKey.objects.get(pk=response.json()["id"])

    assert stored.key_hash == hash_key(raw)
    assert raw not in stored.key_hash
    assert len(stored.key_hash) == 64


@pytest.mark.parametrize("limit", [0, -1, 100_001, "abc"])
def test_invalid_rate_limit_is_rejected(client, user, limit):
    response = client.post(
        "/auth/keys",
        data={"name": "bad", "rate_limit_per_minute": limit},
        content_type="application/json",
        headers=basic_auth(),
    )
    assert response.status_code == 400


@override_settings(MAX_API_KEYS_PER_USER=1)
def test_active_key_limit_returns_409(client, user, make_key):
    make_key("existing")
    response = client.post(
        "/auth/keys",
        data={"name": "one too many"},
        content_type="application/json",
        headers=basic_auth(),
    )
    assert response.status_code == 409
    assert response.json()["error"] == "key_limit_reached"


@override_settings(MAX_API_KEYS_PER_USER=1)
def test_revoked_keys_do_not_count_towards_the_limit(client, user, make_key):
    item, _ = make_key("spent")
    client.delete(f"/auth/keys/{item.pk}", headers=basic_auth())

    response = client.post(
        "/auth/keys",
        data={"name": "replacement"},
        content_type="application/json",
        headers=basic_auth(),
    )
    assert response.status_code == 201


@override_settings(MAX_API_KEYS_PER_USER=3)
def test_the_key_quota_is_counted_under_a_row_lock(user):
    """Regression: counting active keys outside a lock lets two concurrent
    requests each see room for one more, so the cap can be raced past."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from proxyapi.api_keys import APIKeyListCreateView

    with CaptureQueriesContext(connection) as captured:
        APIKeyListCreateView._create_within_quota(user, "locked", 60)

    assert any("FOR UPDATE" in query["sql"].upper() for query in captured.captured_queries)


def test_revoke_deactivates_the_key(client, user, make_key):
    item, _ = make_key("doomed")
    response = client.delete(f"/auth/keys/{item.pk}", headers=basic_auth())
    assert response.status_code == 204

    item.refresh_from_db()
    assert item.is_active is False
    assert item.revoked_at is not None


def test_revoked_key_stops_working_immediately(client, user, make_key):
    item, raw = make_key("short lived", limit=10)
    with fake_upstream():
        assert client.get("/anything", headers={"x-api-key": raw}).status_code == 200

        client.delete(f"/auth/keys/{item.pk}", headers=basic_auth())
        assert client.get("/anything", headers={"x-api-key": raw}).status_code == 403


def test_revoke_rejects_another_users_key(client, user, make_key, django_user_model):
    other = django_user_model.objects.create_user(username="other", password=PASSWORD)
    item, _ = make_key("not yours", owner=other)
    assert client.delete(f"/auth/keys/{item.pk}", headers=basic_auth()).status_code == 404


def test_revoking_twice_is_a_404(client, user, make_key):
    item, _ = make_key("doomed")
    assert client.delete(f"/auth/keys/{item.pk}", headers=basic_auth()).status_code == 204
    assert client.delete(f"/auth/keys/{item.pk}", headers=basic_auth()).status_code == 404


def test_rotate_revokes_the_old_key_and_issues_a_new_one(client, user, make_key):
    old, old_raw = make_key("rotating", limit=42)
    response = client.post(f"/auth/keys/{old.pk}/rotate", headers=basic_auth())

    assert response.status_code == 201
    body = response.json()
    assert body["api_key"].startswith("proxy_live_")
    assert body["api_key"] != old_raw
    assert body["rate_limit_per_minute"] == 42

    old.refresh_from_db()
    assert old.is_active is False
    assert APIKey.objects.get(pk=body["id"]).is_active is True


def test_rotated_key_stops_working_and_its_replacement_works(client, user, make_key):
    old, old_raw = make_key("rotating", limit=10)
    with fake_upstream():
        assert client.get("/anything", headers={"x-api-key": old_raw}).status_code == 200

        new_raw = client.post(f"/auth/keys/{old.pk}/rotate", headers=basic_auth()).json()["api_key"]

        assert client.get("/anything", headers={"x-api-key": old_raw}).status_code == 403
        assert client.get("/anything", headers={"x-api-key": new_raw}).status_code == 200


def test_rotate_rejects_an_unknown_key(client, user):
    assert client.post("/auth/keys/999999/rotate", headers=basic_auth()).status_code == 404


def test_rotate_rejects_another_users_key(client, user, make_key, django_user_model):
    other = django_user_model.objects.create_user(username="other", password=PASSWORD)
    item, _ = make_key("not yours", owner=other)
    assert client.post(f"/auth/keys/{item.pk}/rotate", headers=basic_auth()).status_code == 404


def test_management_endpoints_reject_an_api_key_as_a_credential(client, make_key):
    """API keys are for the gateway; the management API takes Basic or session auth."""
    _, raw = make_key("gateway only")
    assert client.get("/auth/keys", headers={"x-api-key": raw}).status_code == 401
