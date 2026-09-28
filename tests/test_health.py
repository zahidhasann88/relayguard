"""Tests for the health probes, the OpenAPI schema, and the server entry points."""

from unittest.mock import patch

import pytest
from django.db import OperationalError

pytestmark = pytest.mark.django_db


def test_liveness_needs_no_credentials(client):
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_dependencies(client):
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok", "cache": "ok"}


def test_readiness_is_503_when_the_database_is_down(client):
    with patch("proxyapi.health.connection.ensure_connection", side_effect=OperationalError("down")):
        response = client.get("/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unavailable"
    assert body["database"] == "error"


def test_readiness_is_503_when_the_cache_round_trip_fails(client):
    """The rate limiter depends on the cache, so a silent cache must fail readiness."""
    with patch("proxyapi.health.cache.get", return_value=None):
        response = client.get("/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["database"] == "ok"
    assert body["cache"] == "error"


def test_health_probes_reject_non_get_methods(client):
    assert client.post("/health/live").status_code == 405


def test_schema_is_served_without_an_api_key(client):
    response = client.get("/schema/")
    assert response.status_code == 200
    assert b"RelayGuard" in response.content


def test_schema_documents_every_management_endpoint(client):
    body = client.get("/schema/").content.decode()
    for path in ("/auth/keys", "/auth/keys/{id}/rotate", "/health/live", "/health/ready"):
        assert path in body


def test_unrouted_paths_answer_with_json_not_html(client):
    """RelayGuard only ever speaks JSON, including when it fails."""
    response = client.get("/auth/keys/not-a-number")
    assert response.status_code == 404
    assert response["Content-Type"] == "application/json"
    assert response.json()["error"] == "not_found"


def test_asgi_application_is_importable():
    """The gateway is async and must be served over ASGI, so this entry point matters."""
    from config.asgi import application

    assert callable(application)


def test_wsgi_application_is_importable():
    from config.wsgi import application

    assert callable(application)


def test_error_handlers_return_json_for_every_status():
    from django.test import RequestFactory

    from proxyapi import errors

    request = RequestFactory().get("/anything")
    for handler, expected in (
        (errors.bad_request, 400),
        (errors.permission_denied, 403),
        (errors.page_not_found, 404),
    ):
        response = handler(request, Exception("why"))
        assert response.status_code == expected
        assert response["Content-Type"] == "application/json"

    assert errors.server_error(request).status_code == 500
