"""Liveness and readiness probes.

``live`` answers as long as the process is serving requests; ``ready`` also
verifies the database and the cache, which the rate limiter depends on.

They are DRF views only so that they appear in the generated OpenAPI schema
alongside the management API.
"""

import logging

from django.core.cache import cache
from django.db import connection
from drf_spectacular.utils import OpenApiExample, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

logger = logging.getLogger(__name__)

_PROBE_CACHE_KEY = "relayguard:healthcheck"


@extend_schema(
    summary="Liveness probe",
    description="Answers 200 as long as the process is serving requests.",
    responses={200: OpenApiResponse(description="The process is alive.")},
    examples=[OpenApiExample("alive", value={"status": "ok"}, response_only=True)],
    auth=[],
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def live(request):
    return Response({"status": "ok"})


@extend_schema(
    summary="Readiness probe",
    description="Checks the database connection and a cache round-trip. 503 if either fails.",
    responses={
        200: OpenApiResponse(description="Every dependency answered."),
        503: OpenApiResponse(description="At least one dependency is unavailable."),
    },
    examples=[
        OpenApiExample("ready", value={"status": "ok", "database": "ok", "cache": "ok"}, response_only=True),
        OpenApiExample(
            "not ready",
            value={"status": "unavailable", "database": "ok", "cache": "error"},
            response_only=True,
            status_codes=["503"],
        ),
    ],
    auth=[],
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def ready(request):
    checks = {"database": "error", "cache": "error"}
    try:
        connection.ensure_connection()
        checks["database"] = "ok"

        cache.set(_PROBE_CACHE_KEY, "ok", timeout=5)
        if cache.get(_PROBE_CACHE_KEY) != "ok":
            raise RuntimeError("cache round-trip failed")
        checks["cache"] = "ok"
    except Exception:
        logger.warning("Readiness probe failed", exc_info=True)
        return Response({"status": "unavailable", **checks}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    return Response({"status": "ok", **checks})
