"""Serializers for the API-key management endpoints.

These also drive the generated OpenAPI schema, so request and response shapes stay
documented in one place.
"""

from rest_framework import serializers

from .models import APIKey

MAX_RATE_LIMIT_PER_MINUTE = 100_000


class APIKeySerializer(serializers.ModelSerializer):
    """Read view of a key. The secret itself is never included."""

    prefix = serializers.CharField(source="key_prefix", read_only=True)

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "prefix",
            "is_active",
            "rate_limit_per_minute",
            "created_at",
            "last_used_at",
            "revoked_at",
        ]
        read_only_fields = fields


class APIKeyCreateSerializer(serializers.Serializer):
    """Input for issuing a key.

    The per-user cap is enforced in the view, which answers 409 rather than the
    400 a serializer validation error would produce.
    """

    name = serializers.CharField(max_length=120, default="API key")
    rate_limit_per_minute = serializers.IntegerField(
        default=60,
        min_value=1,
        max_value=MAX_RATE_LIMIT_PER_MINUTE,
    )


class IssuedAPIKeySerializer(serializers.Serializer):
    """The one and only response that contains the raw key."""

    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(read_only=True)
    api_key = serializers.CharField(read_only=True)
    rate_limit_per_minute = serializers.IntegerField(read_only=True)
    warning = serializers.CharField(read_only=True)
