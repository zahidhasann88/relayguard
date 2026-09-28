"""Database models: API-key credentials and the proxied-request log."""

from django.conf import settings
from django.db import models


class APIKey(models.Model):
    """A credential presented in the ``X-API-KEY`` header.

    Only a digest of the secret is stored, so nothing in this table can be
    replayed as a credential.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(max_length=120)
    is_active = models.BooleanField(default=True)
    rate_limit_per_minute = models.PositiveIntegerField(default=60)
    created_at = models.DateTimeField(auto_now_add=True)
    # Leading characters of the token. Not a secret, and deliberately not unique:
    # a shared prefix is harmless because authentication matches on key_hash.
    key_prefix = models.CharField(max_length=24, db_index=True, editable=False)
    key_hash = models.CharField(max_length=64, unique=True, editable=False)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("user", "is_active"))]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(rate_limit_per_minute__gte=1),
                name="apikey_rate_limit_positive",
            ),
            # A revoked key must not look active, whichever code path wrote it.
            models.CheckConstraint(
                condition=models.Q(revoked_at__isnull=True) | models.Q(is_active=False),
                name="apikey_revoked_implies_inactive",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_prefix})"


class RequestLog(models.Model):
    """One proxied request. Written outside the request path; purged on a schedule."""

    api_key = models.ForeignKey(
        APIKey,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="request_logs",
    )
    endpoint_requested = models.CharField(max_length=2048)
    http_method = models.CharField(max_length=16)
    response_status = models.IntegerField()
    latency_ms = models.PositiveIntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ("-timestamp",)
        # Left unnamed so Django keeps generated names inside the 30-character
        # limit that models.E034 enforces.
        indexes = [
            models.Index(fields=("timestamp",)),
            models.Index(fields=("api_key", "timestamp")),
        ]

    def __str__(self):
        return f"{self.http_method} {self.endpoint_requested} -> {self.response_status}"
