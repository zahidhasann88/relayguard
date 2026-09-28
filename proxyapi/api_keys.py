"""API-key issuance, revocation and rotation.

Authenticated with HTTP Basic or a Django session, never with an API key: the
gateway middleware skips these paths. A raw key is returned exactly once, at
creation or rotation; only its digest is stored.
"""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .credentials import KEY_PREFIX_LENGTH, api_key_cache_key, generate_key, hash_key
from .models import APIKey
from .serializers import APIKeyCreateSerializer, APIKeySerializer, IssuedAPIKeySerializer

_STORE_SECURELY = "Store this key securely. It will not be shown again."


def issue_key(user, name: str, limit: int) -> tuple[APIKey, str]:
    """Create a key for ``user`` and return it alongside the raw secret."""
    raw = generate_key()
    item = APIKey.objects.create(
        user=user,
        name=name,
        rate_limit_per_minute=limit,
        key_prefix=raw[:KEY_PREFIX_LENGTH],
        key_hash=hash_key(raw),
    )
    return item, raw


def revoke_key(item: APIKey) -> None:
    """Deactivate a key and drop its cached metadata so it stops working now."""
    item.is_active = False
    item.revoked_at = timezone.now()
    item.save(update_fields=["is_active", "revoked_at"])
    _evict(item.key_hash)


def _evict(key_hash: str) -> None:
    """Invalidate cached metadata, before and after the surrounding commit.

    The second eviction covers a race: another worker resolving the same key
    mid-transaction still sees ``is_active=True``, and would otherwise re-populate
    the cache with a row that is about to be revoked, keeping a dead key working
    for the rest of the cache TTL.
    """
    cache_key = api_key_cache_key(key_hash)
    cache.delete(cache_key)
    transaction.on_commit(lambda: cache.delete(cache_key))


def _issued_payload(item: APIKey, raw: str) -> dict:
    return {
        "id": item.id,
        "name": item.name,
        "api_key": raw,
        "rate_limit_per_minute": item.rate_limit_per_minute,
        "warning": _STORE_SECURELY,
    }


class ManagementAPIView(APIView):
    """Shared authentication policy for every management endpoint."""

    authentication_classes = [BasicAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]


class APIKeyListCreateView(ManagementAPIView):
    @extend_schema(responses={200: APIKeySerializer(many=True)})
    def get(self, request):
        keys = APIKey.objects.filter(user=request.user)
        return Response(APIKeySerializer(keys, many=True).data)

    @extend_schema(request=APIKeyCreateSerializer, responses={201: IssuedAPIKeySerializer})
    def post(self, request):
        serializer = APIKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            item, raw = self._create_within_quota(
                request.user,
                serializer.validated_data["name"],
                serializer.validated_data["rate_limit_per_minute"],
            )
        except _QuotaReached:
            return Response(
                {
                    "error": "key_limit_reached",
                    "detail": f"At most {settings.MAX_API_KEYS_PER_USER} active keys are allowed per user.",
                },
                status=status.HTTP_409_CONFLICT,
            )

        return Response(_issued_payload(item, raw), status=status.HTTP_201_CREATED)

    @staticmethod
    def _create_within_quota(user, name: str, limit: int) -> tuple[APIKey, str]:
        """Count and create under a row lock, so the cap cannot be raced past.

        Two requests that both counted before either inserted would each see room
        for one more key; locking the owner's row serialises them.
        """
        with transaction.atomic():
            get_user_model().objects.select_for_update().get(pk=user.pk)
            active = APIKey.objects.filter(user=user, is_active=True).count()
            if active >= settings.MAX_API_KEYS_PER_USER:
                raise _QuotaReached
            return issue_key(user, name, limit)


class _QuotaReached(Exception):
    """The caller already holds the maximum number of active keys."""


class APIKeyRevokeView(ManagementAPIView):
    @extend_schema(request=None, responses={204: None})
    def delete(self, request, pk):
        with transaction.atomic():
            item = APIKey.objects.select_for_update().filter(pk=pk, user=request.user, is_active=True).first()
            if item is None:
                return Response({"error": "not_found"}, status=status.HTTP_404_NOT_FOUND)
            revoke_key(item)
        return Response(status=status.HTTP_204_NO_CONTENT)


class APIKeyRotateView(ManagementAPIView):
    @extend_schema(request=None, responses={201: IssuedAPIKeySerializer})
    def post(self, request, pk):
        with transaction.atomic():
            old = APIKey.objects.select_for_update().filter(pk=pk, user=request.user, is_active=True).first()
            if old is None:
                return Response({"error": "not_found"}, status=status.HTTP_404_NOT_FOUND)
            revoke_key(old)
            item, raw = issue_key(request.user, old.name, old.rate_limit_per_minute)

        return Response(_issued_payload(item, raw), status=status.HTTP_201_CREATED)
