"""Root URL configuration.

The catch-all comes last *and* refuses to match the prefixes RelayGuard serves
itself. Both matter: the middleware waves those prefixes through without an API
key, so a catch-all that still matched them (``/auth/nonsense``, say) would let
anyone reach the upstream unauthenticated and unmetered. Deriving the pattern from
``settings.GATEWAY_EXEMPT_PATH_PREFIXES`` keeps the two from drifting apart.
"""

import re

from django.conf import settings
from django.urls import re_path
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.views import SpectacularAPIView

from proxyapi.api_keys import (
    APIKeyListCreateView,
    APIKeyRevokeView,
    APIKeyRotateView,
)
from proxyapi.errors import bad_request, page_not_found, permission_denied, server_error
from proxyapi.health import live, ready
from proxyapi.views import ProxyGatewayView

_EXEMPT_ALTERNATION = "|".join(re.escape(prefix.lstrip("/")) for prefix in settings.GATEWAY_EXEMPT_PATH_PREFIXES)
_PROXY_PATTERN = rf"^(?!{_EXEMPT_ALTERNATION})(?P<path>.*)$"

urlpatterns = [
    re_path(r"^health/live$", live, name="health-live"),
    re_path(r"^health/ready$", ready, name="health-ready"),
    re_path(r"^schema/$", SpectacularAPIView.as_view(), name="schema"),
    re_path(r"^auth/keys$", APIKeyListCreateView.as_view(), name="api-key-list-create"),
    re_path(r"^auth/keys/(?P<pk>\d+)/rotate$", APIKeyRotateView.as_view(), name="api-key-rotate"),
    re_path(r"^auth/keys/(?P<pk>\d+)$", APIKeyRevokeView.as_view(), name="api-key-revoke"),
    # Header auth needs no CSRF. The decorator has to wrap the view callable
    # itself; on dispatch, CsrfViewMiddleware would not see it.
    re_path(_PROXY_PATTERN, csrf_exempt(ProxyGatewayView.as_view()), name="proxy-gateway"),
]

handler400 = bad_request
handler403 = permission_denied
handler404 = page_not_found
handler500 = server_error
