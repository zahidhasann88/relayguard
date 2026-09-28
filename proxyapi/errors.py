"""JSON error handlers, since Django's defaults render HTML."""

from django.http import JsonResponse


def bad_request(request, exception=None):
    return JsonResponse({"error": "bad_request", "detail": "The request could not be processed."}, status=400)


def permission_denied(request, exception=None):
    return JsonResponse({"error": "forbidden", "detail": "Access is denied."}, status=403)


def page_not_found(request, exception=None):
    return JsonResponse({"error": "not_found", "detail": "No route matches this path."}, status=404)


def server_error(request):
    return JsonResponse({"error": "server_error", "detail": "An unexpected error occurred."}, status=500)
