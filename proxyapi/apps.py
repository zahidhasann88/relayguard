from django.apps import AppConfig


class ProxyApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "proxyapi"
    verbose_name = "RelayGuard gateway"
