import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models

class Migration(migrations.Migration):
    initial = True
    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(name="APIKey", fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("key", models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, unique=True)),
            ("name", models.CharField(max_length=120)), ("is_active", models.BooleanField(default=True)),
            ("rate_limit_per_minute", models.PositiveIntegerField(default=60)), ("created_at", models.DateTimeField(auto_now_add=True)),
            ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="api_keys", to=settings.AUTH_USER_MODEL)),
        ]),
        migrations.CreateModel(name="RequestLog", fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("endpoint_requested", models.CharField(max_length=2048)), ("http_method", models.CharField(max_length=16)),
            ("response_status", models.IntegerField()), ("latency_ms", models.PositiveIntegerField()),
            ("timestamp", models.DateTimeField(auto_now_add=True)), ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
            ("api_key", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="request_logs", to="proxyapi.apikey")),
        ]),
        migrations.AddIndex(model_name="requestlog", index=models.Index(fields=["timestamp"], name="proxyapi_re_timestamp_7c53f8_idx")),
        migrations.AddIndex(model_name="requestlog", index=models.Index(fields=["api_key", "timestamp"], name="proxyapi_re_api_key_1a4b33_idx")),
    ]
