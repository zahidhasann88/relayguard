from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("proxyapi", "0002_secure_api_keys"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="apikey",
            options={"ordering": ("-created_at",)},
        ),
        migrations.AlterModelOptions(
            name="requestlog",
            options={"ordering": ("-timestamp",)},
        ),
        migrations.RenameIndex(
            model_name="requestlog",
            new_name="proxyapi_re_timesta_e8ab14_idx",
            old_name="proxyapi_re_timestamp_7c53f8_idx",
        ),
        migrations.RenameIndex(
            model_name="requestlog",
            new_name="proxyapi_re_api_key_90d174_idx",
            old_name="proxyapi_re_api_key_1a4b33_idx",
        ),
        migrations.AddIndex(
            model_name="apikey",
            index=models.Index(fields=["user", "is_active"], name="proxyapi_ap_user_id_9ff5a8_idx"),
        ),
    ]
