"""Make the digest the only stored form of an API key.

``APIKey.key`` held a random UUID that the middleware also accepted as a
credential, stored in the clear -- so a database dump handed out working keys,
exactly what hashing ``key_hash`` was meant to prevent.

Existing rows cannot be carried over: legacy rows have no digest at all, and the
digest format changed from a PBKDF2 password hash to a SHA-256 of the token, which
no stored value can be converted into. Every row is removed and affected callers
need a key re-issued; ``RequestLog.api_key`` is ``SET_NULL``, so request history
survives.
"""

from django.db import migrations, models


def drop_unverifiable_keys(apps, schema_editor):
    apps.get_model("proxyapi", "APIKey").objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [("proxyapi", "0003_fix_index_names_and_ordering")]

    operations = [
        migrations.RunPython(drop_unverifiable_keys, migrations.RunPython.noop),
        migrations.RemoveField(model_name="apikey", name="key"),
        migrations.AlterField(
            model_name="apikey",
            name="key_prefix",
            field=models.CharField(db_index=True, editable=False, max_length=24),
        ),
        migrations.AlterField(
            model_name="apikey",
            name="key_hash",
            field=models.CharField(editable=False, max_length=64, unique=True),
        ),
        migrations.AddConstraint(
            model_name="apikey",
            constraint=models.CheckConstraint(
                condition=models.Q(rate_limit_per_minute__gte=1),
                name="apikey_rate_limit_positive",
            ),
        ),
        migrations.AddConstraint(
            model_name="apikey",
            constraint=models.CheckConstraint(
                condition=models.Q(("revoked_at__isnull", True)) | models.Q(("is_active", False)),
                name="apikey_revoked_implies_inactive",
            ),
        ),
    ]
