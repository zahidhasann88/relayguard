from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [("proxyapi", "0001_initial")]
    operations = [
        migrations.AddField(model_name="apikey", name="key_prefix", field=models.CharField(blank=True, db_index=True, max_length=24, null=True)),
        migrations.AddField(model_name="apikey", name="key_hash", field=models.CharField(blank=True, max_length=256, null=True, unique=True)),
        migrations.AddField(model_name="apikey", name="last_used_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="apikey", name="revoked_at", field=models.DateTimeField(blank=True, null=True)),
    ]
