from django.db import migrations, models


LEGACY_ALGORITHMS = ["TLS 1.3", "ECDH-P256", "ECDSA-P256", "AES-256-GCM", "SHA-256"]


def remove_legacy_baselines(apps, schema_editor):
    AssetSource = apps.get_model("discovery", "AssetSource")
    CryptoAsset = apps.get_model("inventory", "CryptoAsset")
    ScanResult = apps.get_model("discovery", "ScanResult")
    source_ids = AssetSource.objects.filter(source_type="website", is_demo=False).values_list("id", flat=True)
    CryptoAsset.objects.filter(source_id__in=source_ids, algorithm__in=LEGACY_ALGORITHMS, metadata={}).delete()
    ScanResult.objects.filter(result_type="tls", data__mode="baseline").delete()


class Migration(migrations.Migration):
    dependencies = [("discovery", "0001_initial"), ("inventory", "0001_initial")]
    operations = [
        migrations.AlterField(model_name="scanjob", name="mode", field=models.CharField(default="evidence", max_length=20)),
        migrations.RunPython(remove_legacy_baselines, migrations.RunPython.noop),
    ]
