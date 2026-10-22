from django.db import migrations


def refresh_source_counts(apps, schema_editor):
    AssetSource = apps.get_model("discovery", "AssetSource")
    for source in AssetSource.objects.all():
        count = source.assets.count()
        source.asset_count = count
        if count == 0 and not source.is_demo:
            source.risk_score = 0
            source.risk_level = "safe"
            if source.source_type == "website":
                source.status = "pending"
        source.save(update_fields=["asset_count", "risk_score", "risk_level", "status"])


class Migration(migrations.Migration):
    dependencies = [("discovery", "0002_remove_legacy_baselines")]
    operations = [migrations.RunPython(refresh_source_counts, migrations.RunPython.noop)]
