from django.db import migrations, models


def renumber_duplicate_refs(apps, schema_editor):
    """Refs used to be count()+1, so deletions produced duplicates. Give every
    duplicate after the first a fresh ref above the organization's highest one."""
    CryptoAsset = apps.get_model("inventory", "CryptoAsset")
    org_ids = CryptoAsset.objects.exclude(asset_ref="").values_list("organization_id", flat=True).distinct()
    for org_id in org_ids:
        rows = CryptoAsset.objects.filter(organization_id=org_id).exclude(asset_ref="").order_by("created_at", "id")
        highest = 0
        for ref in rows.values_list("asset_ref", flat=True):
            if ref.startswith("CA-") and ref[3:].isdigit():
                highest = max(highest, int(ref[3:]))
        seen = set()
        for asset in rows:
            if asset.asset_ref in seen:
                highest += 1
                asset.asset_ref = f"CA-{highest:06d}"
                asset.save(update_fields=["asset_ref"])
            seen.add(asset.asset_ref)


class Migration(migrations.Migration):
    dependencies = [("inventory", "0002_remove_inferred_architecture")]

    operations = [
        migrations.RunPython(renumber_duplicate_refs, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="cryptoasset",
            constraint=models.UniqueConstraint(condition=~models.Q(asset_ref=""), fields=("organization", "asset_ref"),
                                               name="unique_asset_ref_per_org"),
        ),
    ]
