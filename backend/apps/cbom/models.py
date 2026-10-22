from django.db import models

from apps.organizations.models import OrgOwned


def cbom_upload_path(instance, filename):
    import uuid
    return f"cbom/{instance.organization_id}/{uuid.uuid4().hex}/{filename}"


class CBOMDocument(OrgOwned):
    name = models.CharField(max_length=200)
    source = models.ForeignKey("discovery.AssetSource", null=True, blank=True, on_delete=models.SET_NULL,
                               related_name="cbom_documents")
    origin = models.CharField(max_length=20, default="generated")  # generated | uploaded
    spec_format = models.CharField(max_length=30, default="CycloneDX")
    spec_version = models.CharField(max_length=10, default="1.6")
    serial_number = models.CharField(max_length=80, blank=True)
    file_format = models.CharField(max_length=10, default="json")
    raw = models.JSONField(default=dict, blank=True)  # normalised CycloneDX-style BOM
    file = models.FileField(upload_to=cbom_upload_path, null=True, blank=True)
    validation = models.JSONField(default=dict, blank=True)
    component_count = models.IntegerField(default=0)
    is_demo = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]


class CBOMComponent(OrgOwned):
    document = models.ForeignKey(CBOMDocument, on_delete=models.CASCADE, related_name="components")
    bom_ref = models.CharField(max_length=200)
    component_type = models.CharField(max_length=40)   # application | library | cryptographic-asset | file
    asset_type = models.CharField(max_length=30, blank=True)  # algorithm | key | certificate | protocol | library | application | file
    name = models.CharField(max_length=300)
    version = models.CharField(max_length=60, blank=True)
    crypto_properties = models.JSONField(default=dict, blank=True)
    risk_level = models.CharField(max_length=10, default="safe")
    asset = models.ForeignKey("inventory.CryptoAsset", null=True, blank=True, on_delete=models.SET_NULL,
                              related_name="cbom_components")

    class Meta:
        unique_together = ("document", "bom_ref")
        ordering = ["asset_type", "name"]


class CBOMDependency(OrgOwned):
    document = models.ForeignKey(CBOMDocument, on_delete=models.CASCADE, related_name="dependencies")
    source_ref = models.CharField(max_length=200)
    target_ref = models.CharField(max_length=200)
    relation = models.CharField(max_length=30, default="depends_on")  # uses|implements|depends_on|protects|communicates_with
