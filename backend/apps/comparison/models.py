from django.conf import settings
from django.db import models

from apps.inventory.models import AlgorithmBase
from apps.organizations.models import OrgOwned


class PQCAlgorithm(AlgorithmBase):
    """Post-quantum algorithm parameter sets with *specification* data (FIPS 203/204/205)."""
    security_level_bits = models.IntegerField(null=True, blank=True)  # classical-equivalent bits (informative)
    nist_category = models.IntegerField(null=True, blank=True)
    implementation_maturity = models.CharField(max_length=60, blank=True)
    shared_secret_size = models.IntegerField(null=True, blank=True)


class PQCRecommendation(OrgOwned):
    asset = models.ForeignKey("inventory.CryptoAsset", on_delete=models.CASCADE, related_name="recommendations")
    candidate = models.CharField(max_length=80)
    rank = models.IntegerField(default=1)
    reason = models.TextField(blank=True)
    security_level = models.CharField(max_length=80, blank=True)
    tradeoffs = models.JSONField(default=list, blank=True)
    benchmark_required = models.BooleanField(default=True)
    migration_notes = models.TextField(blank=True)

    class Meta:
        ordering = ["asset_id", "rank"]


class Comparison(OrgOwned):
    asset = models.ForeignKey("inventory.CryptoAsset", null=True, blank=True, on_delete=models.SET_NULL,
                              related_name="comparisons")
    classical_algorithm = models.CharField(max_length=80)
    candidates = models.JSONField(default=list)
    purpose = models.CharField(max_length=40)
    environment = models.CharField(max_length=80, blank=True)
    result = models.JSONField(default=dict)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-created_at"]
