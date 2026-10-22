from django.db import models

from apps.organizations.models import OrgOwned


class RiskFactor(OrgOwned):
    """Configurable scoring factor (weight + description) per organization."""
    key = models.CharField(max_length=60)
    label = models.CharField(max_length=120)
    weight = models.FloatField(default=10)
    enabled = models.BooleanField(default=True)
    description = models.TextField(blank=True)

    class Meta:
        unique_together = ("organization", "key")
        ordering = ["-weight", "key"]


class RiskAssessment(OrgOwned):
    overall_score = models.IntegerField(default=0)
    level = models.CharField(max_length=10, default="safe")
    counts = models.JSONField(default=dict, blank=True)
    factor_averages = models.JSONField(default=dict, blank=True)
    config_snapshot = models.JSONField(default=dict, blank=True)
    asset_count = models.IntegerField(default=0)

    class Meta:
        ordering = ["-created_at"]


class RiskFinding(OrgOwned):
    assessment = models.ForeignKey(RiskAssessment, null=True, blank=True, on_delete=models.SET_NULL, related_name="findings")
    asset = models.ForeignKey("inventory.CryptoAsset", on_delete=models.CASCADE, related_name="findings")
    title = models.CharField(max_length=300)
    severity = models.CharField(max_length=10, db_index=True)
    score = models.IntegerField(default=0, db_index=True)
    reason = models.TextField(blank=True)
    recommended_action = models.TextField(blank=True)
    components = models.JSONField(default=list, blank=True)  # [{factor,label,score,weight,contribution,explanation}]
    status = models.CharField(max_length=20, default="open")

    class Meta:
        ordering = ["-score", "title"]
