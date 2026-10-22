from django.db import models

from apps.organizations.models import OrgOwned


class MonitoringConfiguration(OrgOwned):
    enabled = models.BooleanField(default=False)
    frequency_hours = models.IntegerField(default=24)
    last_scan_at = models.DateTimeField(null=True, blank=True)
    next_scan_at = models.DateTimeField(null=True, blank=True)
    notify_on = models.JSONField(default=list, blank=True)
    simulated = models.BooleanField(default=False)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization"], name="one_monitoring_config_per_org")]


class MonitoringEvent(OrgOwned):
    source = models.ForeignKey("discovery.AssetSource", null=True, blank=True, on_delete=models.SET_NULL,
                               related_name="monitoring_events")
    event_type = models.CharField(max_length=30, db_index=True)  # crypto_change|certificate_change|new_dependency|new_algorithm|risk_change
    title = models.CharField(max_length=300)
    detail = models.TextField(blank=True)
    severity = models.CharField(max_length=15, default="info")
    occurred_at = models.DateTimeField(db_index=True)
    is_simulated = models.BooleanField(default=False)

    class Meta:
        ordering = ["-occurred_at"]
