from django.conf import settings
from django.db import models

from apps.organizations.models import OrgOwned


class Alert(OrgOwned):
    severity = models.CharField(max_length=15, db_index=True)  # critical|high|medium|low|info
    alert_type = models.CharField(max_length=40, db_index=True)
    title = models.CharField(max_length=300)
    message = models.TextField(blank=True)
    status = models.CharField(max_length=15, default="open", db_index=True)  # open|acknowledged|resolved|muted
    asset = models.ForeignKey("inventory.CryptoAsset", null=True, blank=True, on_delete=models.SET_NULL, related_name="alerts")
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name="assigned_alerts")
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
