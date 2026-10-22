from django.db import models

from apps.organizations.models import OrgOwned


class Integration(OrgOwned):
    """Integration record. In the MVP connectors are mocks (is_mock=True); real
    OAuth/API flows can replace `connect()` in integration_service later."""
    provider = models.CharField(max_length=30)  # github|gitlab|bitbucket|aws|azure|gcp|servicenow|slack|webhook
    category = models.CharField(max_length=20)  # scm|cloud|ticketing|notification
    status = models.CharField(max_length=20, default="disconnected")
    config = models.JSONField(default=dict, blank=True)  # non-secret settings only
    is_mock = models.BooleanField(default=True)
    connected_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("organization", "provider")
        ordering = ["category", "provider"]
