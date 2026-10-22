from django.conf import settings
from django.db import models

from apps.organizations.models import Environment, OrgOwned


class SourceType(models.TextChoices):
    WEBSITE = "website", "Website / Domain"
    ZIP = "zip", "Source Code ZIP"
    GITHUB = "github", "GitHub Repository"
    PUBLIC_REPO = "public_repo", "Public Repository"
    CBOM = "cbom", "CBOM Upload"


def upload_path(instance, filename):
    # Stored under MEDIA_ROOT/<org>/<source>/, never under the served source tree.
    import uuid
    return f"uploads/{instance.organization_id}/{uuid.uuid4().hex}/{filename}"


class AssetSource(OrgOwned):
    name = models.CharField(max_length=200)
    source_type = models.CharField(max_length=20, choices=SourceType.choices)
    target = models.CharField(max_length=500, help_text="URL, repository or file name")
    branch = models.CharField(max_length=120, blank=True)
    options = models.JSONField(default=dict, blank=True)
    environment = models.ForeignKey(Environment, null=True, blank=True, on_delete=models.SET_NULL, related_name="sources")
    upload = models.FileField(upload_to=upload_path, null=True, blank=True)
    monitoring_enabled = models.BooleanField(default=False)
    status = models.CharField(max_length=20, default="pending")  # pending|scanning|active|error
    last_scan_at = models.DateTimeField(null=True, blank=True)
    asset_count = models.IntegerField(default=0)
    risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=10, default="safe")
    is_demo = models.BooleanField(default=False)

    class Meta:
        unique_together = ("organization", "source_type", "target")
        ordering = ["-created_at"]

    def __str__(self):
        return self.name


class ScanJob(OrgOwned):
    source = models.ForeignKey(AssetSource, on_delete=models.CASCADE, related_name="scans")
    status = models.CharField(max_length=20, default="queued")  # queued|running|completed|failed
    stage = models.CharField(max_length=80, blank=True)
    stage_index = models.IntegerField(default=0)
    progress = models.IntegerField(default=0)
    counters = models.JSONField(default=dict, blank=True)
    stages = models.JSONField(default=list, blank=True)
    error = models.TextField(blank=True)
    mode = models.CharField(max_length=20, default="evidence")  # evidence | simulated
    triggered_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def duration_seconds(self):
        if self.started_at and self.finished_at:
            return round((self.finished_at - self.started_at).total_seconds(), 1)
        return None


class ScanResult(OrgOwned):
    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="results")
    result_type = models.CharField(max_length=40)  # tls | dependencies | code | cbom | summary
    data = models.JSONField(default=dict, blank=True)
