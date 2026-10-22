from django.conf import settings
from django.db import models

from apps.organizations.models import OrgOwned

PHASES = ["inventory", "assessment", "planning", "hybrid", "pqc", "verification", "decommission"]
STATUSES = ["backlog", "planned", "in_progress", "testing", "verified", "completed"]


class MigrationProject(OrgOwned):
    name = models.CharField(max_length=200)
    status = models.CharField(max_length=20, default="active")
    current_phase = models.CharField(max_length=20, default="inventory")
    target_date = models.DateField(null=True, blank=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]


class MigrationTask(OrgOwned):
    project = models.ForeignKey(MigrationProject, on_delete=models.CASCADE, related_name="tasks")
    asset = models.ForeignKey("inventory.CryptoAsset", null=True, blank=True, on_delete=models.SET_NULL,
                              related_name="migration_tasks")
    title = models.CharField(max_length=300)
    current_algorithm = models.CharField(max_length=80)
    target_algorithm = models.CharField(max_length=80, blank=True)   # a recommendation *candidate*, not a mandate
    migration_path = models.JSONField(default=list, blank=True)       # e.g. ["Classical", "Hybrid", "PQC"]
    purpose = models.CharField(max_length=40, blank=True)
    risk_level = models.CharField(max_length=10, default="medium")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    owner_name = models.CharField(max_length=120, blank=True)
    status = models.CharField(max_length=20, default="backlog", db_index=True)
    phase = models.CharField(max_length=20, default="planning")
    due_date = models.DateField(null=True, blank=True)
    rollback_strategy = models.TextField(blank=True)
    validation = models.TextField(blank=True)
    priority = models.IntegerField(default=3)
    effort_days = models.IntegerField(default=5)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["priority", "due_date", "title"]


class MigrationDependency(OrgOwned):
    task = models.ForeignKey(MigrationTask, on_delete=models.CASCADE, related_name="dependencies")
    depends_on = models.ForeignKey(MigrationTask, on_delete=models.CASCADE, related_name="blocking")

    class Meta:
        unique_together = ("task", "depends_on")
