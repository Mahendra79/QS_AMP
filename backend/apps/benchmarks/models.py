from django.conf import settings
from django.db import models

from apps.organizations.models import OrgOwned


class DataSource(models.TextChoices):
    MEASURED = "measured", "Measured on this environment"
    DEMO = "demo", "Demo benchmark"


class BenchmarkRun(OrgOwned):
    name = models.CharField(max_length=200)
    status = models.CharField(max_length=20, default="completed")  # running | completed | failed
    algorithms = models.JSONField(default=list)
    operations = models.JSONField(default=list)
    iterations = models.IntegerField(default=20)
    platform = models.CharField(max_length=120, blank=True)
    cpu = models.CharField(max_length=200, blank=True)
    os = models.CharField(max_length=120, blank=True)
    compiler = models.CharField(max_length=120, blank=True)
    adapter = models.CharField(max_length=60, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]


class BenchmarkResult(OrgOwned):
    """One (algorithm, operation) measurement. `data_source` is never mixed."""
    run = models.ForeignKey(BenchmarkRun, on_delete=models.CASCADE, related_name="results")
    algorithm = models.CharField(max_length=80, db_index=True)
    version = models.CharField(max_length=60, blank=True)
    platform = models.CharField(max_length=120, blank=True)
    cpu = models.CharField(max_length=200, blank=True)
    os = models.CharField(max_length=120, blank=True)
    library = models.CharField(max_length=160, blank=True)
    compiler = models.CharField(max_length=120, blank=True)
    operation = models.CharField(max_length=30)  # keygen|encapsulation|decapsulation|sign|verify
    iterations = models.IntegerField()
    median = models.FloatField(help_text="milliseconds")
    mean = models.FloatField()
    min = models.FloatField()
    max = models.FloatField()
    memory_kb = models.FloatField(null=True, blank=True)
    throughput_ops = models.FloatField(null=True, blank=True)
    latency_ms = models.FloatField(null=True, blank=True)
    data_source = models.CharField(max_length=10, choices=DataSource.choices)
    notes = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
