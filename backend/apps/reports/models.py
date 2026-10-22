from django.conf import settings
from django.db import models

from apps.organizations.models import OrgOwned


def report_path(instance, filename):
    return f"reports/{instance.organization_id}/{filename}"


class Report(OrgOwned):
    report_type = models.CharField(max_length=40)
    file_format = models.CharField(max_length=10)  # pdf | json | csv
    title = models.CharField(max_length=250)
    status = models.CharField(max_length=15, default="ready")  # ready | failed
    file = models.FileField(upload_to=report_path, null=True, blank=True)
    size_bytes = models.IntegerField(default=0)
    params = models.JSONField(default=dict, blank=True)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    is_demo = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]
