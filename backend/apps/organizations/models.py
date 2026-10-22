import uuid

from django.conf import settings
from django.db import models


class Role(models.TextChoices):
    OWNER = "owner", "Owner"
    ADMIN = "admin", "Admin"
    ANALYST = "analyst", "Security Analyst"
    DEVELOPER = "developer", "Developer"
    AUDITOR = "auditor", "Auditor"
    VIEWER = "viewer", "Viewer"


WRITE_ROLES = (Role.OWNER, Role.ADMIN, Role.ANALYST, Role.DEVELOPER)
ADMIN_ROLES = (Role.OWNER, Role.ADMIN)


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=80, unique=True)
    plan = models.CharField(max_length=40, default="local")
    is_demo = models.BooleanField(default=False)
    settings = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class OrganizationMembership(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.VIEWER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("organization", "user")
        ordering = ["created_at"]


class OrgOwned(models.Model):
    """Abstract base: every organization-owned record has UUID pk + organization FK."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="%(app_label)s_%(class)s_set")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Environment(OrgOwned):
    name = models.CharField(max_length=80)
    kind = models.CharField(max_length=30, default="production")
    is_default = models.BooleanField(default=False)

    class Meta:
        unique_together = ("organization", "name")
        ordering = ["-is_default", "name"]

    def __str__(self):
        return self.name
