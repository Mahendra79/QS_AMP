from rest_framework import serializers

from apps.organizations.mixins import OrgReadOnlyViewSet
from apps.organizations.models import ADMIN_ROLES, Role

from .models import AuditLog


class AuditSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source="user.email", read_only=True, default=None)

    class Meta:
        model = AuditLog
        fields = ("id", "action", "object_type", "object_id", "object_repr", "user_email", "ip_address", "created_at")


class AuditViewSet(OrgReadOnlyViewSet):
    queryset = AuditLog.objects.select_related("user")
    serializer_class = AuditSerializer
    read_roles = ADMIN_ROLES + (Role.AUDITOR,)
    write_roles = ()
    filterset_fields = ["action", "object_type"]
