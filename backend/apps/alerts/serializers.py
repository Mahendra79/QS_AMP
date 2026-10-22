from rest_framework import serializers

from .models import Alert


class AlertSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True, default="")
    assigned_to_email = serializers.CharField(source="assigned_to.email", read_only=True, default="")

    class Meta:
        model = Alert
        fields = "__all__"
        read_only_fields = ("organization", "acknowledged_at", "resolved_at")

