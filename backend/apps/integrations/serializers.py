from rest_framework import serializers

from .models import Integration


class IntegrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Integration
        fields = "__all__"
        read_only_fields = ("organization", "status", "is_mock", "connected_at")

