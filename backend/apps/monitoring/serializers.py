from rest_framework import serializers

from .models import MonitoringConfiguration, MonitoringEvent


class MonitoringConfigurationSerializer(serializers.ModelSerializer):
    # 1 hour .. 30 days. 0 or a negative value would make every scheduler tick a scan.
    frequency_hours = serializers.IntegerField(min_value=1, max_value=720, required=False)
    notify_on = serializers.ListField(child=serializers.CharField(max_length=40), required=False, max_length=20)

    class Meta:
        model = MonitoringConfiguration
        fields = "__all__"
        # `simulated` is decided by whether the workspace is a demo workspace, not by users.
        read_only_fields = ("organization", "last_scan_at", "next_scan_at", "simulated")


class MonitoringEventSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True, default="")

    class Meta:
        model = MonitoringEvent
        fields = "__all__"

