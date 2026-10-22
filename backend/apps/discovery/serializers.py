from rest_framework import serializers

from .models import AssetSource, ScanJob, ScanResult


class AssetSourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssetSource
        fields = ("id", "name", "source_type", "target", "branch", "options", "environment", "upload",
                  "monitoring_enabled", "status", "last_scan_at", "asset_count", "risk_score", "risk_level",
                  "is_demo", "created_at")
        read_only_fields = ("id", "status", "last_scan_at", "asset_count", "risk_score", "risk_level", "is_demo", "created_at")

    def validate(self, attrs):
        if self.instance is not None:
            # A source's kind and uploaded content are fixed at creation: changing
            # them would bypass upload validation and orphan the collected evidence.
            if "source_type" in attrs and attrs["source_type"] != self.instance.source_type:
                raise serializers.ValidationError({"source_type": "The source type cannot be changed; add a new source."})
            if "upload" in attrs:
                raise serializers.ValidationError({"upload": "Upload a new ZIP by adding a new source."})
            if self.instance.source_type == "zip" and attrs.get("target", self.instance.target) != self.instance.target:
                raise serializers.ValidationError({"target": "The archive name of a ZIP source cannot be changed."})
        source_type = attrs.get("source_type", getattr(self.instance, "source_type", None))
        upload = attrs.get("upload")
        if source_type == "zip" and upload is None and self.instance is None:
            raise serializers.ValidationError({"upload": "A ZIP file is required."})
        target = attrs.get("target", getattr(self.instance, "target", ""))
        if source_type in ("website", "public_repo", "github") and not target:
            raise serializers.ValidationError({"target": "A URL or repository is required."})
        return attrs


class ScanJobSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True)
    duration_seconds = serializers.FloatField(read_only=True)

    class Meta:
        model = ScanJob
        fields = ("id", "source", "source_name", "status", "stage", "stage_index", "progress", "counters",
                  "stages", "error", "mode", "started_at", "finished_at", "duration_seconds", "created_at")


class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = ("id", "result_type", "data", "created_at")

