from rest_framework import serializers

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    generated_by_email = serializers.CharField(source="generated_by.email", read_only=True, default="")
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = "__all__"
        read_only_fields = ("organization", "status", "file", "size_bytes", "generated_by", "is_demo")

    def get_download_url(self, obj):
        return f"/api/reports/{obj.id}/download/" if obj.file else None

