from rest_framework import serializers

from .cbom_service import is_stale
from .models import CBOMComponent, CBOMDependency, CBOMDocument


class CBOMComponentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CBOMComponent
        fields = "__all__"


class CBOMDependencySerializer(serializers.ModelSerializer):
    class Meta:
        model = CBOMDependency
        fields = "__all__"


class CBOMDocumentSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True, default="")
    is_stale = serializers.SerializerMethodField()

    class Meta:
        model = CBOMDocument
        fields = ("id", "name", "source", "source_name", "origin", "spec_format", "spec_version", "serial_number",
                  "file_format", "validation", "component_count", "is_demo", "is_stale", "created_at", "updated_at")

    def get_is_stale(self, obj):
        return is_stale(obj)


class CBOMDocumentDetailSerializer(CBOMDocumentSerializer):
    components = CBOMComponentSerializer(many=True, read_only=True)
    dependencies = CBOMDependencySerializer(many=True, read_only=True)
    raw = serializers.JSONField(read_only=True)

    class Meta(CBOMDocumentSerializer.Meta):
        fields = CBOMDocumentSerializer.Meta.fields + ("raw", "components", "dependencies")

