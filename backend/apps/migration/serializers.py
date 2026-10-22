from rest_framework import serializers

from .migration_service import DONE_STATUSES, target_problem
from .models import PHASES, STATUSES, MigrationDependency, MigrationProject, MigrationTask


class MigrationProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = MigrationProject
        fields = "__all__"
        read_only_fields = ("organization",)


class MigrationTaskSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True, default="")
    owner_username = serializers.CharField(source="owner.username", read_only=True, default="")
    status = serializers.ChoiceField(choices=STATUSES, required=False)
    phase = serializers.ChoiceField(choices=PHASES, required=False)
    priority = serializers.IntegerField(min_value=1, max_value=5, required=False)
    effort_days = serializers.IntegerField(min_value=0, max_value=3650, required=False)

    class Meta:
        model = MigrationTask
        fields = "__all__"
        read_only_fields = ("organization",)

    def validate(self, attrs):
        instance = self.instance
        target = attrs.get("target_algorithm", getattr(instance, "target_algorithm", ""))
        asset = attrs.get("asset", getattr(instance, "asset", None))
        purpose = attrs.get("purpose", getattr(instance, "purpose", "")) or (asset.purpose if asset else "")
        status = attrs.get("status", getattr(instance, "status", "backlog"))
        if "target_algorithm" in attrs or status in DONE_STATUSES:
            problem = target_problem(target, purpose)
            if problem:
                raise serializers.ValidationError({"target_algorithm": problem})
        return attrs


class MigrationDependencySerializer(serializers.ModelSerializer):
    class Meta:
        model = MigrationDependency
        fields = "__all__"
        read_only_fields = ("organization",)
