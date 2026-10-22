from rest_framework import serializers

from .models import RiskAssessment, RiskFactor, RiskFinding
from .risk_service import FINDING_STATUSES


class RiskAssessmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskAssessment
        fields = "__all__"


class RiskFindingSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True)
    algorithm = serializers.CharField(source="asset.algorithm", read_only=True)
    purpose = serializers.CharField(source="asset.purpose", read_only=True)
    application = serializers.CharField(source="asset.application", read_only=True)

    class Meta:
        model = RiskFinding
        fields = "__all__"


class RiskFindingTriageSerializer(serializers.ModelSerializer):
    """Only the triage status of a finding is editable; everything else is derived."""
    status = serializers.ChoiceField(choices=FINDING_STATUSES)

    class Meta:
        model = RiskFinding
        fields = ("status",)


class RiskFactorSerializer(serializers.ModelSerializer):
    weight = serializers.FloatField(min_value=0, max_value=100)

    class Meta:
        model = RiskFactor
        fields = "__all__"
        read_only_fields = ("organization", "key", "label", "description")

