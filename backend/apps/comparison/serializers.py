from rest_framework import serializers

from .models import Comparison, PQCAlgorithm, PQCRecommendation


class PQCAlgorithmSerializer(serializers.ModelSerializer):
    class Meta:
        model = PQCAlgorithm
        fields = "__all__"


class RecommendationSerializer(serializers.ModelSerializer):
    class Meta:
        model = PQCRecommendation
        fields = "__all__"


class ComparisonSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comparison
        fields = "__all__"

