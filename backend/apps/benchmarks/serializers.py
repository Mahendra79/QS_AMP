from rest_framework import serializers

from .models import BenchmarkResult, BenchmarkRun


class BenchmarkResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = BenchmarkResult
        fields = "__all__"


class BenchmarkRunSerializer(serializers.ModelSerializer):
    results = BenchmarkResultSerializer(many=True, read_only=True)

    class Meta:
        model = BenchmarkRun
        fields = "__all__"

