from rest_framework import serializers

from apps.accounts.serializers import UserSerializer

from .models import Environment, Organization, OrganizationMembership


class EnvironmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Environment
        fields = ("id", "name", "kind", "is_default")


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ("id", "name", "slug", "plan", "is_demo", "created_at")
        read_only_fields = ("id", "slug", "plan", "is_demo", "created_at")


class MembershipSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = OrganizationMembership
        fields = ("id", "user", "role", "created_at")

