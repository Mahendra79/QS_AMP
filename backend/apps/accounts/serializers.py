from django.contrib.auth import password_validation
from rest_framework import serializers

from .models import APIKey, User


class RegisterSerializer(serializers.Serializer):
    username = serializers.RegexField(r"^[A-Za-z0-9_.-]+$", max_length=80)
    password = serializers.CharField(write_only=True)
    full_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    organization_name = serializers.CharField(max_length=200)

    def validate_username(self, value):
        value = value.lower()
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("That username is already in use.")
        return value

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=254, required=False, allow_blank=True)
    email = serializers.EmailField(required=False, write_only=True)
    password = serializers.CharField()
    otp = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        identifier = (attrs.get("username") or attrs.get("email") or "").strip().lower()
        if not identifier:
            raise serializers.ValidationError({"username": "Username is required."})
        attrs["identifier"] = identifier
        return attrs


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "full_name", "mfa_enabled", "date_joined")
        read_only_fields = ("id", "username", "mfa_enabled", "date_joined")


class APIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = APIKey
        fields = ("id", "name", "prefix", "created_at", "last_used_at", "revoked")
        read_only_fields = ("id", "prefix", "created_at", "last_used_at", "revoked")
