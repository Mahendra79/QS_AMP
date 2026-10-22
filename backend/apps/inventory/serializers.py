from rest_framework import serializers

from .models import CryptoAlgorithm, CryptoAsset, CryptoCertificate, CryptoKey, CryptoLibrary, CryptoProtocol


class CryptoAssetSerializer(serializers.ModelSerializer):
    source_name = serializers.CharField(source="source.name", read_only=True, default="")
    certificate_subject = serializers.CharField(source="certificate.subject", read_only=True, default="")

    class Meta:
        model = CryptoAsset
        fields = "__all__"
        read_only_fields = ("organization", "asset_ref", "risk_score", "risk_level", "quantum_status",
                            "pqc_candidates", "first_seen", "last_seen", "created_at", "updated_at")


class CryptoAlgorithmSerializer(serializers.ModelSerializer):
    class Meta:
        model = CryptoAlgorithm
        fields = "__all__"


class CryptoCertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CryptoCertificate
        fields = "__all__"
        read_only_fields = ("organization",)


class CryptoLibrarySerializer(serializers.ModelSerializer):
    class Meta:
        model = CryptoLibrary
        fields = "__all__"
        read_only_fields = ("organization",)


class CryptoKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = CryptoKey
        fields = "__all__"
        read_only_fields = ("organization",)


class CryptoProtocolSerializer(serializers.ModelSerializer):
    class Meta:
        model = CryptoProtocol
        fields = "__all__"
        read_only_fields = ("organization",)

