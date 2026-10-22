from django.db.models import Count, Q
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.comparison.comparison_service import persist_recommendations
from apps.organizations.mixins import OrgModelViewSet, OrgReadOnlyViewSet

from .architecture_service import graph, rebuild_architecture
from .models import CryptoAlgorithm, CryptoAsset, CryptoCertificate, CryptoKey, CryptoLibrary, CryptoProtocol
from .serializers import (CryptoAlgorithmSerializer, CryptoAssetSerializer, CryptoCertificateSerializer,
                          CryptoKeySerializer, CryptoLibrarySerializer, CryptoProtocolSerializer)


class AssetViewSet(OrgModelViewSet):
    queryset = CryptoAsset.objects.select_related("source", "certificate", "key").prefetch_related("depends_on")
    serializer_class = CryptoAssetSerializer
    filterset_fields = ["algorithm", "primitive", "asset_type", "purpose", "risk_level", "application",
                        "environment", "source", "quantum_status"]
    search_fields = ["asset_ref", "name", "algorithm", "application", "source_location", "library"]

    def get_queryset(self):
        qs = super().get_queryset()
        q = self.request.query_params.get("search")
        if q:
            qs = qs.filter(Q(name__icontains=q) | Q(algorithm__icontains=q) | Q(application__icontains=q) |
                           Q(source_location__icontains=q) | Q(library__icontains=q))
        return qs

    def perform_update(self, serializer):
        super().perform_update(serializer)
        # Any field here can feed risk_score/quantum_status (algorithm, key size,
        # business_criticality, internet_exposed, ...) - re-score rather than leave
        # this asset (and the org aggregate) showing a now-inaccurate cached value.
        from apps.risk.risk_service import assess_organization
        assess_organization(self.request.org)

    def perform_destroy(self, instance):
        super().perform_destroy(instance)
        from apps.risk.risk_service import assess_organization
        assess_organization(self.request.org)

    @action(detail=True, methods=["post"])
    def recommend(self, request, pk=None):
        return Response(persist_recommendations(self.get_object(), request.org))

    @action(detail=False, methods=["get"])
    def facets(self, request):
        qs = CryptoAsset.objects.filter(organization=request.org)
        keys = ("algorithm", "primitive", "asset_type", "purpose", "risk_level", "application", "environment", "quantum_status")
        return Response({key: list(qs.exclude(**{key: ""}).values_list(key, flat=True).distinct().order_by(key)) for key in keys})

    @action(detail=False, methods=["get"])
    def summary(self, request):
        qs = CryptoAsset.objects.filter(organization=request.org)
        return Response({"total": qs.count(), "by_risk": list(qs.values("risk_level").annotate(count=Count("id"))),
                         "by_algorithm": list(qs.values("algorithm").annotate(count=Count("id")).order_by("-count")[:12])})


class AlgorithmViewSet(OrgReadOnlyViewSet):
    queryset = CryptoAlgorithm.objects.all()
    serializer_class = CryptoAlgorithmSerializer

    def get_queryset(self):
        return CryptoAlgorithm.objects.all()


class CertificateViewSet(OrgReadOnlyViewSet):
    queryset = CryptoCertificate.objects.all()
    serializer_class = CryptoCertificateSerializer


class LibraryViewSet(OrgReadOnlyViewSet):
    queryset = CryptoLibrary.objects.all()
    serializer_class = CryptoLibrarySerializer


class KeyViewSet(OrgReadOnlyViewSet):
    queryset = CryptoKey.objects.all()
    serializer_class = CryptoKeySerializer


class ProtocolViewSet(OrgReadOnlyViewSet):
    queryset = CryptoProtocol.objects.all()
    serializer_class = CryptoProtocolSerializer


from rest_framework.views import APIView
from apps.organizations.permissions import RolePermission


class ArchitectureView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        # Read-only: the graph is rebuilt by every reassessment (scans, imports,
        # migrations, edits) and on demand via POST - never as a side effect of viewing.
        return Response(graph(request.org))

    def post(self, request):
        rebuild_architecture(request.org)
        return Response(graph(request.org))

