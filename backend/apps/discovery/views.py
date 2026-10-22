from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.organizations.errors import ServiceError
from apps.organizations.mixins import OrgModelViewSet, OrgReadOnlyViewSet

from .discovery_service import create_scan
from .models import AssetSource, ScanJob
from .safe_zip import validate_zip_upload
from .serializers import AssetSourceSerializer, ScanJobSerializer, ScanResultSerializer


class AssetSourceViewSet(OrgModelViewSet):
    queryset = AssetSource.objects.select_related("environment")
    serializer_class = AssetSourceSerializer
    filterset_fields = ["source_type", "status", "monitoring_enabled"]

    def perform_create(self, serializer):
        data = serializer.validated_data
        upload = data.get("upload")
        target = (data.get("target") or "").strip()
        if data.get("source_type") == "zip":
            validate_zip_upload(upload)
            # Re-uploading an archive with the same file name is a new source, not a conflict.
            target = self._unique_target(data["source_type"], target or upload.name)
        elif AssetSource.objects.filter(organization=self.request.org, source_type=data.get("source_type"),
                                        target=target).exists():
            raise ServiceError("source_exists", "This source is already connected; scan it from Discovery.", 409)
        source = serializer.save(organization=self.request.org, is_demo=self.request.org.is_demo, target=target)
        self.after_create(source)
        self.created_source = source

    def _unique_target(self, source_type, target):
        existing = set(AssetSource.objects.filter(organization=self.request.org, source_type=source_type,
                                                  target__startswith=target).values_list("target", flat=True))
        candidate, n = target, 1
        while candidate in existing:
            n += 1
            candidate = f"{target} ({n})"
        return candidate[:500]

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        job = create_scan(self.created_source, request.user)
        response.data["scan_job"] = ScanJobSerializer(job).data
        return response

    @action(detail=True, methods=["post"])
    def scan(self, request, pk=None):
        source = self.get_object()  # create_scan atomically rejects a concurrent scan with 409
        return Response(ScanJobSerializer(create_scan(source, request.user)).data, status=status.HTTP_202_ACCEPTED)

    def perform_destroy(self, instance):
        had_assets = instance.assets.exists()
        super().perform_destroy(instance)
        if had_assets:
            # Deleting a source cascades to delete its CryptoAssets - the org-wide
            # RiskAssessment snapshot and the dependency graph must drop them too.
            from apps.risk.risk_service import assess_organization
            assess_organization(self.request.org)


class ScanJobViewSet(OrgReadOnlyViewSet):
    queryset = ScanJob.objects.select_related("source")
    serializer_class = ScanJobSerializer
    filterset_fields = ["status", "source"]

    @action(detail=True, methods=["get"])
    def results(self, request, pk=None):
        return Response(ScanResultSerializer(self.get_object().results.all(), many=True).data)

