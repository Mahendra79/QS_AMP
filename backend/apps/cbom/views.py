from django.http import HttpResponse
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.discovery.models import AssetSource, SourceType
from apps.organizations.errors import ServiceError
from apps.organizations.mixins import OrgReadOnlyViewSet

from .cbom_service import (export_document, generate_for_org, graph, import_assets_from_document, parse_bytes,
                           read_upload, refresh_component_risks, store_document, validate_bom)
from .models import CBOMDocument
from .serializers import CBOMDocumentDetailSerializer, CBOMDocumentSerializer


class CBOMViewSet(OrgReadOnlyViewSet):
    queryset = CBOMDocument.objects.select_related("source")
    serializer_class = CBOMDocumentSerializer

    def get_serializer_class(self):
        return CBOMDocumentDetailSerializer if self.action == "retrieve" else CBOMDocumentSerializer

    @action(detail=False, methods=["post"])
    def generate(self, request):
        source = None
        if request.data.get("source"):
            source = AssetSource.objects.filter(organization=request.org, pk=request.data["source"]).first()
            if not source:
                raise ServiceError("not_found", "Source not found.", 404)
        doc = generate_for_org(request.org, source=source, name=request.data.get("name"), is_demo=request.org.is_demo)
        return Response(CBOMDocumentSerializer(doc).data, status=201)

    @action(detail=False, methods=["post"])
    def upload(self, request):
        upload = request.FILES.get("file")
        if not upload:
            raise ServiceError("validation_error", "A CBOM JSON or XML file is required.")
        data = read_upload(upload, 10 * 1024 * 1024)
        bom, fmt = parse_bytes(data, upload.name)
        validation = validate_bom(bom)
        if not validation.get("valid"):
            raise ServiceError("invalid_cbom", "; ".join(validation.get("errors", [])))
        source, _ = AssetSource.objects.get_or_create(
            organization=request.org, source_type=SourceType.CBOM, target=upload.name,
            defaults={"name": upload.name, "status": "active", "is_demo": request.org.is_demo})
        doc = store_document(request.org, bom, request.data.get("name") or upload.name, source=source,
                             origin="uploaded", file_format=fmt, validation=validation, upload=upload,
                             is_demo=request.org.is_demo)
        imported = import_assets_from_document(request.org, doc, source)
        source.asset_count = source.assets.count()
        source.save(update_fields=["asset_count", "updated_at"])
        if source.asset_count:
            # Imported (and re-imported, updated) assets must be scored before they are
            # shown - otherwise they sit at risk 0 / "safe" until someone runs an assessment.
            from apps.risk.risk_service import assess_organization
            assess_organization(request.org)
            refresh_component_risks(doc)
        return Response({**CBOMDocumentSerializer(doc).data, "assets_imported": imported}, status=201)

    @action(detail=True, methods=["get"])
    def graph(self, request, pk=None):
        return Response(graph(self.get_object()))

    @action(detail=True, methods=["get"], url_path="export/(?P<fmt>json|xml)")
    def export(self, request, pk=None, fmt="json"):
        content, content_type, filename = export_document(self.get_object(), fmt)
        response = HttpResponse(content, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @action(detail=True, methods=["post"])
    def validate(self, request, pk=None):
        doc = self.get_object()
        doc.validation = validate_bom(doc.raw)
        doc.save(update_fields=["validation", "updated_at"])
        return Response(doc.validation)

