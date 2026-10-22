from django.http import FileResponse
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.organizations.errors import ServiceError
from apps.organizations.mixins import OrgReadOnlyViewSet

from .models import Report
from .report_service import generate_report
from .serializers import ReportSerializer


class ReportViewSet(OrgReadOnlyViewSet):
    queryset = Report.objects.select_related("generated_by")
    serializer_class = ReportSerializer

    @action(detail=False, methods=["post"])
    def generate(self, request):
        row = generate_report(request.org, request.user, request.data.get("report_type", "executive_security"),
                              request.data.get("file_format", "pdf"), request.data.get("title", ""))
        return Response(ReportSerializer(row).data, status=201)

    @action(detail=True, methods=["get"])
    def download(self, request, pk=None):
        row = self.get_object()
        if not row.file or not row.file.storage.exists(row.file.name):
            raise ServiceError("report_file_missing", "The report file is no longer available; generate it again.", 404)
        return FileResponse(row.file.open("rb"), as_attachment=True, filename=f"{row.title}.{row.file_format}")

