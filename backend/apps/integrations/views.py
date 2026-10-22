from django.utils import timezone
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.organizations.mixins import OrgModelViewSet

from .models import Integration
from .serializers import IntegrationSerializer


class IntegrationViewSet(OrgModelViewSet):
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer
    filterset_fields = ["provider", "category", "status"]

    @action(detail=True, methods=["post"])
    def connect(self, request, pk=None):
        row = self.get_object()
        row.status, row.connected_at, row.is_mock = "connected", timezone.now(), True
        row.config = {**row.config, **request.data.get("config", {})}
        row.save(update_fields=["status", "connected_at", "is_mock", "config", "updated_at"])
        return Response({**IntegrationSerializer(row).data, "notice": "Demo connection configured. No external credentials were transmitted."})

    @action(detail=True, methods=["post"])
    def disconnect(self, request, pk=None):
        row = self.get_object()
        row.status, row.connected_at = "disconnected", None
        row.save(update_fields=["status", "connected_at", "updated_at"])
        return Response(IntegrationSerializer(row).data)

