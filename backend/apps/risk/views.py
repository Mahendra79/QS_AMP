from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.organizations.mixins import OrgModelViewSet, OrgReadOnlyViewSet
from apps.organizations.permissions import RolePermission

from .models import RiskAssessment, RiskFactor, RiskFinding
from .risk_service import assess_organization, ensure_factors, latest_assessment
from .serializers import (RiskAssessmentSerializer, RiskFactorSerializer, RiskFindingSerializer,
                          RiskFindingTriageSerializer)


class RiskSummaryView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        current = latest_assessment(request.org)
        if current is None:
            current = assess_organization(request.org)
        findings = RiskFinding.objects.filter(organization=request.org).select_related("asset")[:10]
        return Response({"assessment": RiskAssessmentSerializer(current).data,
                         "factors": RiskFactorSerializer(ensure_factors(request.org), many=True).data,
                         "top_findings": RiskFindingSerializer(findings, many=True).data})

    def post(self, request):
        return Response(RiskAssessmentSerializer(assess_organization(request.org)).data, status=201)


class RiskFindingViewSet(OrgModelViewSet):
    queryset = RiskFinding.objects.select_related("asset")
    serializer_class = RiskFindingSerializer
    filterset_fields = ["severity", "status", "asset"]
    http_method_names = ["get", "patch", "head", "options"]

    def get_serializer_class(self):
        return RiskFindingTriageSerializer if self.action == "partial_update" else RiskFindingSerializer

    def update(self, request, *args, **kwargs):
        super().update(request, *args, **kwargs)
        return Response(RiskFindingSerializer(self.get_object()).data)


class RiskFactorViewSet(OrgModelViewSet):
    queryset = RiskFactor.objects.all()
    serializer_class = RiskFactorSerializer
    http_method_names = ["get", "patch", "head", "options"]

    def list(self, request, *args, **kwargs):
        ensure_factors(request.org)
        return super().list(request, *args, **kwargs)

    def perform_update(self, serializer):
        super().perform_update(serializer)
        # The weight/enabled flag just changed - every asset's cached risk_score was
        # computed under the previous configuration.
        from apps.inventory.models import CryptoAsset
        if CryptoAsset.objects.filter(organization=self.request.org).exists():
            assess_organization(self.request.org)

