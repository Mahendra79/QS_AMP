from rest_framework.response import Response
from rest_framework.views import APIView

from apps.inventory.models import CryptoAsset
from apps.organizations.errors import ServiceError
from apps.organizations.permissions import RolePermission

from .comparison_service import compare_classical_vs_pqc, recommend_pqc
from .models import Comparison, PQCAlgorithm
from .serializers import ComparisonSerializer, PQCAlgorithmSerializer


class ComparisonView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        history = Comparison.objects.filter(organization=request.org)[:20]
        return Response({"algorithms": PQCAlgorithmSerializer(PQCAlgorithm.objects.filter(is_active=True), many=True).data,
                         "history": ComparisonSerializer(history, many=True).data})

    def post(self, request):
        asset = None
        if request.data.get("asset_id"):
            asset = CryptoAsset.objects.filter(organization=request.org, pk=request.data["asset_id"]).first()
            if not asset:
                raise ServiceError("not_found", "Asset not found.", 404)
        classical = request.data.get("classical_algorithm") or (asset.algorithm if asset else "")
        purpose = request.data.get("purpose") or (asset.purpose if asset else "")
        candidates = request.data.get("pqc_algorithms") or []
        if not candidates and asset:
            candidates = [c["candidate"] for c in recommend_pqc(asset)["candidates"][:3]]
        result = compare_classical_vs_pqc(classical, candidates, purpose, request.data.get("environment", ""),
                                          request.org, asset.key_size if asset else request.data.get("key_size"))
        row = Comparison.objects.create(organization=request.org, asset=asset, classical_algorithm=classical,
                                        candidates=candidates, purpose=purpose, environment=request.data.get("environment", ""),
                                        result=result, created_by=request.user)
        return Response(ComparisonSerializer(row).data, status=201)


class RecommendationView(APIView):
    permission_classes = [RolePermission]

    def get(self, request, asset_id):
        asset = CryptoAsset.objects.filter(organization=request.org, pk=asset_id).first()
        if not asset:
            raise ServiceError("not_found", "Asset not found.", 404)
        return Response(recommend_pqc(asset))

