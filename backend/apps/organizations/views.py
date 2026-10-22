from django.db import models
from django.db.models import Count
from django.utils import timezone
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.alerts.models import Alert
from apps.discovery.models import AssetSource, ScanJob
from apps.inventory.models import CryptoAsset
from apps.migration.models import MigrationTask
from apps.monitoring.models import MonitoringEvent
from apps.risk.models import RiskAssessment, RiskFinding
from apps.risk.risk_service import assess_organization

from .defaults import merged_settings, validate_settings
from .models import Environment, OrganizationMembership
from .permissions import RolePermission
from .serializers import EnvironmentSerializer, MembershipSerializer, OrganizationSerializer


class OrganizationListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        memberships = OrganizationMembership.objects.filter(user=request.user).select_related("organization")
        return Response([{
            **OrganizationSerializer(m.organization).data,
            "role": m.role,
        } for m in memberships])


class EnvironmentListView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        rows = Environment.objects.filter(organization=request.org)
        return Response(EnvironmentSerializer(rows, many=True).data)


class TeamView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        rows = OrganizationMembership.objects.filter(organization=request.org).select_related("user")
        return Response(MembershipSerializer(rows, many=True).data)


class SettingsView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        return Response({"organization": OrganizationSerializer(request.org).data, "settings": merged_settings(request.org)})

    def patch(self, request):
        incoming = request.data.get("settings", request.data)
        if not isinstance(incoming, dict):
            return Response({"success": False, "error": {"code": "validation_error", "message": "Settings must be an object."}}, status=400)
        validate_settings(incoming, request.org)
        current = request.org.settings or {}
        for section, values in incoming.items():
            if isinstance(values, dict) and isinstance(current.get(section), dict):
                current[section] = {**current[section], **values}
            else:
                current[section] = values
        request.org.settings = current
        request.org.save(update_fields=["settings"])
        if "risk" in incoming and CryptoAsset.objects.filter(organization=request.org).exists():
            # Weights/thresholds just changed - every cached risk_score/risk_level and the
            # Dashboard's quantum-exposure number were computed under the old config.
            assess_organization(request.org)
        return self.get(request)


class DashboardView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        assets = CryptoAsset.objects.filter(organization=request.org)
        risk_counts = {row["risk_level"]: row["count"] for row in assets.values("risk_level").annotate(count=Count("id"))}
        algorithm_distribution = list(assets.values("algorithm").annotate(value=Count("id")).order_by("-value")[:8])
        total = assets.count()
        migration_targets = assets.filter(purpose__in=("key_exchange", "digital_signature"))
        pq_ready = migration_targets.filter(quantum_status__in=("pq_standardized", "pq_hybrid")).count()
        pq_total = migration_targets.count()
        latest = RiskAssessment.objects.filter(organization=request.org).first()
        migration_total = MigrationTask.objects.filter(organization=request.org).count()
        migration_done = MigrationTask.objects.filter(organization=request.org, status__in=("verified", "completed")).count()
        recent = assets.select_related("source").order_by("-last_seen")[:8]
        monitoring = request.org.monitoring_monitoringconfiguration_set.first()
        return Response({
            "organization": OrganizationSerializer(request.org).data,
            "has_sources": AssetSource.objects.filter(organization=request.org).exists(),
            "metrics": {
                "total_assets": total,
                "critical_assets": risk_counts.get("critical", 0),
                "high_risk": risk_counts.get("high", 0),
                "pqc_readiness": round(100 * pq_ready / pq_total) if pq_total else 0,
                "quantum_exposure": latest.overall_score if latest else 0,
                "migration_progress": round(100 * migration_done / migration_total) if migration_total else 0,
            },
            "risk_distribution": [{"name": k.title(), "value": risk_counts.get(k, 0)} for k in ("critical", "high", "medium", "low", "safe")],
            "algorithm_distribution": algorithm_distribution,
            "recent_assets": [{
                "id": str(a.id), "asset_ref": a.asset_ref, "name": a.name, "application": a.application,
                "algorithm": a.algorithm, "purpose": a.purpose, "risk_level": a.risk_level, "risk_score": a.risk_score,
                "quantum_status": a.quantum_status, "last_seen": a.last_seen,
            } for a in recent],
            "open_findings": RiskFinding.objects.filter(organization=request.org, status="open").count(),
            "open_alerts": Alert.objects.filter(organization=request.org, status="open").count(),
            "scan_count": ScanJob.objects.filter(organization=request.org).count(),
            "changes_today": MonitoringEvent.objects.filter(organization=request.org, occurred_at__date=timezone.localdate()).count(),
            "monitoring": {"enabled": monitoring.enabled, "next_scan_at": monitoring.next_scan_at} if monitoring else {"enabled": False},
            "readiness_trajectory": [
                {"n": "Inventory", "v": 100 if total else 0},
                {"n": "Assess", "v": 100 if latest and latest.asset_count == total else 0},
                # Share of quantum-vulnerable assets that have a migration task (capped: tasks
                # can outlive the asset they were planned for).
                {"n": "Plan", "v": min(100, round(100 * MigrationTask.objects.filter(
                    organization=request.org, asset__quantum_status="vulnerable").values("asset").distinct().count()
                    / max(1, assets.filter(quantum_status="vulnerable").count())))},
                {"n": "Verify", "v": round(100 * migration_done / migration_total) if migration_total else 0},
                {"n": "PQC", "v": round(100 * pq_ready / pq_total) if pq_total else 0},
            ],
        })


class SearchView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        q = (request.query_params.get("q") or "").strip()
        if len(q) < 2:
            return Response([])
        assets = CryptoAsset.objects.filter(organization=request.org).filter(
            models.Q(name__icontains=q) | models.Q(algorithm__icontains=q) | models.Q(application__icontains=q)
        )[:10]
        return Response([{"type": "asset", "id": str(a.id), "title": a.name, "subtitle": f"{a.application} - {a.risk_level.title()}"} for a in assets])


