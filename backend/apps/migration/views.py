from django.db.models import Count, Sum
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.organizations.mixins import OrgModelViewSet
from apps.organizations.permissions import RolePermission
from apps.inventory.models import CryptoAsset
from apps.comparison.comparison_service import candidate_names

from .migration_service import DONE_STATUSES, apply_completed_migration
from .models import MigrationProject, MigrationTask
from .serializers import MigrationProjectSerializer, MigrationTaskSerializer


class MigrationProjectViewSet(OrgModelViewSet):
    queryset = MigrationProject.objects.all()
    serializer_class = MigrationProjectSerializer


class MigrationTaskViewSet(OrgModelViewSet):
    queryset = MigrationTask.objects.select_related("asset", "owner", "project")
    serializer_class = MigrationTaskSerializer
    filterset_fields = ["project", "status", "phase", "risk_level", "owner"]

    def perform_create(self, serializer):
        super().perform_create(serializer)
        if serializer.instance.status in DONE_STATUSES:
            apply_completed_migration(serializer.instance)

    def perform_update(self, serializer):
        previous_status = serializer.instance.status
        super().perform_update(serializer)
        task = serializer.instance
        if task.status in DONE_STATUSES and previous_status not in DONE_STATUSES:
            # The Kanban card just reached a "done" state: the migration is no
            # longer just tracked, it is real - sync the inventory asset and
            # re-run risk scoring so quantum risk actually reflects it.
            apply_completed_migration(task)


class MigrationSummaryView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        qs = MigrationTask.objects.filter(organization=request.org)
        status_counts = {r["status"]: r["count"] for r in qs.values("status").annotate(count=Count("id"))}
        total = qs.count()
        done = status_counts.get("verified", 0) + status_counts.get("completed", 0)
        phases = ["inventory", "assessment", "planning", "hybrid", "pqc", "verification", "decommission"]
        phase_progress = {phase: 0 for phase in phases}
        if CryptoAsset.objects.filter(organization=request.org).exists():
            phase_progress["inventory"] = 100
        from apps.risk.models import RiskAssessment
        if RiskAssessment.objects.filter(organization=request.org).exists():
            phase_progress["assessment"] = 100
        if total:
            phase_progress["planning"] = round(100 * qs.exclude(status="backlog").count() / total)
            for phase in ("hybrid", "pqc", "verification", "decommission"):
                phase_progress[phase] = round(100 * qs.filter(phase=phase, status__in=("verified", "completed")).count() / total)
        return Response({"progress": round(100 * done / total) if total else 0, "total": total,
                         "estimated_effort_days": qs.aggregate(value=Sum("effort_days"))["value"] or 0,
                         "by_status": status_counts, "phase_progress": phase_progress,
                         "projects": MigrationProjectSerializer(MigrationProject.objects.filter(organization=request.org), many=True).data,
                         "tasks": MigrationTaskSerializer(qs, many=True).data})

    def post(self, request):
        project, _ = MigrationProject.objects.get_or_create(
            organization=request.org, name="Quantum-safe migration", defaults={"current_phase": "planning"})
        created = 0
        assets = CryptoAsset.objects.filter(organization=request.org, quantum_status="vulnerable")
        for asset in assets:
            candidates = candidate_names(asset)
            if not candidates:
                continue
            _, was_created = MigrationTask.objects.get_or_create(
                organization=request.org, project=project, asset=asset,
                defaults={"title": f"Migrate {asset.name} in {asset.application}",
                          "current_algorithm": asset.algorithm, "target_algorithm": candidates[0],
                          "migration_path": ["Classical", "Hybrid", "PQC"], "purpose": asset.purpose,
                          "risk_level": asset.risk_level, "phase": "planning",
                          "priority": 1 if asset.risk_level == "critical" else 2})
            created += int(was_created)
        return Response({"created": created, "message": f"Created {created} migration task(s)."}, status=201)
