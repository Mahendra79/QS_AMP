from django.conf import settings
from django.db.models import Count
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.organizations.errors import ServiceError
from apps.organizations.permissions import RolePermission

from .models import MonitoringEvent
from .monitoring_service import get_config, real_scan, reschedule, simulate_scan
from .serializers import MonitoringConfigurationSerializer, MonitoringEventSerializer


class MonitoringView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        cfg = get_config(request.org)
        all_events = MonitoringEvent.objects.filter(organization=request.org)
        events = all_events.select_related("source")[:50]
        counts = {r["event_type"]: r["count"] for r in all_events.order_by().values("event_type").annotate(count=Count("id"))}
        return Response({"configuration": MonitoringConfigurationSerializer(cfg).data,
                         "events": MonitoringEventSerializer(events, many=True).data, "counts": counts,
                         "changes_today": MonitoringEvent.objects.filter(
                             organization=request.org, occurred_at__date=timezone.localdate()).count(),
                         "scheduler_available": settings.CELERY_ENABLED})

    def patch(self, request):
        cfg = get_config(request.org)
        serializer = MonitoringConfigurationSerializer(cfg, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        reschedule(cfg)  # a config change is not a scan: last_scan_at stays as it was
        return Response(MonitoringConfigurationSerializer(cfg).data)


class MonitoringScanView(APIView):
    permission_classes = [RolePermission]

    def post(self, request):
        cfg = get_config(request.org)
        if cfg.simulated:
            if not settings.DEMO_MODE:
                raise ServiceError("demo_disabled", "Simulated monitoring is disabled.", 403)
            try:
                count = min(10, max(1, int(request.data.get("count") or 0))) if request.data.get("count") else None
            except (TypeError, ValueError):
                raise ServiceError("validation_error", "count must be a whole number between 1 and 10.")
            events = simulate_scan(request.org, count)
            return Response({"mode": "simulated", "events": MonitoringEventSerializer(events, many=True).data},
                            status=201)
        jobs, skipped = real_scan(request.org, request.user)
        if not jobs and not skipped:
            raise ServiceError("no_monitored_sources",
                               "No sources have continuous monitoring enabled. Enable it on a source first.")
        return Response({"mode": "evidence", "jobs": [str(j.id) for j in jobs],
                         "skipped": [s.name for s in skipped]}, status=202)
