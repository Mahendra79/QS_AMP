from rest_framework.response import Response
from rest_framework.views import APIView

from apps.organizations.permissions import RolePermission

from .benchmark_service import capabilities, recover_stale_runs, run_benchmark
from .models import BenchmarkRun
from .serializers import BenchmarkRunSerializer


class BenchmarkView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        recover_stale_runs(request.org)
        runs = BenchmarkRun.objects.filter(organization=request.org).prefetch_related("results")[:20]
        return Response({"capabilities": capabilities(), "runs": BenchmarkRunSerializer(runs, many=True).data})

    def post(self, request):
        run = run_benchmark(request.org, request.user, request.data.get("algorithms", []),
                            request.data.get("operations"), request.data.get("iterations", 20),
                            request.data.get("name", ""), request.data.get("force_demo", False), background=True)
        # 202: measurement continues in the background; poll GET until the run leaves "running".
        return Response(BenchmarkRunSerializer(run).data, status=202 if run.status == "running" else 201)
