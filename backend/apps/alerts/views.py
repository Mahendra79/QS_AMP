from rest_framework.decorators import action
from rest_framework.response import Response

from apps.organizations.mixins import OrgModelViewSet

from .alert_service import transition
from .models import Alert
from .serializers import AlertSerializer


class AlertViewSet(OrgModelViewSet):
    queryset = Alert.objects.select_related("asset", "assigned_to")
    serializer_class = AlertSerializer
    # status__in=open,acknowledged lists the active queue in one request
    filterset_fields = {"severity": ["exact"], "alert_type": ["exact"], "status": ["exact", "in"],
                        "assigned_to": ["exact"]}
    http_method_names = ["get", "post", "patch", "head", "options"]

    @action(detail=True, methods=["post"])
    def reopen(self, request, pk=None):
        return Response(AlertSerializer(transition(self.get_object(), "reopen", request.user)).data)

    @action(detail=True, methods=["post"])
    def acknowledge(self, request, pk=None):
        return Response(AlertSerializer(transition(self.get_object(), "acknowledge", request.user)).data)

    @action(detail=True, methods=["post"])
    def resolve(self, request, pk=None):
        return Response(AlertSerializer(transition(self.get_object(), "resolve", request.user)).data)

    @action(detail=True, methods=["post"])
    def mute(self, request, pk=None):
        return Response(AlertSerializer(transition(self.get_object(), "mute", request.user)).data)

