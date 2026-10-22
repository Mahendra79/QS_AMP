from rest_framework import viewsets


class OrgScopedMixin:
    """Restricts every queryset to request.org and stamps org on create.

    This is the single choke point for tenant isolation.
    """

    def get_queryset(self):
        return super().get_queryset().filter(organization=self.request.org)

    def perform_create(self, serializer):
        obj = serializer.save(organization=self.request.org)
        self.after_create(obj)

    def after_create(self, obj):
        from apps.audit.services import log_action
        log_action(self.request, "create", obj)

    def perform_update(self, serializer):
        obj = serializer.save()
        from apps.audit.services import log_action
        log_action(self.request, "update", obj)

    def perform_destroy(self, instance):
        from apps.audit.services import log_action
        log_action(self.request, "delete", instance)
        instance.delete()


class OrgModelViewSet(OrgScopedMixin, viewsets.ModelViewSet):
    pass


class OrgReadOnlyViewSet(OrgScopedMixin, viewsets.ReadOnlyModelViewSet):
    pass
