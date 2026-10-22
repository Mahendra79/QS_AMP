from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="docs"),
    path("api/", include("apps.accounts.urls")),
    path("api/", include("apps.organizations.urls")),
    path("api/", include("apps.discovery.urls")),
    path("api/", include("apps.inventory.urls")),
    path("api/", include("apps.cbom.urls")),
    path("api/", include("apps.risk.urls")),
    path("api/", include("apps.comparison.urls")),
    path("api/", include("apps.benchmarks.urls")),
    path("api/", include("apps.monitoring.urls")),
    path("api/", include("apps.migration.urls")),
    path("api/", include("apps.reports.urls")),
    path("api/", include("apps.alerts.urls")),
    path("api/", include("apps.integrations.urls")),
    path("api/", include("apps.audit.urls")),
]
