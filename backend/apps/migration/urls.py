from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import MigrationProjectViewSet, MigrationSummaryView, MigrationTaskViewSet

router = DefaultRouter()
router.register("migration/projects", MigrationProjectViewSet, basename="migration-project")
router.register("migration/tasks", MigrationTaskViewSet, basename="migration-task")
urlpatterns = [path("migration/", MigrationSummaryView.as_view()), *router.urls]
