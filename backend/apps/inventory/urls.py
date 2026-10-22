from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (AlgorithmViewSet, ArchitectureView, AssetViewSet, CertificateViewSet, KeyViewSet,
                    LibraryViewSet, ProtocolViewSet)

router = DefaultRouter()
router.register("inventory", AssetViewSet, basename="inventory")
router.register("algorithms", AlgorithmViewSet, basename="algorithm")
router.register("certificates", CertificateViewSet, basename="certificate")
router.register("libraries", LibraryViewSet, basename="library")
router.register("keys", KeyViewSet, basename="key")
router.register("protocols", ProtocolViewSet, basename="protocol")
urlpatterns = [path("architecture/", ArchitectureView.as_view()), *router.urls]

