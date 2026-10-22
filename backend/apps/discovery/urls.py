from rest_framework.routers import DefaultRouter

from .views import AssetSourceViewSet, ScanJobViewSet

router = DefaultRouter()
router.register("discovery/sources", AssetSourceViewSet, basename="source")
router.register("discovery/scans", ScanJobViewSet, basename="scan")
urlpatterns = router.urls
