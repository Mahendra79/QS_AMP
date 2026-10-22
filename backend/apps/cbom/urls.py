from rest_framework.routers import DefaultRouter

from .views import CBOMViewSet

router = DefaultRouter()
router.register("cbom", CBOMViewSet, basename="cbom")
urlpatterns = router.urls

