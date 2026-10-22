from rest_framework.routers import DefaultRouter

from .views import IntegrationViewSet

router = DefaultRouter()
router.register("integrations", IntegrationViewSet, basename="integration")
urlpatterns = router.urls

