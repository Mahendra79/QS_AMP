from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import RiskFactorViewSet, RiskFindingViewSet, RiskSummaryView

router = DefaultRouter()
router.register("risk/findings", RiskFindingViewSet, basename="risk-finding")
router.register("risk/factors", RiskFactorViewSet, basename="risk-factor")
urlpatterns = [path("risk/", RiskSummaryView.as_view()), *router.urls]

