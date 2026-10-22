from django.urls import path

from .views import ComparisonView, RecommendationView

urlpatterns = [
    path("comparison/", ComparisonView.as_view()),
    path("comparison/run/", ComparisonView.as_view()),
    path("comparison/recommend/<uuid:asset_id>/", RecommendationView.as_view()),
]
