from django.urls import path

from .views import MonitoringScanView, MonitoringView

urlpatterns = [path("monitoring/", MonitoringView.as_view()), path("monitoring/scan/", MonitoringScanView.as_view())]

