from django.urls import path

from .views import BenchmarkView

urlpatterns = [path("benchmarks/", BenchmarkView.as_view()), path("benchmarks/run/", BenchmarkView.as_view())]

