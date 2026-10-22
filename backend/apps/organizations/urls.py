from django.urls import path

from . import views

urlpatterns = [
    path("organizations/", views.OrganizationListView.as_view()),
    path("environments/", views.EnvironmentListView.as_view()),
    path("team/", views.TeamView.as_view()),
    path("settings/", views.SettingsView.as_view()),
    path("dashboard/", views.DashboardView.as_view()),
    path("search/", views.SearchView.as_view()),
]

