from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from . import views

urlpatterns = [
    path("auth/register/", views.RegisterView.as_view()),
    path("auth/login/", views.LoginView.as_view()),
    path("auth/refresh/", TokenRefreshView.as_view()),
    path("auth/forgot-password/", views.ForgotPasswordView.as_view()),
    path("auth/me/", views.MeView.as_view()),
    path("auth/change-password/", views.ChangePasswordView.as_view()),
    path("auth/mfa/setup/", views.MFASetupView.as_view()),
    path("auth/mfa/verify/", views.MFAVerifyView.as_view()),
    path("auth/mfa/disable/", views.MFADisableView.as_view()),
    path("auth/api-keys/", views.APIKeyListCreateView.as_view()),
    path("auth/api-keys/<uuid:pk>/", views.APIKeyDetailView.as_view()),
]
