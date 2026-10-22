import pyotp
from django.conf import settings
from django.contrib.auth import authenticate, password_validation
from django.db.models import Q
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from apps.audit.services import log_action
from apps.organizations.errors import ServiceError
from apps.organizations.permissions import RolePermission, resolve_membership
from apps.organizations.services import create_organization

from .models import APIKey, User
from .serializers import APIKeySerializer, LoginSerializer, RegisterSerializer, UserSerializer


def _tokens(user):
    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}


def me_payload(request):
    from apps.discovery.models import AssetSource
    user = request.user
    active = resolve_membership(request)
    orgs = [{"id": str(m.organization_id), "name": m.organization.name, "role": m.role,
             "is_demo": m.organization.is_demo} for m in user.memberships.select_related("organization")]
    active_org = None
    if active:
        active_org = {"id": str(active.organization_id), "name": active.organization.name, "role": active.role,
                      "is_demo": active.organization.is_demo, "plan": active.organization.plan,
                      "source_count": AssetSource.objects.filter(organization=active.organization).count()}
    return {"user": UserSerializer(user).data, "organizations": orgs, "active_organization": active_org,
            "demo_mode": settings.DEMO_MODE}


class AuthThrottled(APIView):
    throttle_scope = "auth"
    permission_classes = [permissions.AllowAny]
    authentication_classes = []


class RegisterView(AuthThrottled):
    def post(self, request):
        s = RegisterSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        internal_email = f"{d['username']}@local.invalid"
        user = User.objects.create_user(internal_email, d["password"], username=d["username"],
                                        full_name=d.get("full_name", ""))
        org = create_organization(d["organization_name"], user)
        log_action(None, "register", org, user=user, organization=org)
        return Response({"success": True, **_tokens(user)}, status=201)


class LoginView(AuthThrottled):
    def post(self, request):
        s = LoginSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        account = User.objects.filter(Q(username__iexact=d["identifier"]) | Q(email__iexact=d["identifier"])).first()
        user = authenticate(request, username=account.email if account else "", password=d["password"])
        if not user:
            raise ServiceError("authentication_failed", "Invalid username or password.", 401)
        if user.mfa_enabled:
            if not d.get("otp"):
                raise ServiceError("mfa_required", "A one-time code is required.", 401)
            if not pyotp.TOTP(user.mfa_secret).verify(d["otp"], valid_window=1):
                raise ServiceError("mfa_invalid", "Invalid one-time code.", 401)
        return Response({"success": True, **_tokens(user)})


class ForgotPasswordView(AuthThrottled):
    def post(self, request):
        # No email transport is configured in the MVP. The response is generic so
        # it does not reveal whether an account exists.
        return Response({"success": True, "message":
                         "If an account exists for that address, reset instructions will be sent. "
                         "(Email delivery is not configured in this environment.)"})


class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(me_payload(request))

    def patch(self, request):
        s = UserSerializer(request.user, data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        s.save()
        return Response(me_payload(request))


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if not request.user.check_password(request.data.get("current_password", "")):
            raise ServiceError("invalid_password", "Current password is incorrect.")
        new = request.data.get("new_password", "")
        try:
            password_validation.validate_password(new, request.user)
        except Exception as e:
            raise ServiceError("weak_password", " ".join(getattr(e, "messages", [str(e)])))
        request.user.set_password(new)
        request.user.save()
        return Response({"success": True})


class MFASetupView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        secret = pyotp.random_base32()
        request.user.mfa_secret = secret
        request.user.mfa_enabled = False
        request.user.save(update_fields=["mfa_secret", "mfa_enabled"])
        uri = pyotp.TOTP(secret).provisioning_uri(request.user.username or "qsamp-user", issuer_name="QS-AMP")
        return Response({"secret": secret, "otpauth_uri": uri})


class MFAVerifyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        u = request.user
        if not u.mfa_secret or not pyotp.TOTP(u.mfa_secret).verify(str(request.data.get("code", "")), valid_window=1):
            raise ServiceError("mfa_invalid", "Invalid one-time code.")
        u.mfa_enabled = True
        u.save(update_fields=["mfa_enabled"])
        return Response({"success": True, "mfa_enabled": True})


class MFADisableView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        u = request.user
        if not u.check_password(request.data.get("password", "")):
            raise ServiceError("invalid_password", "Password is incorrect.")
        u.mfa_enabled, u.mfa_secret = False, ""
        u.save(update_fields=["mfa_enabled", "mfa_secret"])
        return Response({"success": True, "mfa_enabled": False})


class APIKeyListCreateView(APIView):
    permission_classes = [RolePermission]

    def get(self, request):
        keys = APIKey.objects.filter(user=request.user, organization=request.org, revoked=False)
        return Response(APIKeySerializer(keys, many=True).data)

    def post(self, request):
        name = (request.data.get("name") or "").strip()
        if not name:
            raise ServiceError("validation_error", "Key name is required.")
        obj, raw = APIKey.generate(request.user, request.org, name[:100])
        log_action(request, "create_api_key", obj)
        return Response({**APIKeySerializer(obj).data, "key": raw,
                         "notice": "Store this key now; it cannot be shown again."}, status=201)


class APIKeyDetailView(APIView):
    permission_classes = [RolePermission]

    def delete(self, request, pk):
        n = APIKey.objects.filter(pk=pk, user=request.user, organization=request.org).update(revoked=True)
        if not n:
            raise ServiceError("not_found", "API key not found.", 404)
        return Response(status=204)
