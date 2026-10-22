from django.utils import timezone
from rest_framework import authentication, exceptions


class APIKeyAuthentication(authentication.BaseAuthentication):
    """X-API-Key header authentication (key is looked up by SHA-256 hash)."""

    def authenticate(self, request):
        raw = request.headers.get("X-API-Key")
        if not raw:
            return None
        from .models import APIKey
        key = APIKey.objects.select_related("user").filter(key_hash=APIKey.hash_key(raw), revoked=False).first()
        if not key or not key.user.is_active:
            raise exceptions.AuthenticationFailed("Invalid API key.")
        APIKey.objects.filter(pk=key.pk).update(last_used_at=timezone.now())
        request.META["HTTP_X_ORGANIZATION"] = str(key.organization_id)
        return key.user, key
