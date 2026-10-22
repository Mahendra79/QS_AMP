import hashlib
import secrets
import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models


class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, **extra):
        if not email:
            raise ValueError("Email is required")
        normalized = self.normalize_email(email).lower()
        extra.setdefault("username", normalized.split("@", 1)[0])
        user = self.model(email=normalized, **extra)
        user.set_password(password)  # hashed (PBKDF2); raw passwords are never stored
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra):
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=80, unique=True, null=True, blank=True)
    full_name = models.CharField(max_length=150, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=64, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = UserManager()
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username or self.email


class APIKey(models.Model):
    """Only a SHA-256 hash of the key is stored; the plaintext is shown once."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_keys")
    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=12)
    key_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked = models.BooleanField(default=False)

    @staticmethod
    def hash_key(raw):
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def generate(cls, user, organization, name):
        raw = "qsamp_" + secrets.token_urlsafe(32)
        obj = cls.objects.create(user=user, organization=organization, name=name,
                                 prefix=raw[:10], key_hash=cls.hash_key(raw))
        return obj, raw
