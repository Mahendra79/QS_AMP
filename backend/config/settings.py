"""QS-AMP Django settings. All secrets come from environment variables."""
import os
from datetime import timedelta
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


DEBUG = env_bool("DEBUG", True)
SECRET_KEY = os.getenv("SECRET_KEY") or ("dev-insecure-key-change-me" if DEBUG else "")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be set when DEBUG is False")
ALLOWED_HOSTS = [h for h in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h]

# Demo mode: seeded data, simulated scanning/monitoring, demo benchmark adapters.
DEMO_MODE = env_bool("DEMO_MODE", True)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "django_filters",
    "drf_spectacular",
    "apps.accounts",
    "apps.organizations",
    "apps.discovery",
    "apps.inventory",
    "apps.cbom",
    "apps.risk",
    "apps.comparison",
    "apps.benchmarks",
    "apps.monitoring",
    "apps.migration",
    "apps.reports",
    "apps.alerts",
    "apps.integrations",
    "apps.audit",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]

# ---- Database: PostgreSQL only -------------------------------------------------
_db_url = os.getenv("DATABASE_URL")
if _db_url:
    DATABASES = {"default": dj_database_url.parse(_db_url, conn_max_age=60)}
else:
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME", "qsamp"),
        "USER": os.getenv("DB_USER", "postgres"),
        "PASSWORD": os.getenv("DB_PASSWORD", ""),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", "5432"),
        "CONN_MAX_AGE": 60,
    }}

AUTH_USER_MODEL = "accounts.User"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
PASSWORD_HASHERS = ["django.contrib.auth.hashers.PBKDF2PasswordHasher"]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Uploaded files live under MEDIA_ROOT, outside of the source tree that is served.
MEDIA_URL = "media/"
MEDIA_ROOT = Path(os.getenv("MEDIA_ROOT", BASE_DIR / "media"))
UPLOAD_MAX_BYTES = int(os.getenv("UPLOAD_MAX_BYTES", 50 * 1024 * 1024))
ZIP_MAX_UNCOMPRESSED_BYTES = int(os.getenv("ZIP_MAX_UNCOMPRESSED_BYTES", 200 * 1024 * 1024))
ZIP_MAX_FILES = int(os.getenv("ZIP_MAX_FILES", 20000))
ZIP_MAX_RATIO = int(os.getenv("ZIP_MAX_RATIO", 200))
DATA_UPLOAD_MAX_MEMORY_SIZE = UPLOAD_MAX_BYTES
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024

# Base URL of the web app; generated reports deep-link back into it.
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173")

# ---- CORS / CSRF ----------------------------------------------------------------
CORS_ALLOWED_ORIGINS = [o for o in os.getenv(
    "CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o]
CSRF_TRUSTED_ORIGINS = CORS_ALLOWED_ORIGINS
CORS_ALLOW_HEADERS = ["accept", "authorization", "content-type", "x-organization", "x-api-key"]

# ---- DRF / JWT ------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "apps.accounts.authentication.APIKeyAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("apps.organizations.permissions.RolePermission",),
    "DEFAULT_FILTER_BACKENDS": ("django_filters.rest_framework.DjangoFilterBackend",),
    "DEFAULT_PAGINATION_CLASS": "apps.organizations.pagination.StandardPagination",
    "PAGE_SIZE": 25,
    "EXCEPTION_HANDLER": "apps.organizations.errors.api_exception_handler",
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.ScopedRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {"auth": os.getenv("AUTH_THROTTLE", "30/min")},
}
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=int(os.getenv("JWT_ACCESS_MINUTES", 30))),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=int(os.getenv("JWT_REFRESH_DAYS", 7))),
    "ROTATE_REFRESH_TOKENS": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
}
SPECTACULAR_SETTINGS = {
    "TITLE": "QS-AMP API",
    "DESCRIPTION": "Quantum Security Assessment & Migration Platform REST API",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

# ---- Celery (optional). Without a broker, scans run in a background thread. ----
REDIS_URL = os.getenv("REDIS_URL", "")
CELERY_BROKER_URL = REDIS_URL or "memory://"
CELERY_ENABLED = env_bool("CELERY_ENABLED", False)
CELERY_BEAT_SCHEDULE = {
    "run-due-monitoring-scans": {
        "task": "apps.monitoring.tasks.run_due_scans_task",
        "schedule": 60.0,
    },
} if CELERY_ENABLED else {}
# Run scans inline (used by tests). Otherwise a worker thread/celery task is used.
SCAN_SYNC = env_bool("SCAN_SYNC", False)
# Seconds each demo scan stage takes (gives the UI real progress to poll).
SCAN_STAGE_DELAY = float(os.getenv("SCAN_STAGE_DELAY", 0.6))
# Website scans: attempt real TLS probes (public hosts only).
LIVE_TLS_PROBE = env_bool("LIVE_TLS_PROBE", True)

if not DEBUG:
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
