try:  # Celery is optional at runtime.
    from .celery import app as celery_app  # noqa: F401
except Exception:  # pragma: no cover
    celery_app = None
