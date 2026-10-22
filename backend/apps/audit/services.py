def log_action(request, action, obj=None, user=None, organization=None):
    """Write an audit record. Never raises: auditing must not break requests."""
    from .models import AuditLog
    try:
        ip = None
        if request is not None:
            user = user or (request.user if request.user.is_authenticated else None)
            organization = organization or getattr(request, "org", None)
            ip = (request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
                  or request.META.get("REMOTE_ADDR") or None)
        AuditLog.objects.create(
            organization=organization, user=user, action=action, ip_address=ip or None,
            object_type=obj.__class__.__name__ if obj is not None else "",
            object_id=str(getattr(obj, "pk", "")) if obj is not None else "",
            object_repr=str(obj)[:255] if obj is not None else "")
    except Exception:  # pragma: no cover
        pass
