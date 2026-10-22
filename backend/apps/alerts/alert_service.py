from django.utils import timezone

from .models import Alert

SEVERITIES = ["critical", "high", "medium", "low", "info"]
ALERT_TYPES = {
    "vulnerable_algorithm": "New vulnerable algorithm",
    "certificate_expiring": "Certificate expiring",
    "new_dependency": "New crypto dependency",
    "risk_increased": "Risk score increased",
    "new_asset": "New asset discovered",
    "scan_failed": "Scan failed",
    "migration_failed": "Migration failed",
    "pqc_verification_failed": "PQC verification failed",
}


def create_alert(org, severity, alert_type, title, message="", asset=None, dedupe=True):
    """Create an open alert; skips duplicates (same type+title still open)."""
    if dedupe and Alert.objects.filter(organization=org, alert_type=alert_type, title=title,
                                       status__in=("open", "acknowledged", "muted")).exists():
        return None
    return Alert.objects.create(organization=org, severity=severity, alert_type=alert_type, title=title,
                                message=message, asset=asset)


def transition(alert, action, user=None, assignee=None):
    now = timezone.now()
    if action == "acknowledge":
        alert.status, alert.acknowledged_at = "acknowledged", now
    elif action == "resolve":
        alert.status, alert.resolved_at = "resolved", now
    elif action == "mute":
        alert.status = "muted"
    elif action == "reopen":
        alert.status, alert.resolved_at = "open", None
    elif action == "assign":
        alert.assigned_to = assignee
    alert.save()
    return alert
