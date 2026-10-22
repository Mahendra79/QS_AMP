"""Continuous monitoring: config, events, simulated periodic scans and due-scan runner.

Architecture: `run_due_scans()` (management command `run_monitoring`, or a Celery
beat task) re-scans every monitored source whose configured interval elapsed.
In demo mode `simulate_scan()` emits clearly-flagged simulated events.
"""
import random
from datetime import timedelta

from django.utils import timezone

from .models import MonitoringConfiguration, MonitoringEvent

EVENT_TYPES = {
    "crypto_change": "Crypto changes",
    "certificate_change": "Certificate changes",
    "new_dependency": "New dependencies",
    "new_algorithm": "New algorithms",
    "risk_change": "Risk changes",
}

SIM_TEMPLATES = [
    ("certificate_change", "RSA certificate changed", "Leaf certificate for {app} was replaced (new serial).", "high"),
    ("new_dependency", "New crypto dependency detected", "Library {lib} added to {app}.", "medium"),
    ("certificate_change", "Certificate renewed", "Certificate for {app} renewed ahead of expiry.", "info"),
    ("new_algorithm", "New algorithm detected", "{alg} observed in {app}.", "medium"),
    ("risk_change", "Risk score increased", "Risk score for {app} increased after a configuration change.", "high"),
    ("crypto_change", "Cipher suite configuration changed", "TLS cipher suite ordering changed on {app}.", "low"),
]


def get_config(org):
    cfg, _ = MonitoringConfiguration.objects.get_or_create(
        organization=org, defaults={"enabled": False, "frequency_hours": 24, "simulated": org.is_demo})
    return cfg


def record_event(org, event_type, title, detail="", severity="info", source=None, simulated=False, when=None):
    return MonitoringEvent.objects.create(organization=org, source=source, event_type=event_type, title=title[:300],
                                          detail=detail, severity=severity, occurred_at=when or timezone.now(),
                                          is_simulated=simulated)


def schedule_next(cfg, now=None):
    now = now or timezone.now()
    cfg.last_scan_at = now
    cfg.next_scan_at = now + timedelta(hours=cfg.frequency_hours) if cfg.enabled else None
    cfg.save()


def simulate_scan(org, count=None):
    """Demo-mode monitoring pass: emits flagged, simulated events (no data is altered)."""
    from apps.alerts.alert_service import create_alert
    from apps.discovery.models import AssetSource
    from apps.inventory.models import CryptoAsset
    rng = random.Random(int(timezone.now().timestamp() // 60))
    sources = list(AssetSource.objects.filter(organization=org))
    assets = list(CryptoAsset.objects.filter(organization=org)[:200])
    libs = ["OpenSSL 3.0.13", "bouncycastle 1.78", "PyJWT 2.8", "node-forge 1.3.1", "cryptography 42.0"]
    events = []
    for _ in range(count or rng.randint(1, 3)):
        etype, title, detail, sev = rng.choice(SIM_TEMPLATES)
        a = rng.choice(assets) if assets else None
        src = rng.choice(sources) if sources else None
        app = (a.application if a and a.application else (src.name if src else "unknown"))
        ev = record_event(org, etype, title, detail.format(app=app, lib=rng.choice(libs),
                                                           alg=a.name if a else "RSA-2048"),
                          sev, src, simulated=True)
        events.append(ev)
        if sev == "high":
            create_alert(org, "high", "risk_increased" if etype == "risk_change" else "vulnerable_algorithm",
                         f"{title} ({app})", f"{ev.detail} [simulated monitoring event]", a)
    cfg = get_config(org)
    schedule_next(cfg)
    return events


def reschedule(cfg):
    """Recompute next_scan_at after a configuration change without pretending a scan ran."""
    base = cfg.last_scan_at or timezone.now()
    cfg.next_scan_at = max(base + timedelta(hours=cfg.frequency_hours), timezone.now()) if cfg.enabled else None
    cfg.save(update_fields=["next_scan_at", "updated_at"])


def real_scan(org, user=None):
    """Re-scan every monitored source (real discovery path). Sources that are
    already being scanned are skipped rather than scanned twice."""
    from apps.discovery.discovery_service import create_scan
    from apps.discovery.models import AssetSource
    from apps.organizations.errors import ServiceError
    jobs, skipped = [], []
    for s in AssetSource.objects.filter(organization=org, monitoring_enabled=True):
        try:
            jobs.append(create_scan(s, user))
        except ServiceError as exc:
            if exc.code != "scan_in_progress":
                raise
            skipped.append(s)
    cfg = get_config(org)
    schedule_next(cfg)
    return jobs, skipped


def run_due_scans():
    """Called by cron / celery beat. Runs due monitoring configs; returns number of orgs scanned."""
    from apps.discovery.discovery_service import recover_stale_scans
    recover_stale_scans()
    n = 0
    for cfg in MonitoringConfiguration.objects.filter(enabled=True).select_related("organization"):
        now = timezone.now()
        if cfg.next_scan_at is not None and cfg.next_scan_at > now:
            continue
        # Claim this run: if cron and Celery beat (or two beat instances) overlap,
        # only the caller whose conditional update succeeds performs the scan.
        claimed = MonitoringConfiguration.objects.filter(pk=cfg.pk, next_scan_at=cfg.next_scan_at).update(
            next_scan_at=now + timedelta(hours=cfg.frequency_hours))
        if not claimed:
            continue
        if cfg.simulated:
            simulate_scan(cfg.organization)
        else:
            real_scan(cfg.organization)
        n += 1
    return n
