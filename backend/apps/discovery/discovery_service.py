import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from django.conf import settings
from django.db import close_old_connections, transaction
from django.utils import timezone

from apps.alerts.alert_service import create_alert
from apps.audit.services import log_action
from apps.cbom.cbom_service import generate_for_org
from apps.inventory import catalog
from apps.inventory.inventory_service import upsert_asset
from apps.inventory.models import CryptoAsset, CryptoCertificate, CryptoKey, CryptoLibrary, CryptoProtocol
from apps.migration.models import MigrationProject, MigrationTask
from apps.organizations.errors import ServiceError
from apps.risk.risk_service import assess_organization

from .code_scanner import scan_tree
from .models import AssetSource, ScanJob, ScanResult
from .network_utils import public_url
from .safe_zip import safe_extract
from .tls_probe import key_exchange_from_suite, probe_tls

STAGES = [
    "Source validated", "Content inspected", "Cryptographic assets detected", "Dependencies mapped",
    "CBOM generated", "Risk analysis prepared",
]
# A job that has not written progress for this long belongs to a worker that
# died (restart/deploy/crash); it is failed so the source can be scanned again.
STALE_SCAN_AFTER = timedelta(minutes=30)
ACTIVE_JOB_STATUSES = ("queued", "running")


def _progress(job, index, counters=None):
    job.stage_index = index
    job.stage = STAGES[index]
    job.progress = round((index + 1) * 100 / len(STAGES))
    if counters is not None:
        job.counters = counters
    job.save(update_fields=["stage_index", "stage", "progress", "counters", "updated_at"])
    # Pacing exists only so the simulated demo scan has visible stages; real
    # evidence scans never wait artificially.
    if job.mode == "simulated" and not settings.SCAN_SYNC:
        time.sleep(settings.SCAN_STAGE_DELAY)


def _evidence(kind, confidence, **extra):
    return {"evidence_type": kind, "confidence": confidence, "observed_at": timezone.now().isoformat(), **extra}


# ---- collection: network / filesystem only, no database writes ------------------------
def _collect_zip(job):
    temp_dir = Path(tempfile.mkdtemp(prefix="qsamp-scan-"))
    try:
        extracted = safe_extract(job.source.upload.path, temp_dir)
        result = scan_tree(temp_dir, job.source.name)
        result["extracted"] = extracted
        return "code", result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _collect_repository(job):
    source = job.source
    parsed, _ = public_url(source.target, schemes=("https",))
    branch = source.branch or "main"
    if branch.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._/-]{1,120}", branch):
        raise ServiceError("invalid_branch", "Repository branch contains unsupported characters.")
    temp_dir = Path(tempfile.mkdtemp(prefix="qsamp-repo-"))
    checkout = temp_dir / "checkout"
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https"}
    command = ["git", "-c", "protocol.file.allow=never", "-c", "http.followRedirects=false", "clone",
               "--depth", "1", "--single-branch", "--no-tags", "--branch", branch, parsed.geturl(), str(checkout)]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)
        if proc.returncode:
            message = (proc.stderr or proc.stdout or "Repository clone failed.").strip().splitlines()[-1]
            raise ServiceError("repository_unavailable", message[:300])
        return "code", scan_tree(checkout, source.name)
    except FileNotFoundError as exc:
        raise ServiceError("git_unavailable", "Git is required to analyze public repositories.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ServiceError("repository_timeout", "Repository download exceeded the 60 second limit.") from exc
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _collect_website(job):
    if not settings.LIVE_TLS_PROBE:
        raise ServiceError("tls_probe_disabled", "Live TLS probing is disabled; no inventory was created.")
    return "tls", probe_tls(job.source.target)


COLLECTORS = {"zip": _collect_zip, "github": _collect_repository, "public_repo": _collect_repository,
              "website": _collect_website}


# ---- storage: database writes, run inside one transaction -----------------------------
def _public_key_asset(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, f"RSA-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size, f"ECDSA-P{public_key.key_size}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448, "Ed448"
    name = type(public_key).__name__
    return name, getattr(public_key, "key_size", None), name


def _numbered_location(counts, path):
    """A bundle or keystore file can hold several PEM blocks; each position is its own asset."""
    position = counts.get(path, 0)
    counts[path] = position + 1
    return path if position == 0 else f"{path}#{position}"


def _store_code_inventory(job, result):
    source = job.source
    asset_ids = []
    for item in result["findings"]:
        obj, _ = upsert_asset(source.organization, source, {
            "name": item["algorithm"], "algorithm": item["algorithm"], "purpose": item["purpose"],
            "application": source.name, "source_location": f"{item['file']}:{item['line']}",
            "crypto_functions": [item["function"]], "environment": "unknown",
            "metadata": _evidence("static_code_match", "heuristic", snippet=item["snippet"],
                                  requires_confirmation=True),
        })
        asset_ids.append(obj.id)
    for name, item in result["libraries"].items():
        CryptoLibrary.objects.update_or_create(
            organization=source.organization, name=name, version=item.get("version", ""),
            defaults={"language": item.get("language", ""), "source": item.get("file", "")})
        obj, _ = upsert_asset(source.organization, source, {
            "name": name, "algorithm": name, "asset_type": "library", "purpose": "implementation",
            "application": source.name, "source_location": item.get("file", ""), "library": name,
            "environment": "unknown", "metadata": _evidence("dependency_manifest", "observed",
                                                                 version=item.get("version", "")),
        })
        asset_ids.append(obj.id)
    per_file = {}
    for item in result["keys"]:
        algorithm = "RSA" if "RSA" in item["type"] else "EC" if "EC " in item["type"] else "Unknown"
        location = _numbered_location(per_file, item["file"])
        key = CryptoKey.objects.create(organization=source.organization, name=f"Key in {item['file']}",
                                       algorithm=algorithm, storage="file")
        obj, _ = upsert_asset(source.organization, source, {
            "name": f"{algorithm} private key", "algorithm": algorithm, "asset_type": "key",
            "purpose": "unknown", "application": source.name, "source_location": location, "key": key,
            "environment": "unknown", "metadata": _evidence("private_key_header", "observed",
                                                                 sensitive_content_stored=False),
        })
        asset_ids.append(obj.id)
    per_file = {}
    per_file = {}
    for item in result["certificates"]:
        try:
            parsed = x509.load_pem_x509_certificate(item["text"].encode())
        except ValueError:
            continue
        key_algorithm, key_size, algorithm = _public_key_asset(parsed.public_key())
        certificate = CryptoCertificate.objects.create(
            organization=source.organization, subject=parsed.subject.rfc4514_string(),
            issuer=parsed.issuer.rfc4514_string(), serial_number=str(parsed.serial_number),
            not_before=parsed.not_valid_before_utc, not_after=parsed.not_valid_after_utc,
            key_algorithm=key_algorithm, key_size=key_size,
            signature_algorithm=parsed.signature_algorithm_oid._name or parsed.signature_algorithm_oid.dotted_string,
            is_self_signed=parsed.issuer == parsed.subject, is_demo=source.is_demo)
        location = _numbered_location(per_file, item["file"])
        obj, _ = upsert_asset(source.organization, source, {
            "name": algorithm, "algorithm": algorithm, "asset_type": "certificate",
            "purpose": "digital_signature", "application": source.name, "source_location": location,
            "key_size": key_size, "certificate": certificate, "environment": "unknown",
            "metadata": _evidence("certificate_file", "observed"),
        })
        asset_ids.append(obj.id)
    result["provenance"] = {"evidence_type": "static_analysis", "confidence": "heuristic",
                            "notice": "Matches indicate code or configuration references and require confirmation."}
    ScanResult.objects.create(organization=source.organization, job=job, result_type="code", data=result)
    return {
        "files_scanned": result["files"], "crypto_references": len(result["findings"]),
        "libraries": len(result["libraries"]), "certificates": len(result["certificates"]),
        "keys": len(result["keys"]), "protocols": 0, "_asset_ids": asset_ids,
    }


def _store_tls(job, observed):
    source = job.source
    cert_data = observed["certificate"]
    observed = {**observed, "protocol": observed["protocol"].replace("TLSv", "TLS ")}
    # Older probe results (and callers without an OpenSSL CLI) carry no group; derive
    # the key exchange from the negotiated suite instead.
    kex = observed.get("key_exchange") or {
        "group": None, "evidence": "cipher_suite",
        "algorithm": key_exchange_from_suite(observed["protocol"], observed.get("cipher_suite"))}
    certificate = CryptoCertificate.objects.create(
        organization=source.organization, subject=cert_data["subject"], issuer=cert_data["issuer"],
        serial_number=cert_data["serial_number"], not_before=cert_data["not_before"],
        not_after=cert_data["not_after"], key_algorithm=cert_data["key_algorithm"],
        key_size=cert_data["key_size"], signature_algorithm=cert_data["signature_algorithm"],
        san=cert_data["san"], host=observed["host"], is_self_signed=cert_data["is_self_signed"], is_demo=False)
    common = {"application": source.name, "environment": "observed", "internet_exposed": True}
    kex_bits = re.search(r"-(\d{4})$", kex["algorithm"])
    records = [
        {"name": version, "algorithm": version, "variant": version.replace("TLS ", ""),
         "asset_type": "protocol", "purpose": "transport_security", "protocol": version,
         "source_location": f"{observed['host']}:{observed['port']}" + ("" if version == observed["protocol"] else " (legacy)")}
        for version in observed.get("supported_versions") or [observed["protocol"]]
    ] + [
        {"name": kex["algorithm"], "algorithm": kex["algorithm"], "asset_type": "algorithm",
         "purpose": "key_exchange", "protocol": observed["protocol"],
         "key_size": int(kex_bits.group(1)) if kex_bits else None},
        {"name": observed["cipher_algorithm"], "algorithm": observed["cipher_algorithm"],
         "asset_type": "algorithm", "purpose": "symmetric_encryption", "key_size": observed["cipher_bits"]},
        {"name": cert_data["key_asset"], "algorithm": cert_data["key_asset"], "asset_type": "certificate",
         "purpose": "digital_signature", "key_size": cert_data["key_size"], "certificate": certificate},
    ]
    asset_ids = []
    for record in records:
        obj, _ = upsert_asset(source.organization, source, {
            **common, **record, "metadata": _evidence(
                "tls_handshake", "observed", host=observed["host"], port=observed["port"],
                certificate_verified=observed["verified"], cipher_suite=observed["cipher_suite"],
                key_exchange_group=kex.get("group"), key_exchange_evidence=kex.get("evidence")),
        })
        asset_ids.append(obj.id)
    CryptoProtocol.objects.update_or_create(
        organization=source.organization, name="TLS", host=observed["host"],
        defaults={"version": observed["protocol"].replace("TLS ", ""), "cipher_suites": [observed["cipher_suite"]],
                  "supports_pqc_kem": catalog.family_of(kex["algorithm"]) in ("Hybrid-KEM", "ML-KEM")})
    payload = {**observed, "certificate": {**cert_data, "not_before": cert_data["not_before"].isoformat(),
                                            "not_after": cert_data["not_after"].isoformat()},
               "provenance": {"evidence_type": "tls_handshake", "confidence": "observed"}}
    ScanResult.objects.create(organization=source.organization, job=job, result_type="tls", data=payload)
    return {"files_scanned": 0, "crypto_references": len(records), "libraries": 0, "certificates": 1,
            "keys": 0, "protocols": len(observed.get("supported_versions") or [1]), "_asset_ids": asset_ids}


def _verify_completed_migrations(org, source, stale, observed_ids):
    """A migration marked done replaced the inventory record with its target. If
    the scan still observes the original algorithm at the same location, the
    migration did not land: alert, and move the task back to in progress."""
    migrated = [a for a in stale if (a.metadata or {}).get("migrated_from")]
    if not migrated:
        return
    observed = {(a.source_location, a.algorithm): a
                for a in CryptoAsset.objects.filter(id__in=observed_ids)}
    for asset in migrated:
        still_there = observed.get((asset.source_location, asset.metadata["migrated_from"]))
        if still_there is None:
            continue
        create_alert(org, "high", "pqc_verification_failed",
                     f"{asset.metadata['migrated_from']} still observed in {source.name}",
                     f"A migration to {asset.algorithm} was marked complete, but the latest scan still observes "
                     f"{asset.metadata['migrated_from']} at {asset.source_location or source.name}.", still_there)
        MigrationTask.objects.filter(organization=org, asset=asset).update(
            asset=still_there, status="in_progress",
            notes=f"Reopened {timezone.now():%Y-%m-%d}: scan evidence still shows {asset.metadata['migrated_from']}.")


def _source_risk(source):
    scores = list(source.assets.values_list("risk_score", flat=True))
    if not scores:
        return 0, "safe"
    top = sorted(scores, reverse=True)[:max(1, len(scores) // 4)]
    score = round(0.5 * sum(scores) / len(scores) + 0.5 * sum(top) / len(top))
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    return score, level


def _create_follow_up(org, assets):
    from apps.comparison.comparison_service import candidate_names
    project = None
    for asset in assets:
        if asset.risk_level not in ("critical", "high", "medium"):
            continue
        if asset.quantum_status in ("vulnerable", "weak_classical"):
            create_alert(org, asset.risk_level, "vulnerable_algorithm", f"Review {asset.name} in {asset.application}",
                         "Generated from discovery evidence. Confirm heuristic findings before remediation.", asset)
        candidates = candidate_names(asset)
        if asset.quantum_status != "vulnerable" or not candidates:
            continue
        if project is None:
            project, _ = MigrationProject.objects.get_or_create(
                organization=org, name="Quantum-safe migration", defaults={"current_phase": "planning"})
        MigrationTask.objects.get_or_create(
            organization=org, project=project, asset=asset,
            defaults={"title": f"Migrate {asset.name} in {asset.application}", "current_algorithm": asset.algorithm,
                      "target_algorithm": candidates[0], "migration_path": ["Classical", "Hybrid", "PQC"],
                      "purpose": asset.purpose, "risk_level": asset.risk_level, "phase": "planning",
                      "priority": 1 if asset.risk_level == "critical" else 2})


def run_scan(job_id):
    close_old_connections()
    job = ScanJob.objects.select_related("source", "source__organization").get(pk=job_id)
    source, org = job.source, job.organization
    previous_assets = set(source.assets.values_list("name", "source_location", "purpose"))
    had_previous_scan = source.last_scan_at is not None
    job.status, job.started_at = "running", timezone.now()
    job.save(update_fields=["status", "started_at", "updated_at"])
    counters = {"files_scanned": 0, "crypto_references": 0, "algorithms": 0, "libraries": 0,
                "certificates": 0, "keys": 0, "protocols": 0, "assets": 0}
    try:
        _progress(job, 0, counters)
        collector = COLLECTORS.get(source.source_type)
        if collector is None:
            raise ServiceError("unsupported_source", f"Discovery is not implemented for {source.source_type}.")
        kind, collected = collector(job)
        # All inventory changes for this scan commit together: a failure part-way
        # leaves the previous inventory intact instead of half-replaced.
        with transaction.atomic():
            scan_data = _store_code_inventory(job, collected) if kind == "code" else _store_tls(job, collected)
            observed_ids = scan_data.pop("_asset_ids", [])
            counters.update(scan_data)
            stale = list(source.assets.exclude(id__in=observed_ids))
            _verify_completed_migrations(org, source, stale, observed_ids)
            from apps.alerts.models import Alert
            Alert.objects.filter(asset__in=stale, status__in=("open", "acknowledged")).update(
                status="resolved", resolved_at=timezone.now())
            MigrationTask.objects.filter(asset__in=stale, status="backlog").delete()
            CryptoAsset.objects.filter(id__in=[a.id for a in stale]).delete()
            CryptoCertificate.objects.filter(organization=org, assets__isnull=True).delete()
            CryptoKey.objects.filter(organization=org, assets__isnull=True).delete()
        current_assets = set(source.assets.values_list("name", "source_location", "purpose"))
        if had_previous_scan and not source.is_demo:
            from apps.monitoring.monitoring_service import record_event
            added, removed = current_assets - previous_assets, previous_assets - current_assets
            if added:
                record_event(org, "new_asset", f"{len(added)} cryptographic asset(s) added",
                             "The latest evidence differs from the previous successful scan.", "medium", source)
            if removed:
                record_event(org, "crypto_change", f"{len(removed)} cryptographic asset(s) no longer observed",
                             "The latest evidence no longer contains these prior records.", "low", source)
        _progress(job, 1, counters)
        counters["assets"] = source.assets.count()
        counters["algorithms"] = source.assets.values("algorithm").distinct().count()
        _progress(job, 2, counters)
        _progress(job, 3, counters)
        if counters["assets"]:
            generate_for_org(org, source=source, is_demo=source.is_demo)
        _progress(job, 4, counters)
        assess_organization(org)  # also rebuilds the architecture graph
        source_assets = list(source.assets.all())
        _create_follow_up(org, source_assets)
        _progress(job, 5, counters)
        source.risk_score, source.risk_level = _source_risk(source)
        source.asset_count = len(source_assets)
        source.status = "active"
        source.last_scan_at = timezone.now()
        source.save(update_fields=["asset_count", "risk_score", "risk_level", "status", "last_scan_at", "updated_at"])
        job.status, job.progress, job.finished_at = "completed", 100, timezone.now()
        job.counters = counters
        job.save(update_fields=["status", "progress", "finished_at", "counters", "updated_at"])
    except Exception as exc:
        source.status = "error"
        source.save(update_fields=["status", "updated_at"])
        message = getattr(exc, "message", None) or str(exc)
        job.status, job.error, job.finished_at = "failed", message, timezone.now()
        job.save(update_fields=["status", "error", "finished_at", "updated_at"])
        create_alert(org, "high", "scan_failed", f"Discovery failed for {source.name}", message)
    finally:
        close_old_connections()


def recover_stale_scans(source=None):
    """Fail jobs whose worker died and release their sources. Returns the count."""
    cutoff = timezone.now() - STALE_SCAN_AFTER
    jobs = ScanJob.objects.filter(status__in=ACTIVE_JOB_STATUSES, updated_at__lt=cutoff)
    if source is not None:
        jobs = jobs.filter(source=source)
    source_ids = set(jobs.values_list("source_id", flat=True))
    count = jobs.update(status="failed", finished_at=timezone.now(),
                        error="The scan was interrupted before it finished (worker restarted). Start a new scan.")
    stuck = AssetSource.objects.filter(id__in=source_ids, status="scanning")
    stuck.exclude(scans__status__in=ACTIVE_JOB_STATUSES).update(status="error", updated_at=timezone.now())
    return count


def create_scan(source, user=None):
    recover_stale_scans(source)
    # Atomically claim the source: two concurrent requests (or a monitoring run
    # overlapping a manual one) cannot both start a scan of the same source.
    claimed = AssetSource.objects.filter(pk=source.pk).exclude(status="scanning").update(
        status="scanning", updated_at=timezone.now())
    if not claimed:
        raise ServiceError("scan_in_progress", "This source is already being scanned.", 409)
    source.status = "scanning"
    mode = "simulated" if source.is_demo else "evidence"
    job = ScanJob.objects.create(organization=source.organization, source=source, stages=STAGES,
                                 triggered_by=user, mode=mode)
    log_action(None, "start_scan", job, user=user, organization=source.organization)
    if settings.SCAN_SYNC:
        run_scan(job.id)
        job.refresh_from_db()
    elif settings.CELERY_ENABLED:
        from .tasks import run_scan_task
        transaction.on_commit(lambda: run_scan_task.delay(str(job.id)))
    else:
        transaction.on_commit(lambda: threading.Thread(target=run_scan, args=(job.id,), daemon=True).start())
    return job
