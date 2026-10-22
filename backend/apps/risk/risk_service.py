"""Transparent, configurable risk scoring.

score = sum(factor_score_i * weight_i) / sum(weight_i)      (all factor scores 0-100)

Every factor returns (score, explanation). The full component list is stored on
each RiskFinding so a score can always be explained. Weights (RiskFactor rows) and
thresholds (org.settings["risk"]["thresholds"]) are configurable per organization.
"""
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.inventory import catalog
from apps.inventory.models import CryptoAsset
from apps.organizations.defaults import merged_settings

from .models import RiskAssessment, RiskFactor, RiskFinding

FACTORS = {
    "quantum_vulnerability": ("Quantum vulnerability", "Whether the algorithm is broken by a cryptographically relevant quantum computer (Shor) or weakened (Grover)."),
    "algorithm_strength": ("Algorithm strength", "Classical strength and standing of the algorithm / key size (deprecated or broken primitives score high)."),
    "business_criticality": ("Business criticality", "Importance of the application the asset protects."),
    "data_sensitivity": ("Data sensitivity", "Sensitivity and required confidentiality lifetime of the protected data."),
    "internet_exposure": ("Internet exposure", "Whether the asset is reachable from the internet."),
    "hndl_exposure": ("HNDL exposure", "Harvest-now-decrypt-later: recorded traffic protected by a quantum-vulnerable key exchange can be decrypted later."),
    "certificate_expiry": ("Certificate risk", "Certificate expiry proximity for certificate-bound assets."),
    "migration_complexity": ("Migration complexity", "Effort to replace: dependents, library PQC support, exposure."),
    "asset_dependency": ("Asset dependency", "How many other assets / applications depend on this asset."),
}
DEFAULT_WEIGHTS = {"quantum_vulnerability": 25, "algorithm_strength": 10, "business_criticality": 15,
                   "data_sensitivity": 10, "internet_exposure": 10, "hndl_exposure": 10,
                   "certificate_expiry": 5, "migration_complexity": 5, "asset_dependency": 10}

Q_SCORE = {"vulnerable": 100, "weak_classical": 55, "protocol_dependent": 40, "symmetric_review": 30,
           "hash_review": 15, "unknown": 30, "adequate": 5, "pq_hybrid": 5, "pq_standardized": 0}
SAFE_QUANTUM = ("pq_standardized", "pq_hybrid", "adequate")
Q_TEXT = {
    "vulnerable": "Public-key scheme broken by Shor's algorithm on a large fault-tolerant quantum computer.",
    "weak_classical": "Deprecated/broken classically; also not a sound long-term choice.",
    "protocol_dependent": "Depends on the negotiated key exchange and signature algorithms.",
    "symmetric_review": "Symmetric primitive: Grover's algorithm reduces the margin; analyse key size separately.",
    "hash_review": "Hash function: analyse collision/preimage needs separately; generally not a PQC replacement target.",
    "adequate": "Believed adequate against quantum adversaries under current analysis.",
    "pq_standardized": "Standardized / designed for post-quantum security.",
    "pq_hybrid": "Hybrid key establishment: classical + ML-KEM; secure while either component remains unbroken.",
    "unknown": "Quantum posture unknown; manual review needed.",
}


def ensure_factors(org):
    existing = {f.key: f for f in RiskFactor.objects.filter(organization=org)}
    for key, (label, desc) in FACTORS.items():
        if key not in existing:
            existing[key] = RiskFactor.objects.create(organization=org, key=key, label=label,
                                                     description=desc, weight=DEFAULT_WEIGHTS[key])
    return list(existing.values())


def get_config(org):
    factors = ensure_factors(org)
    weights = {f.key: (f.weight if f.enabled else 0) for f in factors}
    thresholds = merged_settings(org)["risk"]["thresholds"]
    return {"weights": weights, "thresholds": thresholds}


def level_for(score, thresholds, quantum=""):
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    if quantum in SAFE_QUANTUM and score < thresholds["medium"]:
        return "safe"
    return "low"


def _algorithm_strength(asset, q):
    fam = catalog.family_of(asset.algorithm)
    if fam in ("RSA", "DH", "DSA", "ECDSA", "ECDH") and not asset.key_size and "unknown" in asset.algorithm.lower():
        return 50, "Key size or parameter set was not present in the observed source; confirm it manually."
    if fam in catalog.WEAK_CLASSICAL_FAMILIES:
        return 100, f"{asset.algorithm} is deprecated/broken against classical attackers."
    if fam == "AES" and "ECB" in f"{asset.algorithm} {asset.variant}".upper():
        return 100, "ECB mode leaks plaintext structure; use an authenticated mode such as GCM."
    if fam == "TLS" and q == "weak_classical":
        return 100, "Legacy protocol version (SSL/TLS <= 1.1) is insecure."
    bits = catalog.classical_security_bits(asset.algorithm, asset.key_size)
    if fam in catalog.PQC_FAMILIES:
        return 5, "Standardized PQC parameter set."
    if fam == "Hybrid-KEM":
        return 5, "Hybrid classical + ML-KEM key establishment."
    if fam == "TLS":
        return 35 if "1.2" in asset.variant + asset.name else 10, "TLS 1.2 is acceptable but 1.3 is preferred." if "1.2" in asset.variant + asset.name else "TLS 1.3 in use."
    if bits < 112:
        return 100, f"~{bits}-bit classical strength is below the 112-bit minimum."
    if bits == 112:
        return 65, "~112-bit classical strength (the draft NIST IR 8547 transition timeline proposes deprecation after 2030)."
    if bits <= 128:
        return 35, f"~{bits}-bit classical strength."
    return 12, f"~{bits}-bit classical strength."


def _hndl(asset, q):
    if asset.purpose in ("key_exchange", "transport_security", "symmetric_encryption") and q in ("vulnerable", "protocol_dependent"):
        base = 60 if q == "vulnerable" else 35
        return min(100, round(base + 0.4 * asset.data_sensitivity)), \
            "Recorded traffic protected by this key establishment could be decrypted once a quantum computer exists (HNDL)."
    if asset.purpose == "digital_signature" and q == "vulnerable":
        return 20, "Signatures are forgeable only by an attacker with a quantum computer at signing/verification time; HNDL risk is low."
    return 5, "No confidentiality-related HNDL exposure identified."


def _cert(asset, now):
    cert = asset.certificate
    if not cert or not cert.not_after:
        return 0, "Not bound to a certificate."
    days = (cert.not_after - now).days
    if days < 0:
        return 100, f"Certificate expired {-days} days ago."
    if days < 30:
        return 90, f"Certificate expires in {days} days."
    if days < 90:
        return 60, f"Certificate expires in {days} days."
    if days < 365:
        return 30, f"Certificate expires in {days} days."
    return 10, f"Certificate valid for {days} more days."


def score_asset(asset, config, now=None):
    now = now or timezone.now()
    n_dependents = asset.dependents.count() if asset.pk else 0
    n_deps = asset.depends_on.count() if asset.pk else 0
    # Always re-derive from the algorithm/key size/variant, never trust the cached
    # asset.quantum_status field as an input - it is a stored *output* of this
    # function, and trusting it here would mean an edited/migrated algorithm could
    # never be reclassified (see the migration-completion and direct-edit fixes).
    quantum = catalog.quantum_status(asset.algorithm, asset.key_size, asset.variant)
    q_score = Q_SCORE.get(quantum, 30)
    mig = min(100, 20 + 12 * n_dependents + (15 if asset.internet_exposed else 0) + (20 if asset.library and "oqs" not in asset.library.lower() else 0))
    dep = min(100, 10 + 15 * (n_dependents + n_deps))
    scores = {
        "quantum_vulnerability": (q_score, Q_TEXT.get(quantum, "")),
        "algorithm_strength": _algorithm_strength(asset, quantum),
        "business_criticality": (asset.business_criticality, f"Business criticality rated {asset.business_criticality}/100 for {asset.application or 'this asset'}."),
        "data_sensitivity": (asset.data_sensitivity, f"Data sensitivity rated {asset.data_sensitivity}/100."),
        "internet_exposure": (100, "Internet-facing.") if asset.internet_exposed else (25, "Internal only."),
        "hndl_exposure": _hndl(asset, quantum),
        "certificate_expiry": _cert(asset, now),
        "migration_complexity": (mig, f"{n_dependents} dependent asset(s); library {asset.library or 'unknown'}."),
        "asset_dependency": (dep, f"{n_dependents} dependent / {n_deps} dependency link(s)."),
    }
    weights = config["weights"]
    total_w = sum(weights.values()) or 1
    components, total = [], 0.0
    for key, (label, _d) in FACTORS.items():
        s, expl = scores[key]
        w = weights.get(key, 0)
        contribution = s * w / total_w
        total += contribution
        components.append({"factor": key, "label": label, "score": int(round(s)), "weight": w,
                           "contribution": round(contribution, 2), "explanation": expl})
    score = int(round(total))
    return {"score": score, "level": level_for(score, config["thresholds"], quantum), "quantum_status": quantum,
            "components": components}


def _finding_text(asset, result, candidates):
    q = result["quantum_status"]
    purpose = catalog.PURPOSE_LABELS.get(asset.purpose, asset.purpose or "use")
    if q == "vulnerable":
        title = f"{asset.name} ({purpose.lower()}) is quantum-vulnerable"
    elif q == "weak_classical":
        title = f"{asset.name} is deprecated / classically weak"
    elif q == "symmetric_review":
        title = f"{asset.name} needs symmetric-strength review"
    elif q == "protocol_dependent":
        title = f"{asset.name} depends on classical key exchange/authentication"
    else:
        title = f"{asset.name}: elevated risk"
    top = sorted(result["components"], key=lambda c: -c["contribution"])[:3]
    reason = " ".join(f"[{c['label']} {c['score']}/100] {c['explanation']}" for c in top)
    if q == "vulnerable" and candidates:
        action = (f"Evaluate {', '.join(candidates[:3])} for {purpose.lower()} (hybrid first where supported); "
                  "benchmark in your environment before committing.")
    elif q == "weak_classical":
        action = "Replace with a current classical algorithm now (e.g. AES-256-GCM / SHA-256+ / TLS 1.3); this is not a PQC question."
    elif q == "symmetric_review":
        action = "Prefer 256-bit keys (AES-256) for long-lived confidentiality; ensure key establishment is quantum-safe."
    elif q == "protocol_dependent":
        action = "Enable a hybrid ML-KEM key exchange group where supported and plan PQ signature migration for the certificate chain."
    else:
        action = "Review and monitor."
    return title, reason, action


SEVERITY_RANK = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FINDING_STATUSES = ("open", "accepted", "false_positive", "resolved")
ASSESSMENT_HISTORY = 50


@transaction.atomic
def assess_organization(org, assets=None):
    """Re-score assets, regenerate findings, store a RiskAssessment snapshot, raise
    alerts for genuine escalations, and refresh the architecture graph.

    This is the single choke point every asset-affecting action (a scan, a
    completed migration, a CBOM import, an edited asset, a changed risk weight)
    must call so that risk scores, findings, alerts and the dependency graph
    never drift out of sync with the inventory.
    """
    from apps.alerts.alert_service import create_alert
    from apps.comparison.comparison_service import candidate_names
    from apps.inventory.architecture_service import rebuild_architecture
    config = get_config(org)
    assets = list(assets if assets is not None else CryptoAsset.objects.filter(organization=org)
                  .select_related("certificate").prefetch_related("dependents", "depends_on"))
    previous_levels = {a.pk: a.risk_level for a in assets}
    now = timezone.now()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
    factor_sums = {k: 0 for k in FACTORS}
    old_findings = RiskFinding.objects.filter(organization=org, asset__in=[a.pk for a in assets])
    # Findings are regenerated, but a human triage decision (accepted / false
    # positive / resolved) must survive while the asset's severity is unchanged.
    triaged = {(f.asset_id, f.severity): f.status for f in old_findings.exclude(status="open")}
    old_findings.delete()
    findings, updates = [], []
    scores = []
    assessment = RiskAssessment.objects.create(organization=org, config_snapshot=config)
    for a in assets:
        r = score_asset(a, config, now)
        prev_level = previous_levels[a.pk]
        a.risk_score, a.risk_level, a.quantum_status = r["score"], r["level"], r["quantum_status"]
        updates.append(a)
        counts[r["level"]] += 1
        scores.append(r["score"])
        for c in r["components"]:
            factor_sums[c["factor"]] += c["score"]
        if r["level"] in ("critical", "high", "medium"):
            title, reason, action = _finding_text(a, r, candidate_names(a))
            findings.append(RiskFinding(organization=org, assessment=assessment, asset=a, title=title,
                                        severity=r["level"], score=r["score"], reason=reason,
                                        recommended_action=action, components=r["components"],
                                        status=triaged.get((a.pk, r["level"]), "open")))
        # Alert only on a genuine escalation into high/critical, whatever triggered this
        # reassessment (scan, migration, CBOM import, edited asset, changed risk weights) -
        # not on every reassessment of an asset that was already at that level.
        if r["level"] in ("high", "critical") and SEVERITY_RANK[r["level"]] > SEVERITY_RANK.get(prev_level, 0):
            create_alert(org, r["level"], "risk_increased",
                        f"Risk increased for {a.name} in {a.application or 'unassigned'}",
                        f"Risk moved from {prev_level} to {r['level']} ({r['score']}/100) after reassessment.", a)
    CryptoAsset.objects.bulk_update(updates, ["risk_score", "risk_level", "quantum_status"], batch_size=500)
    RiskFinding.objects.bulk_create(findings, batch_size=500)
    # Migration tasks show their asset's risk; keep that copy current rather than
    # frozen at whatever level the asset had when the task was created.
    from apps.migration.models import MigrationTask
    by_level = {}
    for a in updates:
        by_level.setdefault(a.risk_level, []).append(a.pk)
    for level, ids in by_level.items():
        MigrationTask.objects.filter(organization=org, asset_id__in=ids).exclude(risk_level=level).update(risk_level=level)
    n = len(assets)
    if n:
        top = sorted(scores, reverse=True)[:max(1, n // 4)]
        overall = round(0.5 * sum(scores) / n + 0.5 * sum(top) / len(top))
    else:
        overall = 0
    assessment.overall_score = overall
    assessment.level = level_for(overall, config["thresholds"]) if n else "safe"
    assessment.counts = counts
    assessment.asset_count = n
    assessment.factor_averages = {k: round(v / n, 1) if n else 0 for k, v in factor_sums.items()}
    assessment.save()
    # Keep a bounded history; every scan and edit creates a snapshot.
    stale_ids = list(RiskAssessment.objects.filter(organization=org).values_list("id", flat=True)[ASSESSMENT_HISTORY:])
    if stale_ids:
        RiskAssessment.objects.filter(id__in=stale_ids).delete()
    rebuild_architecture(org)
    return assessment


def latest_assessment(org):
    return RiskAssessment.objects.filter(organization=org).first()
