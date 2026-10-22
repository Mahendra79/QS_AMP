"""Side effects of migration work actually landing.

Moving a MigrationTask's Kanban card is, by itself, only a task-tracking action -
it does not change what QS-AMP knows about the asset. That is deliberate (a task
can be marked "completed" as a process step before the code ships), but once a
task reaches a state that means the new algorithm is genuinely in place, the
underlying CryptoAsset - and therefore risk scoring, the dashboard, findings and
alerts - must be updated to match. Without this, "quantum risk" would never move
even after every task is closed.
"""
from apps.inventory import catalog

DONE_STATUSES = ("verified", "completed")
UNSAFE_TARGET_STATUSES = ("vulnerable", "weak_classical")
PURPOSE_FAMILIES = {
    "key_exchange": ("ML-KEM", "Hybrid-KEM"),
    "digital_signature": ("ML-DSA", "SLH-DSA"),
    "symmetric_encryption": ("AES", "ChaCha20"),
    "hashing": ("SHA-2", "SHA-3"),
    "transport_security": ("TLS",),
}


def is_algorithm(target):
    return catalog.family_of((target or "").strip()) != "Other"


def target_problem(target, purpose=""):
    """Return why `target` is not a valid migration target for `purpose`, or None.

    A recognised algorithm target is written into the inventory when the task
    completes, so it must be safe and of the same kind as what it replaces (a KEM
    cannot replace a signature). A free-text target ("Review protocol components")
    describes process work only and never rewrites the inventory."""
    target = (target or "").strip()
    if not is_algorithm(target):
        return None
    family = catalog.family_of(target)
    if catalog.quantum_status(target) in UNSAFE_TARGET_STATUSES:
        return f"{target} is itself quantum-vulnerable or classically weak and cannot be a migration target."
    allowed = PURPOSE_FAMILIES.get(purpose)
    if allowed and family not in allowed:
        return f"{target} cannot replace an algorithm used for {catalog.PURPOSE_LABELS.get(purpose, purpose).lower()}; use {' / '.join(allowed)}."
    return None


def apply_completed_migration(task):
    """Called when a task transitions into a done state. Updates the linked
    CryptoAsset to the migrated algorithm and re-runs org-wide risk scoring."""
    asset = task.asset
    if asset is None or not task.target_algorithm:
        return None
    new_name = task.target_algorithm.strip()
    if not new_name or asset.algorithm == new_name:
        return None  # already reflects this target (e.g. re-saving "completed")
    if not is_algorithm(new_name) or target_problem(new_name, asset.purpose):
        return None  # process-only target (free text) or not a valid replacement: inventory unchanged

    previous_algorithm = asset.algorithm
    asset.algorithm = new_name
    asset.name = new_name
    asset.variant = ""
    asset.key_size = None  # classical bit-length no longer applies to a PQC parameter set
    asset.primitive = catalog.primitive_for(new_name, asset.purpose)
    asset.quantum_status = catalog.quantum_status(new_name)
    asset.pqc_candidates = []
    # This change is *declared* by whoever closed the task, not observed. It is
    # labelled as such, and the next discovery scan of the source verifies it
    # (see discovery_service._verify_completed_migrations).
    asset.metadata = {**(asset.metadata or {}), "migrated_from": previous_algorithm,
                      "migration_task_id": str(task.id), "evidence_type": "migration_declared",
                      "confidence": "declared", "requires_verification": True}
    asset.save(update_fields=["algorithm", "name", "variant", "key_size", "primitive",
                              "quantum_status", "pqc_candidates", "metadata", "updated_at"])

    from django.utils import timezone

    from apps.alerts.models import Alert
    Alert.objects.filter(organization=task.organization, asset=asset, status__in=("open", "acknowledged")).update(
        status="resolved", resolved_at=timezone.now())

    from apps.risk.risk_service import assess_organization
    return assess_organization(task.organization)
