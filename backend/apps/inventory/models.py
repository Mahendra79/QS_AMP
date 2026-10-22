import uuid

from django.db import models

from apps.organizations.models import OrgOwned


class AlgorithmBase(models.Model):
    """Shared metadata for the (configurable) algorithm database."""
    name = models.CharField(max_length=80, unique=True)
    family = models.CharField(max_length=60)
    primitive = models.CharField(max_length=40)      # pke | kem | key-agree | signature | block-cipher | hash | mac | kdf
    purpose = models.CharField(max_length=40)        # key_exchange | digital_signature | symmetric_encryption | hashing ...
    security_category = models.CharField(max_length=60, blank=True)
    quantum_status = models.CharField(max_length=30)  # vulnerable | symmetric_review | hash_review | pq_standardized ...
    classical_status = models.CharField(max_length=30, default="acceptable")  # acceptable | deprecated | broken
    standard = models.CharField(max_length=120, blank=True)
    public_key_size = models.IntegerField(null=True, blank=True, help_text="bytes")
    private_key_size = models.IntegerField(null=True, blank=True, help_text="bytes")
    output_size = models.IntegerField(null=True, blank=True, help_text="ciphertext / signature / digest bytes")
    output_kind = models.CharField(max_length=20, blank=True)
    typical_usage = models.TextField(blank=True)
    migration_notes = models.TextField(blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        abstract = True
        ordering = ["family", "name"]

    def __str__(self):
        return self.name


class CryptoAlgorithm(AlgorithmBase):
    """Classical algorithm reference data (global, admin-configurable)."""


class CryptoLibrary(OrgOwned):
    name = models.CharField(max_length=120)
    version = models.CharField(max_length=40, blank=True)
    language = models.CharField(max_length=40, blank=True)
    source = models.CharField(max_length=200, blank=True)
    supports_pqc = models.BooleanField(default=False)

    class Meta:
        unique_together = ("organization", "name", "version")


class CryptoCertificate(OrgOwned):
    subject = models.CharField(max_length=300)
    issuer = models.CharField(max_length=300, blank=True)
    serial_number = models.CharField(max_length=120, blank=True)
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)
    key_algorithm = models.CharField(max_length=40, blank=True)
    key_size = models.IntegerField(null=True, blank=True)
    signature_algorithm = models.CharField(max_length=80, blank=True)
    san = models.JSONField(default=list, blank=True)
    host = models.CharField(max_length=255, blank=True)
    is_self_signed = models.BooleanField(default=False)
    is_demo = models.BooleanField(default=False)

    class Meta:
        ordering = ["not_after"]


class CryptoKey(OrgOwned):
    name = models.CharField(max_length=200)
    algorithm = models.CharField(max_length=60)
    key_size = models.IntegerField(null=True, blank=True)
    purpose = models.CharField(max_length=60, blank=True)
    storage = models.CharField(max_length=60, blank=True)  # hsm | kms | file | env
    rotation_days = models.IntegerField(null=True, blank=True)


class CryptoProtocol(OrgOwned):
    name = models.CharField(max_length=40)       # TLS | SSH | IPsec
    version = models.CharField(max_length=20)
    cipher_suites = models.JSONField(default=list, blank=True)
    host = models.CharField(max_length=255, blank=True)
    supports_pqc_kem = models.BooleanField(default=False)


class RiskLevel(models.TextChoices):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class CryptoAsset(OrgOwned):
    source = models.ForeignKey("discovery.AssetSource", null=True, blank=True, on_delete=models.CASCADE,
                               related_name="assets")
    asset_ref = models.CharField(max_length=20, blank=True, db_index=True)  # human readable id, e.g. CA-000123
    name = models.CharField(max_length=200)
    asset_type = models.CharField(max_length=30, default="algorithm")  # algorithm|key|certificate|protocol|library
    application = models.CharField(max_length=120, blank=True, db_index=True)
    algorithm = models.CharField(max_length=60, db_index=True)         # RSA, ECDSA, AES, SHA-256, TLS ...
    variant = models.CharField(max_length=60, blank=True)              # 2048, P-256, AES-256-GCM
    primitive = models.CharField(max_length=40, blank=True)
    purpose = models.CharField(max_length=40, blank=True, db_index=True)
    key_size = models.IntegerField(null=True, blank=True)
    implementation_platform = models.CharField(max_length=80, blank=True)
    execution_environment = models.CharField(max_length=80, blank=True)
    crypto_functions = models.JSONField(default=list, blank=True)
    source_location = models.CharField(max_length=500, blank=True)
    library = models.CharField(max_length=120, blank=True)
    protocol = models.CharField(max_length=60, blank=True)
    certificate = models.ForeignKey(CryptoCertificate, null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name="assets")
    key = models.ForeignKey(CryptoKey, null=True, blank=True, on_delete=models.SET_NULL, related_name="assets")
    environment = models.CharField(max_length=60, blank=True, db_index=True)
    business_criticality = models.IntegerField(default=50)  # 0-100
    data_sensitivity = models.IntegerField(default=50)
    internet_exposed = models.BooleanField(default=False)
    risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=10, choices=RiskLevel.choices, default=RiskLevel.SAFE, db_index=True)
    quantum_status = models.CharField(max_length=30, blank=True, db_index=True)
    pqc_candidates = models.JSONField(default=list, blank=True)
    depends_on = models.ManyToManyField("self", symmetrical=False, blank=True, related_name="dependents")
    metadata = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_demo = models.BooleanField(default=False)

    class Meta:
        ordering = ["-risk_score", "name"]
        indexes = [models.Index(fields=["organization", "risk_level"])]
        constraints = [models.UniqueConstraint(fields=["organization", "asset_ref"], condition=~models.Q(asset_ref=""),
                                               name="unique_asset_ref_per_org")]

    def __str__(self):
        return f"{self.name} ({self.application})"


class ArchitectureNode(OrgOwned):
    key = models.CharField(max_length=120)
    label = models.CharField(max_length=200)
    node_type = models.CharField(max_length=30)  # internet|cdn|waf|lb|gateway|application|service|database|certificate|algorithm|library
    layer = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=10, default="safe")
    asset = models.ForeignKey(CryptoAsset, null=True, blank=True, on_delete=models.SET_NULL, related_name="arch_nodes")
    metadata = models.JSONField(default=dict, blank=True)
    migration_status = models.CharField(max_length=30, default="not_started")

    class Meta:
        unique_together = ("organization", "key")


class ArchitectureEdge(OrgOwned):
    source = models.ForeignKey(ArchitectureNode, on_delete=models.CASCADE, related_name="out_edges")
    target = models.ForeignKey(ArchitectureNode, on_delete=models.CASCADE, related_name="in_edges")
    relation = models.CharField(max_length=30, default="communicates_with")
