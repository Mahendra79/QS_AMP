import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.accounts.models import User
from apps.alerts.alert_service import create_alert
from apps.benchmarks.benchmark_service import run_benchmark
from apps.cbom.cbom_service import generate_for_org
from apps.comparison.models import PQCAlgorithm
from apps.discovery.models import AssetSource, SourceType
from apps.integrations.models import Integration
from apps.inventory import catalog
from apps.inventory.architecture_service import rebuild_architecture
from apps.inventory.models import CryptoAlgorithm, CryptoAsset, CryptoCertificate
from apps.inventory.inventory_service import upsert_asset
from apps.migration.models import MigrationProject, MigrationTask
from apps.monitoring.models import MonitoringConfiguration
from apps.monitoring.monitoring_service import record_event
from apps.risk.risk_service import assess_organization

from ...models import Organization
from ...services import create_organization


class Command(BaseCommand):
    help = "Create the deterministic QS-AMP demo organization and data."

    def add_arguments(self, parser):
        parser.add_argument("--reset", action="store_true", help="Replace the existing demo organization.")

    def handle(self, *args, **options):
        existing = Organization.objects.filter(slug="acme-financial-technologies", is_demo=True).first()
        if existing and options["reset"]:
            existing.delete()
            existing = None
        user, created = User.objects.get_or_create(email="demo@qsamp.local", defaults={"full_name": "Avery Chen"})
        if user.username != "demo":
            user.username = "demo"
            user.save(update_fields=["username"])
        if created or not user.has_usable_password():
            user.set_password("QuantumReady!2026")
            user.save(update_fields=["password"])
        org = existing or create_organization("Acme Financial Technologies", user, is_demo=True)
        if existing and CryptoAsset.objects.filter(organization=org).exists():
            self.stdout.write(self.style.SUCCESS("Demo data already exists. Use --reset to rebuild it."))
            return

        for row in catalog.CLASSICAL:
            CryptoAlgorithm.objects.update_or_create(name=row["name"], defaults={k: v for k, v in row.items() if k != "name"})
        for row in catalog.PQC:
            PQCAlgorithm.objects.update_or_create(name=row["name"], defaults={k: v for k, v in row.items() if k != "name"})

        source_specs = [
            ("payments.example.com", SourceType.WEBSITE, "https://payments.example.com"),
            ("payments-api", SourceType.GITHUB, "acme/payments-api"),
            ("auth-service", SourceType.GITHUB, "acme/auth-service"),
            ("customer-portal", SourceType.PUBLIC_REPO, "https://github.com/acme/customer-portal"),
            ("legacy-api", SourceType.ZIP, "legacy-api.zip"),
        ]
        sources = []
        for name, kind, target in source_specs:
            sources.append(AssetSource.objects.create(organization=org, name=name, source_type=kind, target=target,
                                                      status="active", monitoring_enabled=True, is_demo=True,
                                                      last_scan_at=timezone.now()))

        apps = ["payments-api", "auth-service", "customer-portal", "ledger-service", "fraud-engine",
                "identity-gateway", "mobile-bff", "partner-api", "settlement-worker", "billing-service",
                "card-vault", "reporting-api", "notification-service", "admin-console", "data-exporter",
                "legacy-api", "merchant-portal", "risk-service", "audit-pipeline", "token-service"]
        algorithms = ["RSA-2048", "ECDSA-P256", "ECDH-P256", "AES-256-GCM", "SHA-256", "SHA-1", "3DES", "TLS 1.2", "TLS 1.3"]
        purposes = {"RSA-2048": "key_exchange", "ECDSA-P256": "digital_signature", "ECDH-P256": "key_exchange",
                    "AES-256-GCM": "symmetric_encryption", "SHA-256": "hashing", "SHA-1": "hashing",
                    "3DES": "symmetric_encryption", "TLS 1.2": "transport_security", "TLS 1.3": "transport_security"}
        rng = random.Random(82471)
        certificates = []
        for i in range(12):
            certificates.append(CryptoCertificate.objects.create(
                organization=org, subject=f"CN={apps[i]}.acme.example", issuer="CN=Acme Internal CA",
                serial_number=f"ACME-{10000 + i}", not_before=timezone.now() - timedelta(days=180),
                not_after=timezone.now() + timedelta(days=20 + i * 73), key_algorithm="RSA" if i % 3 == 0 else "ECDSA",
                key_size=2048 if i % 3 == 0 else 256, signature_algorithm="sha256WithRSAEncryption" if i % 3 == 0 else "ecdsa-with-SHA256",
                host=f"{apps[i]}.acme.example", is_demo=True))

        created_assets = []
        for i in range(128):
            app = apps[i % len(apps)]
            algorithm = algorithms[(i * 5 + i // 9) % len(algorithms)]
            source = sources[i % len(sources)]
            key_size = 2048 if algorithm == "RSA-2048" else 256 if "256" in algorithm else None
            asset, _ = upsert_asset(org, source, {
                "name": algorithm, "algorithm": algorithm, "application": app, "purpose": purposes[algorithm],
                "key_size": key_size, "variant": algorithm.split("-", 1)[1] if "-" in algorithm else "",
                "asset_type": "protocol" if algorithm.startswith("TLS") else "algorithm",
                "source_location": f"services/{app}/security/crypto_{i % 7}.py:{18 + i}",
                "library": ["OpenSSL 3.0", "Java JCA", "cryptography 46", "BouncyCastle 1.78", "Node crypto"][i % 5],
                "environment": ["production", "staging", "development"][i % 3],
                "business_criticality": 45 + rng.randrange(56), "data_sensitivity": 35 + rng.randrange(66),
                "internet_exposed": app in ("payments-api", "customer-portal", "partner-api", "identity-gateway"),
                "certificate": certificates[i % len(certificates)] if algorithm in ("RSA-2048", "ECDSA-P256", "TLS 1.2", "TLS 1.3") else None,
                "is_demo": True, "metadata": {"demo": True, "evidence": "deterministic seed"},
            })
            created_assets.append(asset)
        for i, asset in enumerate(created_assets[1:36], start=1):
            asset.depends_on.add(created_assets[(i * 3) % len(created_assets)])

        assessment = assess_organization(org)
        for source in sources:
            source.asset_count = source.assets.count()
            source.risk_score = assessment.overall_score
            source.risk_level = assessment.level
            source.save(update_fields=["asset_count", "risk_score", "risk_level"])

        project = MigrationProject.objects.create(organization=org, name="Enterprise PQC transition", current_phase="planning",
                                                  target_date=(timezone.now() + timedelta(days=540)).date(),
                                                  description="Prioritized hybrid-first migration of exposed cryptographic assets.")
        targets = {"key_exchange": "ML-KEM-768", "digital_signature": "ML-DSA-65", "symmetric_encryption": "AES-256-GCM", "hashing": "SHA-256"}
        # Re-read after scoring: the in-memory objects still hold pre-assessment risk values,
        # which made every task "safe" and the "top 24" an arbitrary selection.
        scored = list(CryptoAsset.objects.filter(id__in=[a.id for a in created_assets]).order_by("-risk_score", "asset_ref"))
        for i, asset in enumerate(scored[:24]):
            MigrationTask.objects.create(organization=org, project=project, asset=asset,
                                         title=f"Migrate {asset.application} {asset.name}", current_algorithm=asset.algorithm,
                                         target_algorithm=targets.get(asset.purpose, "Review protocol components"),
                                         migration_path=["Classical", "Hybrid", "PQC"] if asset.purpose in ("key_exchange", "digital_signature") else ["Review", "Modernize"],
                                         purpose=asset.purpose, risk_level=asset.risk_level, owner=user, owner_name=user.full_name,
                                         status=["backlog", "planned", "in_progress", "testing", "verified"][i % 5],
                                         phase=["planning", "hybrid", "pqc", "verification"][i % 4],
                                         due_date=(timezone.now() + timedelta(days=30 + i * 12)).date(), priority=1 + i % 4,
                                         effort_days=3 + i % 10, rollback_strategy="Retain the classical path behind a controlled feature flag.",
                                         validation="Interoperability, negative-path, performance, and rollback tests required.")

        MonitoringConfiguration.objects.create(organization=org, enabled=True, frequency_hours=24,
                                               last_scan_at=timezone.now() - timedelta(hours=5),
                                               next_scan_at=timezone.now() + timedelta(hours=19), simulated=True)
        event_types = ["crypto_change", "certificate_change", "new_dependency", "new_algorithm", "risk_change"]
        for i in range(18):
            record_event(org, event_types[i % len(event_types)],
                         ["Cipher suite policy changed", "Certificate renewed", "New crypto dependency detected", "New algorithm detected", "Risk score increased"][i % 5],
                         f"Demo monitoring evidence for {apps[i % len(apps)]}.", ["info", "low", "medium", "high"][i % 4],
                         sources[i % len(sources)], simulated=True, when=timezone.now() - timedelta(hours=i * 3))

        providers = [("github", "scm"), ("gitlab", "scm"), ("bitbucket", "scm"), ("aws", "cloud"),
                     ("azure", "cloud"), ("gcp", "cloud"), ("servicenow", "ticketing"), ("slack", "notification"), ("webhook", "notification")]
        for provider, category in providers:
            Integration.objects.create(organization=org, provider=provider, category=category,
                                       status="connected" if provider in ("github", "aws") else "disconnected",
                                       connected_at=timezone.now() if provider in ("github", "aws") else None, is_mock=True)

        rebuild_architecture(org)
        generate_for_org(org, name="Acme Enterprise CBOM", is_demo=True)
        for finding in org.risk_riskfinding_set.select_related("asset")[:35]:
            create_alert(org, finding.severity, "vulnerable_algorithm", finding.title, finding.recommended_action, finding.asset, dedupe=False)
        run_benchmark(org, user, ["RSA-2048", "ML-KEM-768", "ECDSA-P256", "ML-DSA-65"], iterations=8,
                      name="Demo platform baseline", force_demo=True)
        self.stdout.write(self.style.SUCCESS("Seeded Acme Financial Technologies."))
        self.stdout.write("Login: demo@qsamp.local / QuantumReady!2026")
