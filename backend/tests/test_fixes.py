"""Regression tests for the correctness fixes (classification, scanning, scan
lifecycle, triage, validation). Each test names the defect it guards against."""
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.comparison.comparison_service import compare_classical_vs_pqc
from apps.comparison.models import PQCAlgorithm
from apps.discovery.code_scanner import scan_tree
from apps.discovery.tls_probe import parse_group
from apps.inventory import catalog
from apps.inventory.inventory_service import upsert_asset
from apps.inventory.models import CryptoAsset
from apps.migration.models import MigrationProject, MigrationTask
from apps.organizations.services import create_organization
from apps.risk.models import RiskFinding
from apps.risk.risk_service import assess_organization


@pytest.fixture
def tenant(db):
    user = User.objects.create_user("owner@example.com", "StrongPassword!123")
    org = create_organization("Fix Org", user)
    for row in catalog.PQC:
        PQCAlgorithm.objects.create(**row)
    return user, org


@pytest.fixture
def client(tenant):
    user, org = tenant
    c = APIClient()
    c.force_authenticate(user)
    c.credentials(HTTP_X_ORGANIZATION=str(org.id))
    return c


# ---- classification -------------------------------------------------------------------
def test_hybrid_group_is_not_classified_as_vulnerable_x25519():
    assert catalog.family_of("X25519MLKEM768") == "Hybrid-KEM"
    assert catalog.quantum_status("X25519MLKEM768") == "pq_hybrid"
    assert catalog.quantum_status("SecP256r1MLKEM768") == "pq_hybrid"
    assert catalog.quantum_status("X25519") == "vulnerable"


def test_rsa_1024_is_below_the_112_bit_minimum():
    assert catalog.classical_security_bits("RSA-1024", 1024) == 80
    assert catalog.classical_security_bits("RSA-2048", 2048) == 112
    assert catalog.classical_security_bits("RSA-7680", 7680) == 192
    assert catalog.classical_security_bits("RSA-15360", 15360) == 256


@pytest.mark.parametrize("name,status", [
    ("Ed448", "vulnerable"), ("EdDSA", "vulnerable"), ("DSA", "vulnerable"), ("X448", "vulnerable"),
    ("DES", "weak_classical"), ("RC4", "weak_classical"), ("Blowfish", "weak_classical"),
    ("AES-ECB (key size unknown)", "weak_classical"), ("AES-256-GCM", "adequate"),
])
def test_previously_unknown_families_are_classified(name, status):
    assert catalog.quantum_status(name) == status


# ---- static scanner ------------------------------------------------------------------
def test_aes_without_size_is_not_reported_as_aes_256_gcm(tmp_path):
    (tmp_path / "A.java").write_text(
        'Cipher a = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        'Cipher b = Cipher.getInstance("AES");\n', encoding="utf-8")
    (tmp_path / "b.py").write_text("key = AES-128-CBC\n", encoding="utf-8")
    names = {f["algorithm"] for f in scan_tree(tmp_path)["findings"]}
    assert "AES-256-GCM" not in names
    assert "AES-ECB (key size unknown)" in names
    assert "AES-ECB (Java default mode)" in names
    assert "AES-128-CBC" in names


def test_hybrid_group_in_code_is_not_reported_as_ecdh(tmp_path):
    (tmp_path / "tls.conf").write_text("Groups = X25519MLKEM768\n", encoding="utf-8")
    findings = scan_tree(tmp_path)["findings"]
    assert [f["algorithm"] for f in findings] == ["X25519MLKEM768"]


def _pem_cert(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_every_certificate_in_a_bundle_is_read(tmp_path):
    (tmp_path / "chain.pem").write_text(_pem_cert("leaf") + _pem_cert("intermediate"), encoding="utf-8")
    assert len(scan_tree(tmp_path)["certificates"]) == 2


def test_openssl_group_parsing():
    assert parse_group("Negotiated TLS1.3 group: X25519MLKEM768\n") == "X25519MLKEM768"
    assert parse_group("Peer Temp Key: ECDH, prime256v1, 256 bits\n") == "prime256v1"
    assert parse_group("Server Temp Key: X25519, 253 bits\n") == "X25519"
    assert parse_group("Peer Temp Key: DH, 2048 bits\n") == "FFDHE2048"
    assert parse_group("CONNECTION ESTABLISHED\n") is None


# ---- inventory ---------------------------------------------------------------------
@pytest.mark.django_db
def test_asset_refs_are_not_reused_after_deletion(tenant):
    _, org = tenant
    first, _ = upsert_asset(org, None, {"name": "RSA-2048", "algorithm": "RSA-2048", "source_location": "a"})
    second, _ = upsert_asset(org, None, {"name": "RSA-3072", "algorithm": "RSA-3072", "source_location": "b"})
    first.delete()
    third, _ = upsert_asset(org, None, {"name": "RSA-4096", "algorithm": "RSA-4096", "source_location": "c"})
    assert third.asset_ref != second.asset_ref
    assert third.asset_ref == "CA-000003"


@pytest.mark.django_db
def test_finding_triage_survives_reassessment(tenant, client):
    _, org = tenant
    CryptoAsset.objects.create(organization=org, name="RSA-2048", algorithm="RSA-2048", purpose="key_exchange",
                               internet_exposed=True, business_criticality=90, data_sensitivity=90)
    assess_organization(org)
    finding = RiskFinding.objects.get(organization=org)
    response = client.patch(f"/api/risk/findings/{finding.id}/", {"status": "false_positive"}, format="json")
    assert response.status_code == 200
    assess_organization(org)
    assert RiskFinding.objects.get(organization=org).status == "false_positive"
    bad = client.patch(f"/api/risk/findings/{RiskFinding.objects.get(organization=org).id}/",
                       {"status": "deleted"}, format="json")
    assert bad.status_code == 400


# ---- scan lifecycle --------------------------------------------------------------------
def _zip_bytes():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("app.py", "import hashlib\nhashlib.md5(b'x')\n")
    return stream.getvalue()


@pytest.mark.django_db(transaction=True)
@override_settings(SCAN_SYNC=True, SCAN_STAGE_DELAY=0)
def test_same_zip_name_twice_creates_two_sources(tenant, client, tmp_path):
    with override_settings(MEDIA_ROOT=tmp_path):
        responses = [client.post("/api/discovery/sources/", {
            "source_type": "zip", "name": "app", "target": "app.zip",
            "upload": SimpleUploadedFile("app.zip", _zip_bytes(), content_type="application/zip")},
            format="multipart") for _ in range(2)]
    assert [r.status_code for r in responses] == [201, 201]
    assert {r.data["target"] for r in responses} == {"app.zip", "app.zip (2)"}
    assert responses[0].data["scan_job"]["status"] == "completed"


@pytest.mark.django_db(transaction=True)
@override_settings(SCAN_SYNC=True, SCAN_STAGE_DELAY=0)
def test_zip_without_crypto_completes_instead_of_failing(tenant, client, tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("README.txt", "nothing cryptographic here\n")
    with override_settings(MEDIA_ROOT=tmp_path):
        response = client.post("/api/discovery/sources/", {
            "source_type": "zip", "name": "plain", "target": "plain.zip",
            "upload": SimpleUploadedFile("plain.zip", stream.getvalue(), content_type="application/zip")},
            format="multipart")
    assert response.data["scan_job"]["status"] == "completed"


@pytest.mark.django_db
def test_stuck_scan_is_recovered_and_concurrent_scan_rejected(tenant):
    from apps.discovery.discovery_service import create_scan, recover_stale_scans
    from apps.discovery.models import AssetSource, ScanJob
    from apps.organizations.errors import ServiceError
    _, org = tenant
    source = AssetSource.objects.create(organization=org, name="s", source_type="website",
                                        target="https://x.example", status="scanning")
    job = ScanJob.objects.create(organization=org, source=source, status="running")
    with pytest.raises(ServiceError) as exc:
        create_scan(source)
    assert exc.value.code == "scan_in_progress"
    ScanJob.objects.filter(pk=job.pk).update(updated_at=datetime.now(timezone.utc) - timedelta(hours=2))
    assert recover_stale_scans() == 1
    job.refresh_from_db()
    source.refresh_from_db()
    assert job.status == "failed" and source.status == "error"


@pytest.mark.django_db
def test_source_type_and_upload_are_immutable(tenant, client):
    from apps.discovery.models import AssetSource
    _, org = tenant
    source = AssetSource.objects.create(organization=org, name="s", source_type="website", target="https://x.example")
    assert client.patch(f"/api/discovery/sources/{source.id}/", {"source_type": "zip"}, format="json").status_code == 400
    # Partial updates no longer need to resend the target.
    assert client.patch(f"/api/discovery/sources/{source.id}/", {"monitoring_enabled": True},
                        format="json").status_code == 200


# ---- migration -----------------------------------------------------------------------
@pytest.mark.django_db
def test_migration_target_must_match_purpose_and_free_text_does_not_rewrite(tenant, client):
    _, org = tenant
    asset = CryptoAsset.objects.create(organization=org, name="ECDSA-P256", algorithm="ECDSA-P256",
                                       purpose="digital_signature", source_location="a.py:1")
    project = MigrationProject.objects.create(organization=org, name="p")
    task = MigrationTask.objects.create(organization=org, project=project, asset=asset, title="t",
                                        current_algorithm="ECDSA-P256", target_algorithm="ML-KEM-768",
                                        purpose="digital_signature")
    wrong = client.patch(f"/api/migration/tasks/{task.id}/", {"status": "completed"}, format="json")
    assert wrong.status_code == 400
    MigrationTask.objects.filter(pk=task.pk).update(target_algorithm="Review signing service")
    ok = client.patch(f"/api/migration/tasks/{task.id}/", {"status": "completed"}, format="json")
    assert ok.status_code == 200
    asset.refresh_from_db()
    assert asset.algorithm == "ECDSA-P256"  # free text closes the task but never rewrites inventory
    MigrationTask.objects.filter(pk=task.pk).update(target_algorithm="ML-DSA-65", status="testing")
    client.patch(f"/api/migration/tasks/{task.id}/", {"status": "completed"}, format="json")
    asset.refresh_from_db()
    assert asset.algorithm == "ML-DSA-65"
    assert asset.metadata["confidence"] == "declared"


# ---- validation --------------------------------------------------------------------
@pytest.mark.django_db
def test_settings_reject_bad_thresholds_and_unknown_keys(client):
    assert client.patch("/api/settings/", {"settings": {"risk": {"thresholds": {"high": "x"}}}},
                        format="json").status_code == 400
    assert client.patch("/api/settings/", {"settings": {"risk": {"thresholds": {"medium": 90}}}},
                        format="json").status_code == 400
    assert client.patch("/api/settings/", {"settings": {"bogus": {}}}, format="json").status_code == 400
    assert client.patch("/api/settings/", {"settings": {"risk": {"thresholds": {"medium": 25}}}},
                        format="json").status_code == 200


@pytest.mark.django_db
def test_monitoring_frequency_and_benchmark_iterations_are_validated(client):
    assert client.patch("/api/monitoring/", {"frequency_hours": 0}, format="json").status_code == 400
    assert client.patch("/api/monitoring/", {"simulated": True}, format="json").data["simulated"] is False
    response = client.post("/api/benchmarks/run/", {"algorithms": ["RSA-2048"], "iterations": "many"}, format="json")
    assert response.status_code == 400


@pytest.mark.django_db
def test_monitoring_settings_change_does_not_fake_a_scan(client):
    response = client.patch("/api/monitoring/", {"enabled": True}, format="json")
    assert response.status_code == 200
    assert response.data["last_scan_at"] is None
    assert response.data["next_scan_at"] is not None


# ---- comparison ----------------------------------------------------------------------
@pytest.mark.django_db
def test_protocol_asset_is_compared_through_its_key_exchange(tenant):
    _, org = tenant
    result = compare_classical_vs_pqc("TLS 1.3", ["ML-KEM-768", "ML-DSA-65"], "transport_security", org=org)
    assert result["analysis_type"] == "kem"
    assert result["classical"]["algorithm"] == "X25519"
    assert [c["algorithm"] for c in result["candidates"]] == ["ML-KEM-768"]


@pytest.mark.django_db
def test_rsa_1024_comparison_uses_real_security_level(tenant):
    _, org = tenant
    result = compare_classical_vs_pqc("RSA-1024", ["ML-KEM-512"], "key_exchange", org=org, key_size=1024)
    assert result["classical"]["security"]["classical_bits"] == 80


def test_cbom_xml_properties_use_name_attribute():
    from apps.cbom.cbom_service import parse_bytes, to_xml
    xml = to_xml({"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1", "version": 1,
                  "components": [{"type": "cryptographic-asset", "name": "RSA-2048", "bom-ref": "a",
                                  "properties": [{"name": "qsamp:purpose", "value": "key_exchange"}]}]})
    assert '<property name="qsamp:purpose">key_exchange</property>' in xml
    parsed, _ = parse_bytes(xml.encode(), "x.xml")
    assert parsed["components"][0]["properties"][0] == {"name": "qsamp:purpose", "value": "key_exchange"}


@pytest.mark.django_db
def test_generated_cbom_references_resolve(tenant):
    from apps.cbom.cbom_service import build_bom
    from apps.inventory.models import CryptoCertificate
    _, org = tenant
    cert = CryptoCertificate.objects.create(organization=org, subject="CN=x", signature_algorithm="sha256WithRSAEncryption")
    CryptoAsset.objects.create(organization=org, name="RSA-2048", algorithm="RSA-2048", asset_type="certificate",
                               purpose="digital_signature", certificate=cert)
    CryptoAsset.objects.create(organization=org, name="RSA private key", algorithm="RSA", asset_type="key")
    CryptoAsset.objects.create(organization=org, name="ML-KEM-768", algorithm="ML-KEM-768", purpose="key_exchange",
                               primitive="kem", quantum_status="pq_standardized")
    bom = build_bom(org, list(CryptoAsset.objects.filter(organization=org).select_related("certificate")))
    refs = {c["bom-ref"] for c in bom["components"]}
    text = json.dumps(bom)
    for key in ("signatureAlgorithmRef", "subjectPublicKeyRef", "algorithmRef"):
        for comp in bom["components"]:
            props = comp.get("cryptoProperties", {})
            for section in props.values():
                if isinstance(section, dict) and key in section:
                    assert section[key] in refs
    assert '"oid": ""' not in text
    kem = next(c for c in bom["components"] if c["name"] == "ML-KEM-768" and c["bom-ref"].endswith("key_exchange"))
    assert kem["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3


@pytest.mark.django_db(transaction=True)
@override_settings(SCAN_SYNC=True)
def test_demo_seed_runs_and_tasks_carry_real_risk(tmp_path):
    from django.core.management import call_command
    with override_settings(MEDIA_ROOT=tmp_path):
        call_command("seed_demo")
    from apps.organizations.models import Organization
    org = Organization.objects.get(is_demo=True)
    levels = set(MigrationTask.objects.filter(organization=org).values_list("risk_level", flat=True))
    assert levels - {"safe"}, "seeded migration tasks must reflect assessed asset risk"


@pytest.mark.django_db
@pytest.mark.parametrize("report_type", ["executive_security", "cryptographic_inventory", "quantum_risk", "migration_roadmap"])
def test_pdf_reports_have_bookmarks_and_app_links(tenant, tmp_path, report_type):
    import pypdf
    from apps.reports.report_service import generate_report
    user, org = tenant
    org.name = "Acme <b>&</b> Co"  # markup in user-supplied text must be escaped, not rendered/crash
    org.save()
    asset = CryptoAsset.objects.create(organization=org, asset_ref="CA-000001", name="RSA-2048", algorithm="RSA-2048",
                                       purpose="key_exchange", internet_exposed=True, business_criticality=90)
    project = MigrationProject.objects.create(organization=org, name="p")
    MigrationTask.objects.create(organization=org, project=project, asset=asset, title="Move <RSA>",
                                 current_algorithm="RSA-2048", target_algorithm="ML-KEM-768")
    assess_organization(org)
    with override_settings(MEDIA_ROOT=tmp_path, FRONTEND_BASE_URL="https://qsamp.example"):
        report = generate_report(org, user, report_type, "pdf")
        reader = pypdf.PdfReader(report.file.path)
    titles = [o.title for o in reader.outline if not isinstance(o, list)]
    assert "Overview" in titles and len(titles) >= 3
    uris = [a.get_object()["/A"]["/URI"] for p in reader.pages for a in (p.get("/Annots") or [])
            if a.get_object().get("/A", {}).get("/URI")]
    assert uris and all(u.startswith("https://qsamp.example/") for u in uris)
    assert "Acme <b>&</b> Co" in "".join(p.extract_text() for p in reader.pages[:1])
