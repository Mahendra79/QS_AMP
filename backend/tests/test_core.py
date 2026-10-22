import json
import io
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.cbom.cbom_service import parse_bytes, validate_bom
from apps.comparison.comparison_service import analysis_type, recommend_pqc
from apps.comparison.models import PQCAlgorithm
from apps.inventory import catalog
from apps.inventory.models import CryptoAsset
from apps.organizations.services import create_organization
from apps.risk.risk_service import assess_organization, score_asset
from apps.organizations.errors import ServiceError


@pytest.fixture
def tenant(db):
    user = User.objects.create_user("owner@example.com", "StrongPassword!123")
    org = create_organization("Test Organization", user)
    for row in catalog.PQC:
        PQCAlgorithm.objects.create(**row)
    return user, org


@pytest.mark.django_db
def test_authentication_and_dashboard_isolation(tenant):
    user, org = tenant
    other = create_organization("Other Tenant", User.objects.create_user("other@example.com", "StrongPassword!123"))
    CryptoAsset.objects.create(organization=org, name="RSA-2048", algorithm="RSA-2048", purpose="key_exchange")
    CryptoAsset.objects.create(organization=other, name="Private asset", algorithm="SHA-256", purpose="hashing")
    client = APIClient()
    response = client.post("/api/auth/login/", {"username": user.username, "password": "StrongPassword!123"}, format="json")
    assert response.status_code == 200
    legacy_response = client.post("/api/auth/login/", {"email": user.email, "password": "StrongPassword!123"}, format="json")
    assert legacy_response.status_code == 200
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access']}", HTTP_X_ORGANIZATION=str(org.id))
    inventory = client.get("/api/inventory/")
    assert inventory.status_code == 200
    assert inventory.data["count"] == 1
    assert inventory.data["results"][0]["name"] == "RSA-2048"
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access']}", HTTP_X_ORGANIZATION=str(other.id))
    fallback = client.get("/api/dashboard/")
    assert fallback.status_code == 200
    assert fallback.data["organization"]["id"] == str(org.id)


@pytest.mark.django_db
def test_risk_scoring_is_explainable(tenant):
    _, org = tenant
    asset = CryptoAsset.objects.create(organization=org, name="RSA-2048", algorithm="RSA-2048",
                                       purpose="key_exchange", internet_exposed=True,
                                       business_criticality=90, data_sensitivity=90)
    assessment = assess_organization(org)
    asset.refresh_from_db()
    assert assessment.asset_count == 1
    assert asset.quantum_status == "vulnerable"
    finding = assessment.findings.get()
    assert len(finding.components) == 9
    assert all("explanation" in component for component in finding.components)


@pytest.mark.django_db
def test_recommendations_respect_primitive(tenant):
    _, org = tenant
    signature = CryptoAsset.objects.create(organization=org, name="ECDSA-P256", algorithm="ECDSA-P256",
                                           purpose="digital_signature", key_size=256)
    recommendation = recommend_pqc(signature)
    assert recommendation["analysis_type"] == "signature"
    assert recommendation["candidates"]
    assert all(not row["candidate"].startswith("ML-KEM") for row in recommendation["candidates"])
    assert analysis_type("RSA-2048", "key_exchange") == "kem"


def test_cbom_parser_and_validation():
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{
        "type": "cryptographic-asset", "name": "ML-KEM-768", "bom-ref": "crypto:1",
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "kem"}},
    }]}
    parsed, fmt = parse_bytes(json.dumps(bom).encode(), "example.cdx.json")
    assert fmt == "json"
    assert validate_bom(parsed)["valid"] is True


@pytest.mark.django_db(transaction=True)
@override_settings(SCAN_SYNC=True, SCAN_STAGE_DELAY=0)
def test_website_discovery_creates_evidence_based_inventory(tenant, monkeypatch):
    user, org = tenant
    now = datetime.now(timezone.utc)
    monkeypatch.setattr("apps.discovery.discovery_service.probe_tls", lambda target: {
        "target": target, "host": "payments.example.com", "port": 443, "resolved_address": "203.0.113.10",
        "verified": True, "verification_error": "", "protocol": "TLSv1.3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256", "cipher_bits": 128, "cipher_algorithm": "AES-128-GCM",
        "certificate": {"subject": "commonName=payments.example.com", "issuer": "commonName=Example CA",
                        "serial_number": "123", "not_before": now, "not_after": now + timedelta(days=90),
                        "key_algorithm": "RSA", "key_size": 3072, "key_asset": "RSA-3072",
                        "signature_algorithm": "sha256WithRSAEncryption", "san": ["payments.example.com"],
                        "is_self_signed": False},
    })
    client = APIClient()
    client.force_authenticate(user)
    client.credentials(HTTP_X_ORGANIZATION=str(org.id))
    response = client.post("/api/discovery/sources/", {
        "source_type": "website", "name": "payments.example.com",
        "target": "https://payments.example.com", "monitoring_enabled": True,
    }, format="json")
    assert response.status_code == 201
    assert response.data["scan_job"]["status"] == "completed"
    assert response.data["scan_job"]["mode"] == "evidence"
    # protocol, key exchange, bulk cipher, certificate key
    assert CryptoAsset.objects.filter(organization=org).count() == 4
    assert CryptoAsset.objects.filter(organization=org, algorithm="RSA-3072").exists()
    assert CryptoAsset.objects.filter(organization=org, purpose="key_exchange").exists()
    assert not CryptoAsset.objects.filter(organization=org, algorithm="ECDH-P256").exists()


def test_static_scanner_keeps_pqc_signature_families_separate(tmp_path):
    from apps.discovery.code_scanner import scan_tree
    source = tmp_path / "crypto.py"
    source.write_text("use ML-DSA-65\nuse SLH-DSA\nuse ML-KEM-768\n", encoding="utf-8")
    findings = scan_tree(tmp_path)["findings"]
    by_algorithm = {row["algorithm"]: row["purpose"] for row in findings}
    assert by_algorithm["ML-DSA-65"] == "digital_signature"
    assert by_algorithm["SLH-DSA"] == "digital_signature"
    assert by_algorithm["ML-KEM-768"] == "key_exchange"


def test_zip_bomb_is_rejected_from_manifest_without_decompression():
    from apps.discovery.safe_zip import validate_zip_upload
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", b"A" * (11 * 1024 * 1024))
    upload = SimpleUploadedFile("large.zip", stream.getvalue(), content_type="application/zip")
    with override_settings(ZIP_MAX_FILES=100, ZIP_MAX_UNCOMPRESSED_BYTES=20 * 1024 * 1024, ZIP_MAX_RATIO=10):
        with pytest.raises(ServiceError) as exc:
            validate_zip_upload(upload)
    assert exc.value.code == "zip_bomb"


@pytest.mark.django_db
def test_report_types_have_distinct_evidence_payloads(tenant, tmp_path):
    from apps.reports.report_service import generate_report
    user, org = tenant
    CryptoAsset.objects.create(organization=org, asset_ref="CA-000001", name="RSA-2048",
                               algorithm="RSA-2048", purpose="digital_signature",
                               metadata={"evidence_type": "static_code_match", "confidence": "heuristic"})
    assess_organization(org)
    with override_settings(MEDIA_ROOT=tmp_path):
        inventory = generate_report(org, user, "cryptographic_inventory", "json")
        risk = generate_report(org, user, "quantum_risk", "json")
        with inventory.file.open("rb") as handle:
            inventory_payload = json.load(handle)
        with risk.file.open("rb") as handle:
            risk_payload = json.load(handle)
    assert inventory_payload["assets"][0]["confidence"] == "heuristic"
    assert "assets" not in risk_payload
    assert risk_payload["findings"]


@pytest.mark.django_db
def test_cbom_upload_imports_cryptographic_asset(tenant, tmp_path):
    user, org = tenant
    client = APIClient()
    client.force_authenticate(user)
    client.credentials(HTTP_X_ORGANIZATION=str(org.id))
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{
        "type": "cryptographic-asset", "name": "ECDSA-P256", "bom-ref": "crypto:ecdsa",
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
            "primitive": "signature", "cryptoFunctions": ["sign", "verify"],
        }},
    }]}
    upload = SimpleUploadedFile("sample.cdx.json", json.dumps(bom).encode(), content_type="application/json")
    with override_settings(MEDIA_ROOT=tmp_path):
        response = client.post("/api/cbom/upload/", {"file": upload, "name": "Test CBOM"}, format="multipart")
    assert response.status_code == 201
    assert response.data["assets_imported"] == 1
    assert CryptoAsset.objects.filter(organization=org, algorithm="ECDSA-P256").exists()
