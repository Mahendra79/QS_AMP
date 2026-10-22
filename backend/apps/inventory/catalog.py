"""Algorithm reference catalog + classification helpers.

Sizes for the PQC parameter sets are the published values from FIPS 203 (ML-KEM),
FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA). Classical sizes are the common
encodings (RSA in DER SPKI / PKCS#1; EC public keys as uncompressed points;
ECDSA signatures as raw r||s). These are *specification* data, not measurements.

Quantum statuses (intentionally hedged - none of these are absolute claims):
  vulnerable          public-key scheme broken by Shor's algorithm on a large fault-tolerant quantum computer
  weak_classical      deprecated/broken even against classical adversaries
  symmetric_review    symmetric primitive whose margin is reduced by Grover; needs separate analysis
  hash_review         hash function; analyse collision / preimage requirements separately
  adequate            believed adequate against quantum adversaries under current analysis
  pq_standardized     standardized / designed for post-quantum security
  protocol_dependent  depends on negotiated key exchange & signature algorithms
"""

C = "classical"

CLASSICAL = [
    dict(name="RSA-2048", family="RSA", primitive="pke", purpose="key_exchange", security_category="~112-bit classical",
         quantum_status="vulnerable", classical_status="deprecated", standard="PKCS#1 / RFC 8017",
         public_key_size=294, private_key_size=1192, output_size=256, output_kind="ciphertext",
         typical_usage="TLS certificates, key transport, signatures (JWT RS256, code signing).",
         migration_notes="RSA is used for both encryption/key transport and signatures; determine the actual use before choosing a PQC candidate. NIST IR 8547 (draft) proposes deprecating 112-bit RSA/ECC after 2030 and disallowing after 2035.",
         parameters={"size_note": "DER SPKI public key; PKCS#1 private key (approximate)"}),
    dict(name="RSA-3072", family="RSA", primitive="pke", purpose="key_exchange", security_category="~128-bit classical",
         quantum_status="vulnerable", classical_status="acceptable", standard="PKCS#1 / RFC 8017",
         public_key_size=422, private_key_size=1766, output_size=384, output_kind="ciphertext",
         typical_usage="Higher-assurance TLS and signing keys.",
         migration_notes="Larger keys do not help against Shor's algorithm; plan for PQC/hybrid."),
    dict(name="RSA-4096", family="RSA", primitive="pke", purpose="key_exchange", security_category="~140-bit classical",
         quantum_status="vulnerable", classical_status="acceptable", standard="PKCS#1 / RFC 8017",
         public_key_size=550, private_key_size=2349, output_size=512, output_kind="ciphertext",
         typical_usage="Long-lived root/intermediate CA keys.", migration_notes="Root CA migration needs trust-store planning."),
    dict(name="ECDSA-P256", family="ECDSA", primitive="signature", purpose="digital_signature", security_category="~128-bit classical",
         quantum_status="vulnerable", classical_status="acceptable", standard="FIPS 186-5 / SEC 2",
         public_key_size=65, private_key_size=32, output_size=64, output_kind="signature",
         typical_usage="TLS server certificates, JWT ES256, code signing.",
         migration_notes="Signature scheme: consider ML-DSA or SLH-DSA (not KEMs).",
         parameters={"size_note": "raw r||s signature; DER-encoded up to 72 bytes"}),
    dict(name="ECDSA-P384", family="ECDSA", primitive="signature", purpose="digital_signature", security_category="~192-bit classical",
         quantum_status="vulnerable", classical_status="acceptable", standard="FIPS 186-5",
         public_key_size=97, private_key_size=48, output_size=96, output_kind="signature",
         typical_usage="Government/CNSA-aligned TLS and PKI.", migration_notes="Consider ML-DSA-65/87 or SLH-DSA."),
    dict(name="ECDH-P256", family="ECDH", primitive="key-agree", purpose="key_exchange", security_category="~128-bit classical",
         quantum_status="vulnerable", classical_status="acceptable", standard="SP 800-56A",
         public_key_size=65, private_key_size=32, output_size=65, output_kind="key_share",
         typical_usage="TLS ECDHE key exchange, JWE ECDH-ES.",
         migration_notes="Key establishment: consider ML-KEM, ideally in a hybrid (e.g. X25519MLKEM768) during transition.",
         parameters={"shared_secret_size": 32}),
    dict(name="ECDH-P384", family="ECDH", primitive="key-agree", purpose="key_exchange", security_category="~192-bit classical",
         quantum_status="vulnerable", classical_status="acceptable", standard="SP 800-56A",
         public_key_size=97, private_key_size=48, output_size=97, output_kind="key_share",
         typical_usage="High-assurance TLS.", migration_notes="Consider ML-KEM-1024 / hybrid.",
         parameters={"shared_secret_size": 48}),
    dict(name="X25519", family="ECDH", primitive="key-agree", purpose="key_exchange", security_category="~128-bit classical",
         quantum_status="vulnerable", classical_status="acceptable", standard="RFC 7748",
         public_key_size=32, private_key_size=32, output_size=32, output_kind="key_share",
         typical_usage="Default TLS 1.3 key share.", migration_notes="Hybrid X25519MLKEM768 is being deployed in TLS 1.3.",
         parameters={"shared_secret_size": 32}),
    dict(name="DH-2048", family="DH", primitive="key-agree", purpose="key_exchange", security_category="~112-bit classical",
         quantum_status="vulnerable", classical_status="deprecated", standard="RFC 7919",
         public_key_size=256, private_key_size=256, output_size=256, output_kind="key_share",
         typical_usage="Legacy finite-field DHE.", migration_notes="Replace with ECDHE/hybrid ML-KEM."),
    dict(name="AES-128-GCM", family="AES", primitive="block-cipher", purpose="symmetric_encryption", security_category="~128-bit classical",
         quantum_status="symmetric_review", classical_status="acceptable", standard="FIPS 197 / SP 800-38D",
         private_key_size=16, typical_usage="Bulk data encryption.",
         migration_notes="Grover's algorithm reduces the effective margin; AES-256 is commonly recommended for long-lived confidentiality.",
         parameters={"nonce": 12, "tag": 16}),
    dict(name="AES-256-GCM", family="AES", primitive="block-cipher", purpose="symmetric_encryption", security_category="~256-bit classical",
         quantum_status="adequate", classical_status="acceptable", standard="FIPS 197 / SP 800-38D",
         private_key_size=32, typical_usage="Bulk data encryption.",
         migration_notes="Believed adequate against quantum adversaries under current analysis; not a PQC replacement target. Ensure the key is established with a quantum-safe method.",
         parameters={"nonce": 12, "tag": 16}),
    dict(name="3DES", family="3DES", primitive="block-cipher", purpose="symmetric_encryption", security_category="~112-bit (Sweet32 limits)",
         quantum_status="weak_classical", classical_status="broken", standard="SP 800-67 (withdrawn)",
         private_key_size=24, typical_usage="Legacy payment/HSM systems.", migration_notes="Replace with AES-256-GCM; not a PQC question."),
    dict(name="SHA-1", family="SHA-1", primitive="hash", purpose="hashing", security_category="<64-bit collision",
         quantum_status="weak_classical", classical_status="broken", standard="FIPS 180-4 (deprecated)",
         output_size=20, output_kind="digest", typical_usage="Legacy signatures, git object ids.",
         migration_notes="Collision attacks are practical; replace with SHA-256+ (classical issue, not PQC)."),
    dict(name="SHA-256", family="SHA-2", primitive="hash", purpose="hashing", security_category="128-bit collision",
         quantum_status="hash_review", classical_status="acceptable", standard="FIPS 180-4",
         output_size=32, output_kind="digest", typical_usage="Integrity, HMAC, signature hashing.",
         migration_notes="Analyse separately; generally considered adequate. Not replaced by PQC algorithms."),
    dict(name="SHA-384", family="SHA-2", primitive="hash", purpose="hashing", security_category="192-bit collision",
         quantum_status="adequate", classical_status="acceptable", standard="FIPS 180-4",
         output_size=48, output_kind="digest", typical_usage="CNSA-aligned hashing.", migration_notes="Believed adequate."),
    dict(name="SHA3-256", family="SHA-3", primitive="hash", purpose="hashing", security_category="128-bit collision",
         quantum_status="hash_review", classical_status="acceptable", standard="FIPS 202",
         output_size=32, output_kind="digest", typical_usage="Integrity; used inside ML-KEM/ML-DSA.", migration_notes="Analyse separately."),
]

PQC = [
    dict(name="ML-KEM-512", family="ML-KEM", primitive="kem", purpose="key_exchange", security_category="NIST category 1",
         quantum_status="pq_standardized", standard="FIPS 203", public_key_size=800, private_key_size=1632,
         output_size=768, output_kind="ciphertext", shared_secret_size=32, nist_category=1, security_level_bits=128,
         implementation_maturity="Standardized (2024); native libraries widely available",
         typical_usage="KEM for key establishment (TLS hybrid, VPN, messaging).",
         migration_notes="Lowest-cost parameter set; category 1 is comparable to AES-128 key search. Prefer hybrid with X25519/ECDH during transition."),
    dict(name="ML-KEM-768", family="ML-KEM", primitive="kem", purpose="key_exchange", security_category="NIST category 3",
         quantum_status="pq_standardized", standard="FIPS 203", public_key_size=1184, private_key_size=2400,
         output_size=1088, output_kind="ciphertext", shared_secret_size=32, nist_category=3, security_level_bits=192,
         implementation_maturity="Standardized (2024); protocol and library support varies",
         typical_usage="General-purpose KEM; commonly deployed as X25519MLKEM768.",
         migration_notes="Common default balance of size and margin."),
    dict(name="ML-KEM-1024", family="ML-KEM", primitive="kem", purpose="key_exchange", security_category="NIST category 5",
         quantum_status="pq_standardized", standard="FIPS 203", public_key_size=1568, private_key_size=3168,
         output_size=1568, output_kind="ciphertext", shared_secret_size=32, nist_category=5, security_level_bits=256,
         implementation_maturity="Standardized (2024)", typical_usage="High-assurance / CNSA 2.0 systems.",
         migration_notes="Largest ML-KEM set; use where category 5 is required."),
    dict(name="ML-DSA-44", family="ML-DSA", primitive="signature", purpose="digital_signature", security_category="NIST category 2",
         quantum_status="pq_standardized", standard="FIPS 204", public_key_size=1312, private_key_size=2560,
         output_size=2420, output_kind="signature", nist_category=2, security_level_bits=128,
         implementation_maturity="Standardized (2024)", typical_usage="General-purpose signatures, code signing, PKI.",
         migration_notes="Signatures are ~38x larger than ECDSA-P256; check certificate chain size limits."),
    dict(name="ML-DSA-65", family="ML-DSA", primitive="signature", purpose="digital_signature", security_category="NIST category 3",
         quantum_status="pq_standardized", standard="FIPS 204", public_key_size=1952, private_key_size=4032,
         output_size=3309, output_kind="signature", nist_category=3, security_level_bits=192,
         implementation_maturity="Standardized (2024)", typical_usage="Higher-assurance signatures.", migration_notes="Common recommended default."),
    dict(name="ML-DSA-87", family="ML-DSA", primitive="signature", purpose="digital_signature", security_category="NIST category 5",
         quantum_status="pq_standardized", standard="FIPS 204", public_key_size=2592, private_key_size=4896,
         output_size=4627, output_kind="signature", nist_category=5, security_level_bits=256,
         implementation_maturity="Standardized (2024)", typical_usage="Highest-assurance signatures.", migration_notes=""),
    dict(name="SLH-DSA-SHA2-128s", family="SLH-DSA", primitive="signature", purpose="digital_signature", security_category="NIST category 1",
         quantum_status="pq_standardized", standard="FIPS 205", public_key_size=32, private_key_size=64,
         output_size=7856, output_kind="signature", nist_category=1, security_level_bits=128,
         implementation_maturity="Standardized (2024); hash-based, conservative assumptions",
         typical_usage="Firmware/root-of-trust signing where conservative hash-based security is preferred.",
         migration_notes="Tiny keys but large, slow-to-produce signatures; unsuitable for high-volume online signing."),
    dict(name="SLH-DSA-SHA2-128f", family="SLH-DSA", primitive="signature", purpose="digital_signature", security_category="NIST category 1",
         quantum_status="pq_standardized", standard="FIPS 205", public_key_size=32, private_key_size=64,
         output_size=17088, output_kind="signature", nist_category=1, security_level_bits=128,
         implementation_maturity="Standardized (2024)", typical_usage="Faster signing variant with larger signatures.",
         migration_notes="'f' (fast) trades signature size for signing speed."),
    dict(name="SLH-DSA-SHA2-192s", family="SLH-DSA", primitive="signature", purpose="digital_signature", security_category="NIST category 3",
         quantum_status="pq_standardized", standard="FIPS 205", public_key_size=48, private_key_size=96,
         output_size=16224, output_kind="signature", nist_category=3, security_level_bits=192,
         implementation_maturity="Standardized (2024)", typical_usage="Higher-assurance hash-based signing.", migration_notes=""),
    dict(name="SLH-DSA-SHA2-256s", family="SLH-DSA", primitive="signature", purpose="digital_signature", security_category="NIST category 5",
         quantum_status="pq_standardized", standard="FIPS 205", public_key_size=64, private_key_size=128,
         output_size=29792, output_kind="signature", nist_category=5, security_level_bits=256,
         implementation_maturity="Standardized (2024)", typical_usage="Highest-assurance hash-based signing.", migration_notes=""),
]

# ---- classification ----------------------------------------------------------------
PURPOSE_LABELS = {
    "key_exchange": "Key establishment",
    "digital_signature": "Digital signature",
    "symmetric_encryption": "Symmetric encryption",
    "hashing": "Hashing",
    "transport_security": "Transport security",
    "certificate": "Certificate / PKI",
    "key_derivation": "Key derivation",
}

VULNERABLE_FAMILIES = {"RSA", "ECDSA", "ECDH", "DH", "DSA", "EdDSA"}
WEAK_CLASSICAL_FAMILIES = {"3DES", "DES", "RC4", "Blowfish", "SHA-1", "MD5"}
PQC_FAMILIES = {"ML-KEM", "ML-DSA", "SLH-DSA"}

# Hybrid TLS key-exchange groups combine a classical and an ML-KEM share
# (e.g. X25519MLKEM768, SecP256r1MLKEM768). Checked before the classical
# prefixes so "X25519MLKEM768" is not classified as plain X25519.
_HYBRID_MARKERS = ("MLKEM", "KYBER")


def is_hybrid_kem(algorithm: str) -> bool:
    a = (algorithm or "").upper().replace("_", "").replace("-", "")
    return any(m in a for m in _HYBRID_MARKERS) and any(c in a for c in ("X25519", "X448", "SECP", "P256", "P384"))


def family_of(algorithm: str) -> str:
    if is_hybrid_kem(algorithm):
        return "Hybrid-KEM"
    a = (algorithm or "").upper().replace("_", "-")
    for prefix, fam in (("ML-KEM", "ML-KEM"), ("ML-DSA", "ML-DSA"), ("SLH-DSA", "SLH-DSA"),
                        ("ECDSA", "ECDSA"), ("ECDH", "ECDH"), ("X25519", "ECDH"), ("X448", "ECDH"),
                        ("ED25519", "EdDSA"), ("ED448", "EdDSA"), ("EDDSA", "EdDSA"),
                        ("RSA", "RSA"), ("DSA", "DSA"), ("DH", "DH"), ("AES", "AES"), ("3DES", "3DES"),
                        ("TDES", "3DES"), ("DESEDE", "3DES"), ("TRIPLEDES", "3DES"), ("DES", "DES"),
                        ("RC4", "RC4"), ("ARCFOUR", "RC4"), ("BLOWFISH", "Blowfish"),
                        ("SHA3", "SHA-3"), ("SHA-1", "SHA-1"), ("SHA1", "SHA-1"), ("SHA", "SHA-2"),
                        ("MD5", "MD5"), ("TLS", "TLS"), ("SSL", "TLS"), ("HMAC", "HMAC"), ("CHACHA", "ChaCha20")):
        if a.startswith(prefix):
            return fam
    return "Other"


def quantum_status(algorithm: str, key_size=None, variant: str = "") -> str:
    fam = family_of(algorithm)
    v = f"{algorithm} {variant}".upper()
    if fam == "Hybrid-KEM":
        return "pq_hybrid"
    if fam in PQC_FAMILIES:
        return "pq_standardized"
    if fam in VULNERABLE_FAMILIES:
        return "vulnerable"
    if fam in WEAK_CLASSICAL_FAMILIES:
        return "weak_classical"
    if fam == "AES" and "ECB" in v:
        return "weak_classical"  # ECB leaks plaintext structure regardless of key size
    if fam == "AES" or fam == "ChaCha20":
        size = key_size or (256 if "256" in v else 192 if "192" in v else 128 if "128" in v else None)
        return "adequate" if (size or 0) >= 256 or fam == "ChaCha20" else "symmetric_review"
    if fam == "SHA-2":
        return "adequate" if any(x in v for x in ("384", "512")) else "hash_review"
    if fam == "SHA-3":
        return "adequate" if any(x in v for x in ("384", "512")) else "hash_review"
    if fam == "HMAC":
        return "hash_review"
    if fam == "TLS":
        if any(x in v for x in ("1.0", "1.1", "SSL")):
            return "weak_classical"
        return "protocol_dependent"
    return "unknown"


def primitive_for(algorithm: str, purpose: str = "") -> str:
    fam = family_of(algorithm)
    if fam == "RSA":
        return "signature" if purpose == "digital_signature" else "pke"
    return {"ECDSA": "signature", "EdDSA": "signature", "DSA": "signature", "ECDH": "key-agree", "DH": "key-agree",
            "Hybrid-KEM": "kem", "AES": "block-cipher", "3DES": "block-cipher", "DES": "block-cipher",
            "Blowfish": "block-cipher", "RC4": "stream-cipher", "ChaCha20": "stream-cipher",
            "SHA-1": "hash", "SHA-2": "hash", "SHA-3": "hash", "MD5": "hash", "HMAC": "mac",
            "TLS": "protocol", "ML-KEM": "kem", "ML-DSA": "signature", "SLH-DSA": "signature"}.get(fam, "other")


def default_purpose(algorithm: str) -> str:
    fam = family_of(algorithm)
    return {"RSA": "key_exchange", "ECDSA": "digital_signature", "EdDSA": "digital_signature",
            "DSA": "digital_signature", "ECDH": "key_exchange", "DH": "key_exchange", "Hybrid-KEM": "key_exchange",
            "ML-KEM": "key_exchange", "ML-DSA": "digital_signature", "SLH-DSA": "digital_signature",
            "AES": "symmetric_encryption", "3DES": "symmetric_encryption", "DES": "symmetric_encryption",
            "RC4": "symmetric_encryption", "Blowfish": "symmetric_encryption",
            "ChaCha20": "symmetric_encryption", "SHA-1": "hashing",
            "SHA-2": "hashing", "SHA-3": "hashing", "MD5": "hashing", "HMAC": "hashing",
            "TLS": "transport_security"}.get(fam, "")


def classical_security_bits(algorithm: str, key_size=None) -> int:
    """Approximate classical security strength (NIST SP 800-57 style) used to pick a PQC category."""
    fam = family_of(algorithm)
    ks = key_size or 0
    a = (algorithm or "").upper()
    if fam in ("RSA", "DH", "DSA"):
        # NIST SP 800-57 Part 1 Table 2. An unknown size (0) is assumed to be 2048.
        if 0 < ks < 2048:
            return 80
        return 112 if ks <= 2048 else 128 if ks <= 3072 else 192 if ks <= 7680 else 256
    if fam in ("ECDSA", "ECDH", "EdDSA"):
        if "448" in a or ks == 448:
            return 224
        if "384" in a or ks == 384:
            return 192
        if "521" in a or ks == 521:
            return 256
        return 128
    return ks or 128


def category_for_bits(bits: int) -> int:
    return 1 if bits <= 128 else 3 if bits <= 192 else 5
