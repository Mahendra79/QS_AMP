"""PQC recommendation + classical-vs-PQC comparison.

Never maps algorithms blindly: the primitive and *purpose* of the detected use
decide which PQC families are applicable. KEMs are never suggested for
signatures and vice versa. Performance figures come only from stored benchmark
results (measured / demo, kept apart); otherwise the comparison is size- and
specification-based and says so.
"""
from apps.inventory import catalog
from apps.organizations.errors import ServiceError

from .models import PQCAlgorithm

KEM_FAMILIES = ("ML-KEM",)
SIG_FAMILIES = ("ML-DSA", "SLH-DSA")


def _pqc_by_name():
    return {p.name: p for p in PQCAlgorithm.objects.filter(is_active=True)}


def _classical_sizes(name):
    for c in catalog.CLASSICAL:
        if c["name"].upper() == (name or "").upper():
            return c
    return None


def resolve_purpose(algorithm, purpose=""):
    return purpose or catalog.default_purpose(algorithm)


def analysis_type(algorithm, purpose):
    fam = catalog.family_of(algorithm)
    purpose = resolve_purpose(algorithm, purpose)
    if fam in ("RSA", "DH", "DSA", "ECDH", "ECDSA", "EdDSA"):
        if purpose == "digital_signature":
            return "signature"
        if purpose in ("key_exchange", "encryption", "key_establishment"):
            return "kem"
        return "signature" if fam in ("ECDSA", "EdDSA", "DSA") else "kem"
    if fam in catalog.PQC_FAMILIES or fam == "Hybrid-KEM":
        return "pqc"
    if fam in ("AES", "3DES", "DES", "RC4", "Blowfish", "ChaCha20"):
        return "symmetric"
    if fam in ("SHA-1", "SHA-2", "SHA-3", "MD5", "HMAC"):
        return "hash"
    if fam == "TLS":
        return "protocol"
    return "none"


def _required_category(asset_or_alg, key_size=None):
    alg = asset_or_alg if isinstance(asset_or_alg, str) else asset_or_alg.algorithm + (asset_or_alg.variant or "")
    return catalog.category_for_bits(catalog.classical_security_bits(alg, key_size))


def _classical_key(algorithm, key_size=None, variant=""):
    """Best-effort catalog key for an asset (e.g. RSA + 2048 -> RSA-2048)."""
    if _classical_sizes(algorithm):
        return _classical_sizes(algorithm)["name"]
    fam = catalog.family_of(algorithm)
    a = algorithm.upper()
    if fam == "RSA":
        return f"RSA-{key_size or 2048}"
    if fam in ("ECDSA", "ECDH"):
        if "X25519" in a or "X25519" in (variant or "").upper():
            return "X25519"
        curve = "P384" if "384" in (a + (variant or "")) else "P256"
        return f"{fam}-{curve}"
    return algorithm


def _size_tradeoffs(cl, p, atype):
    out = []
    if not cl:
        return out
    if atype == "kem":
        cl_wire = (cl.get("public_key_size") or 0) + (cl.get("output_size") or 0)
        pq_wire = (p.public_key_size or 0) + (p.output_size or 0)
        out.append(f"Public key {p.public_key_size} B vs {cl.get('public_key_size')} B; ciphertext {p.output_size} B vs {cl.get('output_size')} B.")
        if cl_wire:
            out.append(f"Handshake key-establishment bytes ~{pq_wire} B vs ~{cl_wire} B (~{pq_wire / cl_wire:.1f}x). May affect TLS packet fragmentation / MTU.")
    elif atype == "signature":
        out.append(f"Public key {p.public_key_size} B vs {cl.get('public_key_size')} B; signature {p.output_size} B vs {cl.get('output_size')} B"
                   f" (~{p.output_size / max(cl.get('output_size') or 1, 1):.0f}x).")
        if p.family == "SLH-DSA":
            out.append("Hash-based (conservative assumptions) but large signatures and slow signing; suited to low-volume signing such as firmware/root keys.")
        else:
            out.append("Lattice-based; certificate chains grow substantially (multiple signatures + keys).")
    return out


def recommend_pqc(asset):
    """Return {analysis_type, notes, candidates:[...]} for a CryptoAsset."""
    purpose = resolve_purpose(asset.algorithm, asset.purpose)
    atype = analysis_type(asset.algorithm, purpose)
    pqc = _pqc_by_name()
    req_cat = _required_category(asset, asset.key_size)
    cl = _classical_sizes(_classical_key(asset.algorithm, asset.key_size, asset.variant))
    result = {"analysis_type": atype, "purpose": purpose, "required_nist_category": req_cat,
              "notes": "", "candidates": []}

    def cand(p, applies_to, extra_reason=""):
        meets = (p.nist_category or 0) >= req_cat
        return {
            "candidate": p.name, "family": p.family, "applies_to": applies_to,
            "reason": (f"{p.family} is a {p.primitive.upper()} standardized in {p.standard}, applicable to "
                       f"{catalog.PURPOSE_LABELS.get(applies_to, applies_to).lower()}. {extra_reason}").strip(),
            "security_level": f"{p.security_category} ({p.standard})",
            "meets_requirement": meets,
            "tradeoffs": _size_tradeoffs(cl, p, "kem" if p.primitive == "kem" else "signature"),
            "benchmark_required": True,
            "migration_notes": p.migration_notes,
            "public_key_size": p.public_key_size, "output_size": p.output_size,
        }

    if atype == "kem":
        why = ("RSA used for key transport/encryption maps to a KEM (+ symmetric DEM/HPKE for bulk data), not a drop-in RSA replacement."
               if catalog.family_of(asset.algorithm) == "RSA" else "Key agreement maps to a KEM; hybrid with classical ECDH is recommended during transition.")
        result["notes"] = why
        result["candidates"] = [cand(p, "key_exchange", why) for p in sorted(
            (p for p in pqc.values() if p.family in KEM_FAMILIES), key=lambda p: p.nist_category)]
    elif atype == "signature":
        result["notes"] = ("Digital signatures map to signature schemes (ML-DSA / SLH-DSA). KEMs such as ML-KEM are not signature replacements.")
        cs = [cand(p, "digital_signature") for p in sorted(
            (p for p in pqc.values() if p.family in SIG_FAMILIES), key=lambda p: (p.family, p.nist_category, p.output_size))]
        result["candidates"] = cs
    elif atype == "symmetric":
        result["notes"] = ("Symmetric ciphers are not replaced by PQC algorithms. Analyse key size (Grover reduces the margin): "
                           "AES-256 is believed adequate under current analysis. 3DES must be replaced for classical reasons.")
    elif atype == "hash":
        result["notes"] = ("Hash functions are analysed separately (collision/preimage strength). SHA-256/SHA-384/SHA3 are generally adequate; SHA-1/MD5 must be replaced for classical reasons.")
    elif atype == "protocol":
        result["notes"] = ("A protocol is migrated via its components: key-exchange group (hybrid X25519MLKEM768 / ML-KEM) and authentication (certificate signatures: ML-DSA/SLH-DSA once PKI support exists).")
        result["candidates"] = ([cand(p, "key_exchange", "For the TLS key-exchange group.") for p in pqc.values() if p.name in ("ML-KEM-768", "ML-KEM-1024")] +
                                [cand(p, "digital_signature", "For certificate/handshake authentication.") for p in pqc.values() if p.name in ("ML-DSA-65", "SLH-DSA-SHA2-128s")])
    elif atype == "pqc":
        result["notes"] = ("Already post-quantum (standardized PQC or a hybrid ML-KEM group). No replacement is needed; "
                           "verify the parameter set meets your required security category.")
    else:
        result["notes"] = "No PQC mapping applies to this asset type."
    # meets requirement first, then ascending category
    result["candidates"].sort(key=lambda c: (not c["meets_requirement"],))
    return result


def candidate_names(asset):
    r = recommend_pqc(asset)
    ok = [c["candidate"] for c in r["candidates"] if c["meets_requirement"]]
    return ok or [c["candidate"] for c in r["candidates"]]


def persist_recommendations(asset, org):
    from .models import PQCRecommendation
    PQCRecommendation.objects.filter(asset=asset).delete()
    r = recommend_pqc(asset)
    rows = [PQCRecommendation(organization=org, asset=asset, candidate=c["candidate"], rank=i + 1,
                              reason=c["reason"], security_level=c["security_level"], tradeoffs=c["tradeoffs"],
                              benchmark_required=c["benchmark_required"], migration_notes=c["migration_notes"])
            for i, c in enumerate(r["candidates"])]
    PQCRecommendation.objects.bulk_create(rows)
    return r


# ---------------------------------------------------------------------------------
BENCH_OPS = {"kem": ["keygen", "encapsulation", "decapsulation"], "signature": ["keygen", "sign", "verify"]}


def _benchmark_block(org, algorithm, ops):
    """Latest stored benchmark result per (operation, data_source). Never fabricated."""
    from apps.benchmarks.models import BenchmarkResult
    out = {"measured": {}, "demo": {}}
    if org is None:
        return out
    for r in BenchmarkResult.objects.filter(organization=org, algorithm=algorithm, operation__in=ops).order_by("timestamp"):
        out[r.data_source][r.operation] = {
            "median_ms": r.median, "mean_ms": r.mean, "min_ms": r.min, "max_ms": r.max,
            "iterations": r.iterations, "memory_kb": r.memory_kb, "throughput_ops": r.throughput_ops,
            "latency_ms": r.latency_ms, "library": r.library, "platform": r.platform, "cpu": r.cpu, "os": r.os,
            "timestamp": r.timestamp.isoformat(), "notes": r.notes}
    return out


def compare_classical_vs_pqc(classical_algorithm, pqc_algorithms, purpose="", environment="", org=None, key_size=None):
    """Compare a classical algorithm against one or more PQC candidates.

    Raises ServiceError when the pairing is not a valid replacement (different primitives/purposes).
    """
    if not pqc_algorithms:
        raise ServiceError("validation_error", "At least one PQC candidate is required.")
    atype = analysis_type(classical_algorithm, purpose)
    extra_notes = []
    pqc = _pqc_by_name()
    if atype == "protocol":
        # A protocol is compared through its quantum-vulnerable key-exchange
        # component; X25519 is the default TLS 1.3 group it would be hybridised with.
        atype, classical_algorithm, purpose, key_size = "kem", "X25519", "key_exchange", None
        dropped = [n for n in pqc_algorithms if n in pqc and pqc[n].family not in KEM_FAMILIES]
        pqc_algorithms = [n for n in pqc_algorithms if n not in dropped]
        extra_notes.append("Protocol compared through its key-exchange group (X25519 -> ML-KEM / hybrid). "
                           "Certificate signatures are migrated separately.")
        if not pqc_algorithms:
            pqc_algorithms = ["ML-KEM-768"]
    if atype in ("symmetric", "hash", "pqc", "none"):
        label = "post-quantum" if atype == "pqc" else atype
        raise ServiceError("not_applicable", f"{classical_algorithm} is a {label} construct; PQC algorithms are not direct replacements. "
                           "Use the recommendation analysis instead.")
    cl_key = _classical_key(classical_algorithm, key_size)
    cl = _classical_sizes(cl_key)
    if cl is None and catalog.family_of(cl_key) in ("RSA", "DH"):
        # Sizes are published only for common key lengths; use the closest one for
        # the byte comparison but keep the real key length for the security level.
        nearest = "RSA-2048" if (key_size or 0) <= 2048 else "RSA-3072" if (key_size or 0) <= 3072 else "RSA-4096"
        cl = _classical_sizes(nearest if catalog.family_of(cl_key) == "RSA" else "DH-2048")
        extra_notes.append(f"Key/output sizes shown for {cl['name']}; security level computed for {cl_key}.")
    if cl is None:
        raise ServiceError("unknown_algorithm", f"No specification data for {classical_algorithm}.")
    cl_bits = catalog.classical_security_bits(cl_key, key_size)
    req_cat = catalog.category_for_bits(cl_bits)
    expected_family = KEM_FAMILIES if atype == "kem" else SIG_FAMILIES
    candidates, ops = [], BENCH_OPS[atype]
    cl_bench = _benchmark_block(org, cl_key, ops)
    for name in pqc_algorithms:
        p = pqc.get(name)
        if not p:
            raise ServiceError("unknown_algorithm", f"Unknown PQC algorithm {name}.")
        if p.family not in expected_family:
            raise ServiceError("incompatible_primitives",
                               f"{name} ({p.primitive.upper()}) cannot replace {classical_algorithm} used for "
                               f"{catalog.PURPOSE_LABELS.get(resolve_purpose(classical_algorithm, purpose), purpose)}; "
                               f"applicable families: {', '.join(expected_family)}.")
        wire_cl = (cl["public_key_size"] or 0) + (cl["output_size"] or 0)
        wire_pq = (p.public_key_size or 0) + (p.output_size or 0)
        env = (environment or "").lower()
        compat = ["Requires library/HSM/PKI support for " + p.standard + "; verify vendor roadmaps."]
        if atype == "kem":
            compat.append("Larger ClientHello/ServerHello may fragment over UDP/QUIC or constrained MTUs.")
            compat.append("Deploy as a hybrid (classical + ML-KEM) first for defence in depth and interoperability.")
        else:
            compat.append("Larger certificates/signatures affect TLS handshake size, JWT size limits and embedded storage.")
            compat.append("Public PKI / browser trust stores do not yet broadly support PQ signatures; internal PKI first.")
        if env in ("embedded", "iot", "constrained"):
            compat.append("Constrained environment: large keys/signatures and stack usage need validation.")
        ratio = wire_pq / wire_cl if wire_cl else None
        effort = "high" if (atype == "signature" and p.family == "SLH-DSA") or (ratio and ratio > 8) else "medium"
        candidates.append({
            "algorithm": p.name, "family": p.family, "primitive": p.primitive, "standard": p.standard,
            "security": {"nist_category": p.nist_category, "category_label": p.security_category,
                         "meets_requirement": (p.nist_category or 0) >= req_cat,
                         "quantum_status": p.quantum_status,
                         "note": "Designed/standardized for post-quantum security; believed secure against quantum adversaries under current assumptions."},
            "sizes": {"public_key": p.public_key_size, "private_key": p.private_key_size, "output": p.output_size,
                      "output_kind": p.output_kind, "shared_secret": p.shared_secret_size,
                      "wire_bytes": wire_pq, "wire_ratio_vs_classical": round(ratio, 2) if ratio else None},
            "implementation_maturity": p.implementation_maturity,
            "compatibility": compat,
            "migration_impact": {"effort": effort, "notes": p.migration_notes},
            "benchmarks": _benchmark_block(org, p.name, ops),
        })
    result = {
        "analysis_type": atype,
        "purpose": resolve_purpose(classical_algorithm, purpose),
        "purpose_label": catalog.PURPOSE_LABELS.get(resolve_purpose(classical_algorithm, purpose), ""),
        "environment": environment,
        "required_nist_category": req_cat,
        "classical": {
            "algorithm": cl_key, "family": cl["family"], "primitive": cl["primitive"], "standard": cl["standard"],
            "security": {"classical_bits": cl_bits, "quantum_status": cl["quantum_status"],
                         "note": "Broken by Shor's algorithm on a sufficiently large fault-tolerant quantum computer."},
            "sizes": {"public_key": cl["public_key_size"], "private_key": cl["private_key_size"],
                      "output": cl["output_size"], "output_kind": cl["output_kind"], "wire_bytes": (cl["public_key_size"] or 0) + (cl["output_size"] or 0)},
            "benchmarks": cl_bench,
        },
        "candidates": candidates,
        "operations": ops,
        "data_labels": {"specification": "Specification data (FIPS 203/204/205 and common classical encodings)",
                        "measured": "Measured on this environment (see library/platform in each result)",
                        "demo": "Demo benchmark - synthetic values, not real measurements"},
        "notes": [*extra_notes,
                  "Sizes are specification data. Timing values appear only if benchmark results exist and are always labelled by source.",
                  "Do not choose an algorithm solely because it is faster; consider security level, size, maturity and compatibility."],
    }
    return result
