"""Inventory helpers: algorithm-name normalisation and asset upsert."""
import re

from django.db import IntegrityError, transaction
from django.utils import timezone

from . import catalog
from .models import CryptoAsset

_EC_CURVE = re.compile(r"(?:P-?|SECP)(256|384|521)", re.I)
REF_RETRIES = 5


def parse_algorithm_name(raw):
    """Normalise free-text names ('rsa2048', 'secp256r1 ECDSA', 'AES/GCM/256') into structured fields."""
    s = (raw or "").strip()
    u = s.upper().replace("_", "-")
    out = {"name": s, "algorithm": s, "variant": "", "key_size": None}
    if catalog.is_hybrid_kem(s):
        # e.g. X25519MLKEM768 / SecP256r1MLKEM768: keep the IANA group name as-is.
        return {"name": s, "algorithm": s, "variant": "hybrid", "key_size": None}
    m = re.search(r"RSA[-\s/]?(\d{3,5})", u)
    if u.startswith("RSA") or m and "RSA" in u:
        size = int(m.group(1)) if m else None
        name = f"RSA-{size}" if size else "RSA"
        return {"name": name, "algorithm": name, "variant": str(size or ""), "key_size": size}
    for fam in ("ECDSA", "ECDH"):
        if fam in u:
            cm = _EC_CURVE.search(u)
            if cm:
                name = f"{fam}-P{cm.group(1)}"
                return {"name": name, "algorithm": name, "variant": f"P-{cm.group(1)}",
                        "key_size": int(cm.group(1))}
            return {"name": fam, "algorithm": fam, "variant": "", "key_size": None}
    if "X25519" in u:
        return {"name": "X25519", "algorithm": "X25519", "variant": "Curve25519", "key_size": 256}
    if "X448" in u:
        return {"name": "X448", "algorithm": "X448", "variant": "Curve448", "key_size": 448}
    for ed, size in (("ED25519", 256), ("ED448", 448)):
        if ed in u:
            name = ed.title()
            return {"name": name, "algorithm": name, "variant": "", "key_size": size}
    if u.startswith("AES") or "AES" in u:
        bits = re.search(r"(128|192|256)", u)
        mode = re.search(r"(GCM|CBC|CTR|CCM|ECB)", u)
        size = int(bits.group(1)) if bits else None
        parts = ["AES"] + ([str(size)] if size else []) + ([mode.group(1)] if mode else [])
        v = "-".join(parts)
        return {"name": v, "algorithm": v, "variant": v, "key_size": size}
    if re.fullmatch(r"SHA-?1", u):
        return {"name": "SHA-1", "algorithm": "SHA-1", "variant": "", "key_size": None}
    m3 = re.match(r"SHA-?3-?(224|256|384|512)", u)
    if m3:
        return {"name": f"SHA3-{m3.group(1)}", "algorithm": f"SHA3-{m3.group(1)}", "variant": "", "key_size": None}
    m2 = re.match(r"SHA-?(224|256|384|512)", u)
    if m2:
        return {"name": f"SHA-{m2.group(1)}", "algorithm": f"SHA-{m2.group(1)}", "variant": "", "key_size": None}
    if u in ("3DES", "TDES", "DESEDE", "TRIPLEDES", "3-DES") or u.startswith("DESEDE"):
        return {"name": "3DES", "algorithm": "3DES", "variant": "", "key_size": 168}
    if u == "MD5":
        return {"name": "MD5", "algorithm": "MD5", "variant": "", "key_size": None}
    if u in ("DES", "DES-CBC", "DES-ECB"):
        return {"name": "DES", "algorithm": "DES", "variant": "", "key_size": 56}
    if u in ("RC4", "ARCFOUR"):
        return {"name": "RC4", "algorithm": "RC4", "variant": "", "key_size": None}
    t = re.match(r"(?:TLS|SSL)[\sv-]*(\d(?:\.\d)?)", u)
    if t:
        name = f"TLS {t.group(1)}"
        return {"name": name, "algorithm": name, "variant": t.group(1), "key_size": None}
    for prefix in ("ML-KEM", "ML-DSA", "SLH-DSA"):
        if u.startswith(prefix):
            return {"name": s, "algorithm": s, "variant": s[len(prefix):].strip("- "), "key_size": None}
    return out


def next_ref(org):
    """Next human-readable id. Based on the highest issued ref (not the row count),
    so deleting assets never causes an existing ref to be handed out again."""
    last = (CryptoAsset.objects.filter(organization=org, asset_ref__regex=r"^CA-\d+$")
            .order_by("-asset_ref").values_list("asset_ref", flat=True).first())
    n = int(last[3:]) + 1 if last else 1
    return f"CA-{n:06d}"


def enrich(d):
    """Fill primitive / purpose / quantum status from the catalog."""
    fam_name = d.get("name") or d.get("algorithm", "")
    d.setdefault("purpose", "")
    if not d["purpose"]:
        d["purpose"] = catalog.default_purpose(fam_name)
    d["primitive"] = d.get("primitive") or catalog.primitive_for(fam_name, d["purpose"])
    d["quantum_status"] = catalog.quantum_status(d.get("algorithm") or fam_name, d.get("key_size"), d.get("variant", ""))
    return d


ASSET_FIELDS = {f.name for f in CryptoAsset._meta.fields}


def upsert_asset(org, source, d):
    """Create or refresh an asset keyed by (source, name, application, location, purpose)."""
    d = enrich(dict(d))
    lookup = dict(organization=org, source=source, name=d["name"], application=d.get("application", ""),
                  source_location=d.get("source_location", ""), purpose=d["purpose"])
    defaults = {k: v for k, v in d.items() if k in ASSET_FIELDS and k not in lookup and k not in ("id",)}
    obj = CryptoAsset.objects.filter(**lookup).first()
    created = obj is None
    if not created:
        for k, v in defaults.items():
            setattr(obj, k, v)
        obj.last_seen = timezone.now()
        obj.save()
        return obj, False
    obj = CryptoAsset(**lookup, **defaults)
    # Concurrent scans in one organization can compute the same next ref; the
    # (organization, asset_ref) unique constraint rejects the loser, which retries.
    for attempt in range(REF_RETRIES):
        obj.asset_ref = next_ref(org)
        try:
            with transaction.atomic():
                obj.save(force_insert=True)
            return obj, True
        except IntegrityError:
            if attempt == REF_RETRIES - 1:
                raise
    return obj, True
