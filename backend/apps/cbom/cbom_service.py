"""CycloneDX CBOM generation, parsing, validation, import and export.

The structure follows CycloneDX 1.6 `cryptoProperties` (assetType: algorithm |
certificate | protocol | related-crypto-material). Validation here is a
structural check of the CBOM-relevant parts, not a full JSON-schema validation.
"""
import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone as dt_tz
from xml.dom import minidom

from django.core.files.base import ContentFile
from django.db import transaction

from apps.inventory import catalog
from apps.inventory.inventory_service import parse_algorithm_name, upsert_asset
from apps.inventory.models import CryptoAsset, CryptoCertificate
from apps.organizations.errors import ServiceError

from .models import CBOMComponent, CBOMDependency, CBOMDocument

SUPPORTED_VERSIONS = ("1.4", "1.5", "1.6", "1.7")
CRYPTO_ASSET_TYPES = {"algorithm", "certificate", "protocol", "related-crypto-material"}
PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
              "key-agree", "kem", "ae", "combiner", "other", "unknown"}
NS = "http://cyclonedx.org/schema/bom/"
XML_LISTS = {"components": "component", "dependencies": "dependency", "cipherSuites": "cipherSuite",
             "cryptoFunctions": "cryptoFunction", "occurrences": "occurrence", "properties": "property",
             "algorithms": "algorithm", "identifiers": "identifier", "tools": "tool"}
LEVEL_ORDER = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------- parsing ------------------------------------------------------------------
def _strip(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def _xml_to_obj(el):
    children = list(el)
    if not children:
        return (el.text or "").strip()
    tag = _strip(el.tag)
    if tag in XML_LISTS:
        return [_xml_to_obj(c) if len(c) or not c.attrib else {**c.attrib, "value": (c.text or "").strip()} for c in children]
    obj = {k: v for k, v in el.attrib.items()}
    for c in children:
        name = _strip(c.tag)
        obj[name] = _xml_to_obj(c)
    return obj


def parse_bytes(data: bytes, filename: str):
    """Return (bom_dict, file_format). Raises ServiceError on unparseable input."""
    name = (filename or "").lower()
    text = data.decode("utf-8-sig", errors="strict") if data else ""
    if not text.strip():
        raise ServiceError("invalid_cbom", "The file is empty.")
    try:
        if name.endswith(".xml") or text.lstrip().startswith("<"):
            root = ET.fromstring(text)  # stdlib expat does not resolve external entities
            if _strip(root.tag) != "bom":
                raise ServiceError("invalid_cbom", "XML root element must be <bom>.")
            bom = _xml_to_obj(root)
            bom["bomFormat"] = "CycloneDX"
            ns = root.tag.split("}")[0].strip("{") if "}" in root.tag else ""
            bom["specVersion"] = ns.replace(NS, "") if ns.startswith(NS) else bom.get("specVersion", "")
            bom["serialNumber"] = root.attrib.get("serialNumber", "")
            return bom, "xml"
        bom = json.loads(text)
        if not isinstance(bom, dict):
            raise ServiceError("invalid_cbom", "CBOM JSON must be an object.")
        return bom, "json"
    except ServiceError:
        raise
    except (ET.ParseError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ServiceError("invalid_cbom", f"Could not parse CBOM: {e}")


def _walk(components):
    for c in components or []:
        if isinstance(c, dict):
            yield c
            yield from _walk(c.get("components"))


def validate_bom(bom):
    errors, warnings = [], []
    if bom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be 'CycloneDX'.")
    ver = str(bom.get("specVersion", ""))
    if ver not in SUPPORTED_VERSIONS:
        errors.append(f"Unsupported specVersion '{ver}' (supported: {', '.join(SUPPORTED_VERSIONS)}).")
    elif ver in ("1.4", "1.5"):
        warnings.append(f"specVersion {ver} predates cryptoProperties (added in 1.6); crypto assets may be absent.")
    comps = list(_walk(bom.get("components", [])))
    if not isinstance(bom.get("components", []), list):
        errors.append("components must be an array.")
        comps = []
    refs, crypto = set(), 0
    for i, c in enumerate(comps):
        label = f"components[{i}] ({c.get('name', '?')})"
        if not c.get("type"):
            errors.append(f"{label}: missing 'type'.")
        if not c.get("name"):
            errors.append(f"{label}: missing 'name'.")
        ref = c.get("bom-ref") or c.get("bomRef")
        if ref:
            if ref in refs:
                errors.append(f"{label}: duplicate bom-ref '{ref}'.")
            refs.add(ref)
        if c.get("type") == "cryptographic-asset":
            crypto += 1
            cp = c.get("cryptoProperties")
            if not isinstance(cp, dict):
                errors.append(f"{label}: cryptographic-asset requires cryptoProperties.")
                continue
            at = cp.get("assetType")
            if at not in CRYPTO_ASSET_TYPES:
                errors.append(f"{label}: cryptoProperties.assetType must be one of {sorted(CRYPTO_ASSET_TYPES)}.")
            prim = (cp.get("algorithmProperties") or {}).get("primitive")
            if prim and prim not in PRIMITIVES:
                warnings.append(f"{label}: unknown primitive '{prim}'.")
    for d in bom.get("dependencies", []) or []:
        if isinstance(d, dict):
            if d.get("ref") and d["ref"] not in refs:
                warnings.append(f"dependency ref '{d['ref']}' does not match any component.")
    if not crypto:
        warnings.append("No cryptographic-asset components found; this BOM does not inventory cryptography.")
    return {"valid": not errors, "errors": errors[:50], "warnings": warnings[:50], "spec_version": ver,
            "stats": {"components": len(comps), "crypto_assets": crypto}}


# ---------- risk-aware helpers --------------------------------------------------------
def _slug(s):
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", s).strip("-").lower()[:80]


def _iso(dt):
    return dt.astimezone(dt_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _algorithm_component(a: CryptoAsset):
    fam = catalog.family_of(a.algorithm)
    cat = catalog.category_for_bits(catalog.classical_security_bits(a.name, a.key_size)) if a.quantum_status == "vulnerable" else None
    props = {"primitive": a.primitive if a.primitive in PRIMITIVES else "other",
             "parameterSetIdentifier": a.variant or (str(a.key_size) if a.key_size else ""),
             "executionEnvironment": a.execution_environment or "software-plain-ram",
             "implementationPlatform": a.implementation_platform or "generic",
             "cryptoFunctions": a.crypto_functions or _functions(a),
             "classicalSecurityLevel": catalog.classical_security_bits(a.name, a.key_size)
             if fam in ("RSA", "ECDSA", "ECDH", "DH") else None}
    if fam in ("ML-KEM", "ML-DSA", "SLH-DSA"):
        props["nistQuantumSecurityLevel"] = PQC_CATEGORY.get(a.name.upper())
    elif fam == "Hybrid-KEM":
        props["nistQuantumSecurityLevel"] = _hybrid_category(a.name)
    elif a.quantum_status == "vulnerable":
        props["nistQuantumSecurityLevel"] = 0
    if fam in ("ECDSA", "ECDH"):
        props["curve"] = {"P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1"}.get(a.variant, a.variant)
    return {k: v for k, v in props.items() if v not in (None, "")}


PQC_CATEGORY = {p["name"].upper(): p["nist_category"] for p in catalog.PQC}


def _hybrid_category(name):
    """A hybrid group is as strong as its ML-KEM component (e.g. X25519MLKEM768 -> ML-KEM-768 -> 3)."""
    m = re.search(r"(?:MLKEM|KYBER)[-_]?(512|768|1024)", name.upper())
    return PQC_CATEGORY.get(f"ML-KEM-{m.group(1)}") if m else None


def _functions(a):
    return {"signature": ["sign", "verify"], "pke": ["encrypt", "decrypt"], "kem": ["encapsulate", "decapsulate"],
            "key-agree": ["keygen"], "block-cipher": ["encrypt", "decrypt"], "hash": ["digest"], "mac": ["tag"]}.get(a.primitive, ["other"])


def build_bom(org, assets, name="QS-AMP CBOM", is_demo=False):
    """Generate a CycloneDX 1.6 CBOM dict from CryptoAsset rows."""
    comps, deps, refs = [], {}, {}
    now = datetime.now(dt_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def add(ref, comp):
        if ref not in refs:
            refs[ref] = comp
            comp["bom-ref"] = ref
            comps.append(comp)
            deps.setdefault(ref, set())
        return ref

    def algorithm_ref(name):
        """Every *Ref must resolve to a component in the same BOM; add the
        referenced algorithm as its own component when it is not one already."""
        ref = f"alg/{_slug(name)}"
        parsed = parse_algorithm_name(name)
        primitive = catalog.primitive_for(parsed["algorithm"])
        return add(ref, {"type": "cryptographic-asset", "name": name, "cryptoProperties": {
            "assetType": "algorithm", "algorithmProperties": {"primitive": primitive if primitive in PRIMITIVES else "other"}}})

    for a in assets:
        app = a.application or "unassigned"
        app_ref = add(f"app/{_slug(app)}", {"type": "application", "name": app,
                                            "properties": [{"name": "qsamp:environment", "value": a.environment or ""}]})
        if a.library:
            lib_ref = add(f"lib/{_slug(a.library)}", {"type": "library", "name": a.library})
            deps[app_ref].add(lib_ref)
        else:
            lib_ref = None
        if a.asset_type == "certificate" and a.certificate_id:
            c = a.certificate
            sig_ref = algorithm_ref(c.signature_algorithm or c.key_algorithm or "unknown")
            key_ref = algorithm_ref(a.name)
            ref = add(f"cert/{c.id}", {"type": "cryptographic-asset", "name": c.subject, "cryptoProperties": {
                "assetType": "certificate", "certificateProperties": {
                    "subjectName": c.subject, "issuerName": c.issuer, "notValidBefore": _iso(c.not_before),
                    "notValidAfter": _iso(c.not_after), "signatureAlgorithmRef": sig_ref,
                    "subjectPublicKeyRef": key_ref, "certificateFormat": "X.509"}}})
            deps[app_ref].add(ref)
            deps[ref].update({sig_ref, key_ref})
            continue
        if a.asset_type == "protocol" or catalog.family_of(a.algorithm) == "TLS":
            ref = add(f"proto/{_slug(a.name)}", {"type": "cryptographic-asset", "name": a.name, "cryptoProperties": {
                "assetType": "protocol", "protocolProperties": {"type": "tls", "version": a.variant or a.name.split()[-1]}}})
        elif a.asset_type == "key":
            alg_ref = algorithm_ref(a.algorithm or a.name)
            material = {"type": "private-key", "algorithmRef": alg_ref}
            if a.key_size:
                material["size"] = a.key_size
            ref = add(f"key/{_slug(a.name)}-{a.asset_ref or a.pk}", {"type": "cryptographic-asset", "name": a.name, "cryptoProperties": {
                "assetType": "related-crypto-material", "relatedCryptoMaterialProperties": material}})
            deps[ref].add(alg_ref)
        else:
            ref = add(f"alg/{_slug(a.name)}-{a.purpose}", {"type": "cryptographic-asset", "name": a.name, "cryptoProperties": {
                "assetType": "algorithm", "algorithmProperties": _algorithm_component(a)},
                "properties": [{"name": "qsamp:purpose", "value": a.purpose},
                               {"name": "qsamp:quantumStatus", "value": a.quantum_status},
                               {"name": "qsamp:riskLevel", "value": a.risk_level}]})
        deps[app_ref].add(ref)
        if lib_ref:
            deps[lib_ref].add(ref)
        if a.source_location and "/" in a.source_location or (a.source_location or "").endswith((".py", ".java", ".js", ".go", ".conf", ".pem")):
            fref = add(f"file/{_slug(a.source_location)}", {"type": "file", "name": a.source_location})
            deps[fref].add(ref)
        # evidence occurrences for the component
        comp = refs[ref]
        if a.source_location:
            comp.setdefault("evidence", {"occurrences": []})
            if len(comp["evidence"]["occurrences"]) < 25:
                comp["evidence"]["occurrences"].append({"location": a.source_location, "additionalContext": app})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": now,
                     "tools": {"components": [{"type": "application", "name": "QS-AMP", "version": "1.0.0"}]},
                     "component": {"type": "application", "name": org.name},
                     "properties": [{"name": "qsamp:demo", "value": "true"}] if is_demo else []},
        "components": comps,
        "dependencies": [{"ref": r, "dependsOn": sorted(d)} for r, d in deps.items()],
    }


def _relation(src_type, dst_type):
    if src_type == "application" and dst_type == "library":
        return "depends_on"
    if src_type == "application":
        return "uses"
    if src_type == "library":
        return "implements"
    if src_type == "file":
        return "uses"
    if src_type == "certificate":
        return "protects"
    return "depends_on"


@transaction.atomic
def store_document(org, bom, name, source=None, origin="generated", file_format="json", validation=None,
                   upload=None, is_demo=False):
    """Persist a normalised BOM as CBOMDocument + components + dependencies."""
    doc = CBOMDocument.objects.create(
        organization=org, name=name, source=source, origin=origin, spec_version=str(bom.get("specVersion", "1.6")),
        serial_number=str(bom.get("serialNumber", "")), file_format=file_format, raw=bom,
        validation=validation or validate_bom(bom), is_demo=is_demo)
    if upload is not None:
        doc.file.save(upload.name, upload, save=True)
    comps, by_ref, seen = [], {}, set()
    for i, c in enumerate(_walk(bom.get("components", []))):
        ref = c.get("bom-ref") or c.get("bomRef") or f"auto/{i}"
        if ref in seen:
            continue
        seen.add(ref)
        cp = c.get("cryptoProperties") or {}
        asset_type = cp.get("assetType") or c.get("type", "")
        props = {p.get("name"): p.get("value") for p in c.get("properties", []) or [] if isinstance(p, dict)}
        comp = CBOMComponent(organization=org, document=doc, bom_ref=ref[:200], component_type=c.get("type", "")[:40],
                             asset_type=asset_type[:30], name=str(c.get("name", ""))[:300],
                             version=str(c.get("version", ""))[:60], crypto_properties=cp,
                             risk_level=props.get("qsamp:riskLevel") or _infer_risk(c))
        comps.append(comp)
        by_ref[ref] = comp
    CBOMComponent.objects.bulk_create(comps, batch_size=500)
    edges = []
    for d in bom.get("dependencies", []) or []:
        if not isinstance(d, dict) or d.get("ref") not in by_ref:
            continue
        src = by_ref[d["ref"]]
        targets = d.get("dependsOn") or []
        if isinstance(targets, dict):
            targets = [targets]
        for t in targets:
            t = t.get("ref") if isinstance(t, dict) else t
            if t in by_ref:
                edges.append(CBOMDependency(organization=org, document=doc, source_ref=d["ref"][:200], target_ref=t[:200],
                                            relation=_relation(src.asset_type or src.component_type, by_ref[t].asset_type)))
    CBOMDependency.objects.bulk_create(edges, batch_size=500)
    doc.component_count = len(comps)
    doc.save(update_fields=["component_count"])
    return doc


def _infer_risk(c):
    cp = c.get("cryptoProperties") or {}
    if cp.get("assetType") == "algorithm":
        name = c.get("name", "")
        st = catalog.quantum_status(parse_algorithm_name(name)["algorithm"], parse_algorithm_name(name)["key_size"], name)
        return {"vulnerable": "high", "weak_classical": "high", "symmetric_review": "medium", "hash_review": "low",
                "adequate": "safe", "pq_standardized": "safe"}.get(st, "low")
    return "safe"


def refresh_component_risks(doc):
    """Sync component risk from linked inventory assets (worst wins)."""
    by_name = {}
    for a in CryptoAsset.objects.filter(organization=doc.organization):
        cur = by_name.get(a.name)
        if cur is None or LEVEL_ORDER[a.risk_level] > LEVEL_ORDER[cur]:
            by_name[a.name] = a.risk_level
    upd = []
    for c in doc.components.filter(component_type="cryptographic-asset"):
        if c.name in by_name:
            c.risk_level = by_name[c.name]
            upd.append(c)
    CBOMComponent.objects.bulk_update(upd, ["risk_level"])


def generate_for_org(org, source=None, name=None, is_demo=False):
    qs = CryptoAsset.objects.filter(organization=org).select_related("certificate")
    if source is not None:
        qs = qs.filter(source=source)
    assets = list(qs)
    if not assets:
        raise ServiceError("no_assets", "No cryptographic assets available to build a CBOM.")
    if source is not None and not name:
        # A source's generated CBOM describes its latest scan; earlier generated
        # copies are superseded rather than accumulating one per scan.
        CBOMDocument.objects.filter(organization=org, source=source, origin="generated").delete()
    bom = build_bom(org, assets, name or (f"CBOM - {source.name}" if source else f"CBOM - {org.name}"), is_demo)
    doc = store_document(org, bom, name or (f"CBOM - {source.name}" if source else f"CBOM - {org.name}"),
                         source=source, origin="generated", is_demo=is_demo)
    refresh_component_risks(doc)
    return doc


# ---------- import into inventory ----------------------------------------------------
@transaction.atomic
def import_assets_from_document(org, doc, source):
    """Turn cryptographic-asset components of a document into CryptoAsset rows."""
    comps = {c.bom_ref: c for c in doc.components.all()}
    parents = {}
    for d in doc.dependencies.all():
        parents.setdefault(d.target_ref, []).append(d.source_ref)
    created = 0
    for ref, c in comps.items():
        if c.component_type != "cryptographic-asset":
            continue
        cp = c.crypto_properties or {}
        at = cp.get("assetType")
        app = ""
        for p in parents.get(ref, []):
            if comps[p].component_type == "application":
                app = comps[p].name
                break
        lib = next((comps[p].name for p in parents.get(ref, []) if comps[p].component_type == "library"), "")
        if at == "algorithm":
            ap = cp.get("algorithmProperties") or {}
            parsed = parse_algorithm_name(c.name)
            if parsed["key_size"] is None and str(ap.get("parameterSetIdentifier", "")).isdigit():
                parsed["key_size"] = int(ap["parameterSetIdentifier"])
            funcs = ap.get("cryptoFunctions") or []
            purpose = ""
            if ap.get("primitive") in ("signature",):
                purpose = "digital_signature"
            elif ap.get("primitive") in ("kem", "key-agree", "pke"):
                purpose = "key_exchange"
            data = {**parsed, "application": app, "library": lib, "purpose": purpose,
                    "primitive": ap.get("primitive", ""), "crypto_functions": funcs if isinstance(funcs, list) else [],
                    "execution_environment": ap.get("executionEnvironment", ""),
                    "implementation_platform": ap.get("implementationPlatform", ""),
                    "source_location": ((c.crypto_properties or {}).get("_loc") or ""), "asset_type": "algorithm",
                    "environment": "production", "internet_exposed": False, "metadata": {"cbom_ref": ref}}
        elif at == "protocol":
            pp = cp.get("protocolProperties") or {}
            v = str(pp.get("version", "")) or c.name
            parsed = parse_algorithm_name(f"TLS {v}" if pp.get("type", "tls") == "tls" and not c.name.upper().startswith("TLS") else c.name)
            data = {**parsed, "application": app, "asset_type": "protocol", "library": lib, "environment": "production",
                    "protocol": parsed["name"], "metadata": {"cbom_ref": ref}}
        elif at == "certificate":
            cert = cp.get("certificateProperties") or {}
            # Name the asset by the key/signature algorithm it actually relies on (that is
            # what drives quantum risk), falling back to X.509 when the BOM omits it.
            alg_ref = cert.get("subjectPublicKeyRef") or cert.get("signatureAlgorithmRef")
            alg_name = comps[alg_ref].name if alg_ref in comps else "X.509"
            parsed = parse_algorithm_name(alg_name)
            subject = str(cert.get("subjectName", c.name))[:300]
            issuer = str(cert.get("issuerName", ""))[:300]
            # Re-importing the same BOM must not duplicate the certificate record.
            cobj = CryptoCertificate.objects.filter(organization=org, subject=subject, issuer=issuer).first() \
                or CryptoCertificate.objects.create(organization=org, subject=subject, issuer=issuer,
                                                    signature_algorithm=str(alg_name)[:80])
            data = {**parsed, "name": parsed["name"][:200], "asset_type": "certificate", "application": app,
                    "purpose": "digital_signature", "primitive": "signature", "environment": "production",
                    "source_location": subject[:500], "certificate": cobj, "metadata": {"cbom_ref": ref}}
        else:
            rp = cp.get("relatedCryptoMaterialProperties") or {}
            parsed = parse_algorithm_name(c.name)
            data = {**parsed, "application": app, "asset_type": "key", "key_size": rp.get("size") or parsed["key_size"],
                    "purpose": "key_exchange" if catalog.family_of(parsed["algorithm"]) in ("RSA", "ECDH", "DH") else "",
                    "environment": "production", "metadata": {"cbom_ref": ref}}
        _, was_new = upsert_asset(org, source, data)
        created += was_new
    return created


# ---------- export -------------------------------------------------------------------
def _obj_to_xml(parent, key, value):
    if value is None:
        return
    if key == "property" and isinstance(value, dict):
        # CycloneDX XML: <property name="...">value</property>
        el = ET.SubElement(parent, key, {"name": str(value.get("name", ""))})
        el.text = "" if value.get("value") is None else str(value["value"])
        return
    if isinstance(value, list):
        child_tag = XML_LISTS.get(key, key.rstrip("s") or key)
        container = ET.SubElement(parent, key)
        for item in value:
            _obj_to_xml(container, child_tag, item)
    elif isinstance(value, dict):
        el = ET.SubElement(parent, key)
        for k, v in value.items():
            if k in ("bom-ref", "ref", "type") and not isinstance(v, (dict, list)) and key in ("component", "dependency"):
                el.set(k, str(v))
            else:
                _obj_to_xml(el, k, v)
    else:
        el = ET.SubElement(parent, key)
        el.text = "" if value is None else str(value)


def to_xml(bom):
    ver = str(bom.get("specVersion", "1.6"))
    root = ET.Element("bom", {"xmlns": NS + ver, "version": str(bom.get("version", 1)),
                              "serialNumber": str(bom.get("serialNumber", ""))})
    for k, v in bom.items():
        if k in ("bomFormat", "specVersion", "serialNumber", "version"):
            continue
        if k == "dependencies":
            deps = ET.SubElement(root, "dependencies")
            for d in v:
                de = ET.SubElement(deps, "dependency", {"ref": d["ref"]})
                for t in d.get("dependsOn", []):
                    ET.SubElement(de, "dependency", {"ref": t})
        else:
            _obj_to_xml(root, k, v)
    return minidom.parseString(ET.tostring(root, encoding="utf-8")).toprettyxml(indent="  ")


def export_document(doc, fmt="json"):
    if fmt == "xml":
        return to_xml(doc.raw), "application/xml", f"{_slug(doc.name)}.cdx.xml"
    return json.dumps(doc.raw, indent=2), "application/json", f"{_slug(doc.name)}.cdx.json"


def is_stale(doc):
    """True if inventory the document scopes over has changed since it was generated.

    A CBOM is a point-in-time bill of materials (like any BOM), so it is
    intentionally never rewritten in place - this only surfaces that a newer
    snapshot would look different, so the UI can prompt to regenerate.
    """
    qs = CryptoAsset.objects.filter(organization=doc.organization)
    if doc.source_id:
        qs = qs.filter(source=doc.source_id)
    from django.db.models import Max
    latest = qs.aggregate(m=Max("updated_at"))["m"]
    return bool(latest and latest > doc.created_at)


def graph(doc):
    comps = list(doc.components.all())
    return {
        "nodes": [{"id": c.bom_ref, "label": c.name, "type": c.asset_type or c.component_type,
                   "component_type": c.component_type, "risk": c.risk_level, "version": c.version,
                   "properties": c.crypto_properties} for c in comps],
        "edges": [{"id": str(d.id), "source": d.source_ref, "target": d.target_ref, "relation": d.relation}
                  for d in doc.dependencies.all()],
    }


def read_upload(uploaded, max_bytes):
    """Validate and read an uploaded CBOM file (extension + size)."""
    name = (uploaded.name or "").lower()
    if not name.endswith((".json", ".xml")):
        raise ServiceError("invalid_file", "CBOM files must have a .json or .xml extension.")
    if uploaded.size > max_bytes:
        raise ServiceError("file_too_large", f"File exceeds the {max_bytes // (1024 * 1024)} MB limit.", 413)
    data = uploaded.read()
    uploaded.seek(0)
    return data
