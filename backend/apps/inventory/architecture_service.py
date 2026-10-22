"""Builds the architecture graph (nodes/edges) from the crypto inventory."""
from collections import defaultdict

from django.db import transaction

from .models import ArchitectureEdge, ArchitectureNode, CryptoAsset

ORDER = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def worst(levels):
    return max(levels, key=lambda l: ORDER.get(l, 0), default="safe")


@transaction.atomic
def rebuild_architecture(org, max_algorithms_per_app=3, max_certs=12, max_libs=10):
    ArchitectureEdge.objects.filter(organization=org).delete()
    ArchitectureNode.objects.filter(organization=org).delete()
    assets = list(CryptoAsset.objects.filter(organization=org).select_related("certificate"))
    if not assets:
        return 0
    nodes = {}

    def node(key, label, ntype, layer, risk="safe", asset=None, meta=None):
        if key not in nodes:
            nodes[key] = ArchitectureNode(organization=org, key=key, label=label, node_type=ntype, layer=layer,
                                          risk_level=risk, asset=asset, metadata=meta or {})
        return nodes[key]

    edges = set()
    by_app = defaultdict(list)
    for a in assets:
        by_app[a.application or "unassigned"].append(a)
    lib_risk, cert_seen = {}, 0
    for app, items in sorted(by_app.items()):
        app_key = f"app:{app}"
        exposed = any(i.internet_exposed for i in items)
        node(app_key, app, "application", 2, worst(i.risk_level for i in items),
             meta={"assets": len(items), "environment": items[0].environment,
                   "internet_exposed": exposed, "evidence": "inventory"})
        if exposed:
            node("internet", "Internet", "internet", 0, meta={"evidence": "internet_exposed asset"})
            edges.add(("internet", app_key, "reaches"))
        top, seen = [], set()
        for i in sorted(items, key=lambda x: -x.risk_score):
            if i.asset_type in ("algorithm", "protocol") and i.name not in seen and len(top) < max_algorithms_per_app:
                seen.add(i.name)
                top.append(i)
        for i in top:
            k = f"alg:{app}:{i.name}"
            node(k, i.name, "algorithm", 4, i.risk_level, asset=i,
                 meta={"purpose": i.purpose, "quantum_status": i.quantum_status, "risk_score": i.risk_score,
                       "confidence": i.metadata.get("confidence", "unknown")})
            edges.add((app_key, k, "uses"))
            if i.library:
                lk = f"lib:{i.library}"
                lib_risk.setdefault(lk, [i.library, []])[1].append(i.risk_level)
                edges.add((app_key, lk, "depends_on"))
                edges.add((lk, k, "implements"))
        for i in items:
            if i.asset_type == "library" and i.library:
                lk = f"lib:{i.library}"
                lib_risk.setdefault(lk, [i.library, []])[1].append(i.risk_level)
                edges.add((app_key, lk, "depends_on"))
        # certificate protects the application
        for i in items:
            if i.certificate and cert_seen < max_certs and f"cert:{i.certificate_id}" not in nodes:
                c = i.certificate
                node(f"cert:{c.id}", c.subject[:40], "certificate", 3, i.risk_level, asset=i,
                     meta={"issuer": c.issuer, "not_after": c.not_after.isoformat() if c.not_after else None,
                           "key": f"{c.key_algorithm}-{c.key_size}"})
                edges.add((f"cert:{c.id}", app_key, "protects"))
                cert_seen += 1
    for lk, (lname, risks) in list(lib_risk.items())[:max_libs * 3]:
        node(lk, lname, "library", 3, worst(risks), meta={"evidence": "dependency manifest"})
    ArchitectureNode.objects.bulk_create(nodes.values())
    saved = {n.key: n for n in ArchitectureNode.objects.filter(organization=org)}
    ArchitectureEdge.objects.bulk_create([
        ArchitectureEdge(organization=org, source=saved[s], target=saved[t], relation=r)
        for s, t, r in edges if s in saved and t in saved])
    return len(saved)


def graph(org):
    nodes = ArchitectureNode.objects.filter(organization=org)
    edges = ArchitectureEdge.objects.filter(organization=org)
    return {
        "nodes": [{"id": n.key, "label": n.label, "type": n.node_type, "layer": n.layer, "risk": n.risk_level,
                   "migration_status": n.migration_status, "metadata": n.metadata,
                   "asset_id": str(n.asset_id) if n.asset_id else None} for n in nodes],
        "edges": [{"id": str(e.id), "source": e.source.key, "target": e.target.key, "relation": e.relation}
                  for e in edges.select_related("source", "target")],
    }
