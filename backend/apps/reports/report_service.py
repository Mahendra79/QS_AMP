import csv
import io
import json
from xml.sax.saxutils import escape

from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone
from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (BaseDocTemplate, Frame, PageBreak, PageTemplate, Paragraph, Spacer, Table,
                                TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

from apps.inventory.models import CryptoAsset
from apps.migration.models import MigrationTask
from apps.monitoring.models import MonitoringEvent
from apps.risk.models import RiskAssessment, RiskFinding
from apps.organizations.errors import ServiceError

from .models import Report

REPORT_TYPES = {"executive_security", "cryptographic_inventory", "quantum_risk", "migration_roadmap"}
FILE_FORMATS = {"pdf", "json", "csv"}
PDF_MAX_ROWS = 2000  # tables paginate; the cap only bounds render time


def _asset_rows(org):
    rows = []
    for asset in CryptoAsset.objects.filter(organization=org).select_related("source"):
        metadata = asset.metadata or {}
        rows.append({
            "asset_ref": asset.asset_ref, "name": asset.name, "application": asset.application,
            "algorithm": asset.algorithm, "purpose": asset.purpose, "risk_level": asset.risk_level,
            "quantum_status": asset.quantum_status, "source": asset.source.name if asset.source else "",
            "evidence_type": metadata.get("evidence_type", "unknown"),
            "confidence": metadata.get("confidence", "unknown"), "is_demo": asset.is_demo,
        })
    return rows


def _payload(org, report_type):
    assets = _asset_rows(org)
    assessment = RiskAssessment.objects.filter(organization=org).first()
    base = {
        "organization": org.name, "report_type": report_type, "is_demo": org.is_demo,
        "generated_from": "synthetic demo data" if org.is_demo else "organization evidence",
        "summary": {"assets": len(assets), "risk_score": assessment.overall_score if assessment else 0,
                    "risk_level": assessment.level if assessment else "safe"},
    }
    if report_type == "cryptographic_inventory":
        return {**base, "assets": assets}
    if report_type == "quantum_risk":
        findings = list(RiskFinding.objects.filter(organization=org).values(
            "title", "severity", "score", "reason", "recommended_action", "asset__asset_ref"))
        return {**base, "risk_counts": assessment.counts if assessment else {}, "findings": findings,
                "evidence_notice": "Heuristic source-code findings require confirmation before remediation."}
    if report_type == "migration_roadmap":
        tasks = list(MigrationTask.objects.filter(organization=org).values(
            "title", "current_algorithm", "target_algorithm", "status", "phase", "risk_level",
            "due_date", "effort_days", "asset__asset_ref"))
        return {**base, "tasks": tasks, "task_count": len(tasks)}
    events = list(MonitoringEvent.objects.filter(organization=org).values(
        "title", "severity", "event_type", "occurred_at", "is_simulated")[:20])
    return {**base, "risk_counts": assessment.counts if assessment else {},
            "migration_tasks": MigrationTask.objects.filter(organization=org).count(),
            "recent_monitoring_events": events,
            "top_findings": list(RiskFinding.objects.filter(organization=org).values(
                "title", "severity", "score")[:10])}


def _table_for(payload):
    report_type = payload["report_type"]
    if report_type == "cryptographic_inventory":
        headers = ["Asset", "Application", "Algorithm", "Risk", "Evidence"]
        rows = [[x["asset_ref"], x["application"], x["algorithm"], x["risk_level"], x["confidence"]]
                for x in payload["assets"]]
    elif report_type == "quantum_risk":
        headers = ["Finding", "Severity", "Score", "Asset"]
        rows = [[x["title"], x["severity"], x["score"], x["asset__asset_ref"] or ""] for x in payload["findings"]]
    elif report_type == "migration_roadmap":
        headers = ["Task", "Current", "Target", "Phase", "Status"]
        rows = [[x["title"], x["current_algorithm"], x["target_algorithm"], x["phase"], x["status"]]
                for x in payload["tasks"]]
    else:
        headers = ["Finding", "Severity", "Score"]
        rows = [[x["title"], x["severity"], x["score"]] for x in payload["top_findings"]]
    return headers, rows


# ---- PDF ---------------------------------------------------------------------------------
# The PDF is built from its own queries (it needs record ids for deep links); _payload,
# and therefore the JSON and CSV formats, are unchanged.
NAVY = colors.HexColor("#0b1f33")
TEAL = colors.HexColor("#087f8c")
LINK = "#0b5cad"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "safe"]
SEVERITY_COLORS = {"critical": "#c4364f", "high": "#d9661f", "medium": "#c9a227", "low": "#2563a9", "safe": "#177a55"}
STATUS_ORDER = ["backlog", "planned", "in_progress", "testing", "verified", "completed"]
PHASE_ORDER = ["inventory", "assessment", "planning", "hybrid", "pqc", "verification", "decommission"]
PAGE_W, PAGE_H = A4
MARGIN = 40
CONTENT_W = PAGE_W - 2 * MARGIN


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("RptTitle", parent=base["Title"], fontSize=26, leading=31, alignment=0, textColor=NAVY),
        "subtitle": ParagraphStyle("RptSubtitle", parent=base["Normal"], fontSize=12, leading=16, textColor=colors.HexColor("#40525f")),
        "meta": ParagraphStyle("RptMeta", parent=base["Normal"], fontSize=9, leading=12, textColor=colors.HexColor("#5d6c79")),
        "h1": ParagraphStyle("RptH1", parent=base["Heading1"], fontSize=17, leading=21, textColor=NAVY, spaceBefore=6, spaceAfter=8, keepWithNext=1),
        "h2": ParagraphStyle("RptH2", parent=base["Heading2"], fontSize=12.5, leading=16, textColor=TEAL, spaceBefore=10, spaceAfter=5, keepWithNext=1),
        "body": ParagraphStyle("RptBody", parent=base["Normal"], fontSize=9.5, leading=13.5, spaceAfter=6),
        "note": ParagraphStyle("RptNote", parent=base["Italic"], fontSize=8.5, leading=11, textColor=colors.HexColor("#5d6c79")),
        "cell": ParagraphStyle("RptCell", parent=base["Normal"], fontSize=7.5, leading=9.5),
        "head": ParagraphStyle("RptHead", parent=base["Normal"], fontSize=7.5, leading=9.5, textColor=colors.white, fontName="Helvetica-Bold"),
        "toc_title": ParagraphStyle("RptTocTitle", parent=base["Heading1"], fontSize=17, textColor=NAVY),
        "toc1": ParagraphStyle("RptToc1", fontName="Helvetica-Bold", fontSize=10.5, leading=16, leftIndent=0),
        "toc2": ParagraphStyle("RptToc2", fontName="Helvetica", fontSize=9.5, leading=14, leftIndent=16),
    }


class ReportDoc(BaseDocTemplate):
    """Every RptH1/RptH2 heading becomes a clickable TOC entry and a PDF outline
    (sidebar bookmark). Built with multiBuild so the TOC gets final page numbers."""

    def __init__(self, stream, footer_text, **kwargs):
        super().__init__(stream, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN,
                         bottomMargin=MARGIN + 6, **kwargs)
        self.footer_text = footer_text
        frame = Frame(MARGIN, MARGIN + 6, CONTENT_W, PAGE_H - 2 * MARGIN - 6, id="body")
        self.addPageTemplates([PageTemplate(id="page", frames=[frame], onPage=self._footer)])
        self._heading_seq = 0

    def _footer(self, canv, doc):
        canv.saveState()
        canv.setFont("Helvetica", 7.5)
        canv.setFillColor(colors.HexColor("#6c7d89"))
        canv.drawString(MARGIN, MARGIN - 12, self.footer_text)
        canv.drawRightString(PAGE_W - MARGIN, MARGIN - 12, f"Page {doc.page}")
        canv.restoreState()

    def beforeDocument(self):
        self._heading_seq = 0  # keys must be identical on every multiBuild pass

    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph) or flowable.style.name not in ("RptH1", "RptH2"):
            return
        level = 0 if flowable.style.name == "RptH1" else 1
        text = flowable.getPlainText()
        self._heading_seq += 1
        key = f"section-{self._heading_seq}"
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level, closed=False)
        self.notify("TOCEntry", (level, text, self.page, key))


def _app_url(path):
    return f"{settings.FRONTEND_BASE_URL.rstrip('/')}{path}"


def _link(text, path):
    """Paragraph markup for a deep link into the live app. `text` is escaped here;
    ids are UUIDs, and the whole URL is escaped for the attribute."""
    return f'<link href="{escape(_app_url(path), {chr(34): "&quot;"})}" color="{LINK}"><u>{escape(str(text))}</u></link>'


def _data_table(st, headers, rows, widths, total=None):
    """rows are lists of markup strings (already escaped / linked). Applies PDF_MAX_ROWS."""
    out = []
    total = len(rows) if total is None else total
    if total > PDF_MAX_ROWS:
        out += [Paragraph(f"Showing the first {PDF_MAX_ROWS} of {total} rows. Generate the CSV or JSON "
                          "report for the complete data set.", st["note"]), Spacer(1, 4)]
    body = [[Paragraph(v, st["cell"]) for v in row] for row in rows[:PDF_MAX_ROWS]]
    table = Table([[Paragraph(h, st["head"]) for h in headers], *body], repeatRows=1,
                  colWidths=[CONTENT_W * w for w in widths])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fa")]),
                               ("LINEBELOW", (0, 0), (-1, -1), .25, colors.HexColor("#d8e0e8")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return out + [table]


def _kv_table(st, pairs):
    table = Table([[Paragraph(f"<b>{escape(k)}</b>", st["cell"]), Paragraph(escape(str(v)), st["cell"])] for k, v in pairs],
                  colWidths=[CONTENT_W * .35, CONTENT_W * .65])
    table.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), .25, colors.HexColor("#d8e0e8")),
                               ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return table


def _bar_chart(st, items, title, horizontal=False, color_map=None, default_color="#087f8c"):
    """items: [(label, value)]. Vector chart (reportlab.graphics) embedded as a flowable."""
    if not items or not any(v for _, v in items):
        return Paragraph(f"No data available for: {escape(title)}.", st["note"])
    height = max(150, 22 * len(items) + 50) if horizontal else 210
    drawing = Drawing(CONTENT_W, height)
    chart = HorizontalBarChart() if horizontal else VerticalBarChart()
    left = 150 if horizontal else 40
    chart.x, chart.y = left, 30
    chart.width, chart.height = CONTENT_W - left - 20, height - 55
    values = [v for _, v in items]
    if horizontal:  # top row first
        items, values = items[::-1], values[::-1]
    chart.data = [values]
    chart.categoryAxis.categoryNames = [str(label)[:28] for label, _ in items]
    for text in (chart.categoryAxis.labels, chart.valueAxis.labels, chart.barLabels):
        text.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 7.5
    if not horizontal:
        chart.categoryAxis.labels.angle = 20 if len(items) > 5 else 0
        chart.categoryAxis.labels.boxAnchor = "ne" if len(items) > 5 else "n"
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(values) * 1.15 or 1
    chart.valueAxis.labels.fontSize = 7.5
    chart.valueAxis.forceZero = True
    chart.barLabelFormat = "%d"
    chart.barLabels.fontSize = 7
    chart.barLabels.nudge = 7
    chart.bars.strokeColor = None
    for i, (label, _) in enumerate(items):
        chart.bars[(0, i)].fillColor = colors.HexColor((color_map or {}).get(str(label).lower(), default_color))
    drawing.add(chart)
    drawing.add(String(0, height - 12, title, fontName="Helvetica-Bold", fontSize=9, fillColor=NAVY))
    return drawing


def _badge(label, is_demo):
    table = Table([[label]], colWidths=[None])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ad5818" if is_demo else "#177a55")),
                               ("TEXTCOLOR", (0, 0), (-1, -1), colors.white), ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                               ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 4),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    table.hAlign = "LEFT"
    return table


def _severity_items(counts):
    return [(level.title(), counts.get(level, 0)) for level in SEVERITY_ORDER]


def _pretty(value):
    return str(value or "").replace("_", " ")


def _section_quantum_risk(org, st, ctx):
    findings = list(RiskFinding.objects.filter(organization=org).select_related("asset").order_by("-score", "title"))
    story = [Paragraph("Risk Distribution", st["h1"]),
             Paragraph("Assets per overall risk level in the latest assessment.", st["body"]),
             _bar_chart(st, _severity_items(ctx["counts"]), "Assets by risk level", color_map=SEVERITY_COLORS), Spacer(1, 10),
             Paragraph("Findings", st["h1"]),
             Paragraph(escape(ctx["payload"].get("evidence_notice", "")), st["note"])]
    for level in ("critical", "high", "medium"):
        rows = [[_link(f.title, f"/risk?finding={f.id}"), str(f.score), escape(_pretty(f.status)),
                 _link(f.asset.asset_ref or f.asset.name, f"/inventory?asset={f.asset_id}")]
                for f in findings if f.severity == level]
        if rows:
            story += [Paragraph(f"{level.title()} findings ({len(rows)})", st["h2"]),
                      *_data_table(st, ["Finding", "Score", "Triage", "Asset"], rows, [.58, .09, .15, .18])]
    if not findings:
        story.append(Paragraph("No findings at medium severity or above.", st["body"]))
    story.append(Paragraph("Recommended Actions", st["h1"]))
    grouped = {}
    for f in findings:
        grouped.setdefault(f.recommended_action or "Review and monitor.", []).append(f)
    actions = sorted(grouped.items(), key=lambda kv: (-max(x.score for x in kv[1]), kv[0]))
    rows = [[escape(action), str(len(items)), escape(max(items, key=lambda x: x.score).severity.title())]
            for action, items in actions]
    story += _data_table(st, ["Action", "Findings", "Highest severity"], rows, [.72, .12, .16]) if rows else \
        [Paragraph("No actions required.", st["body"])]
    return story


def _section_inventory(org, st, ctx):
    assets = list(CryptoAsset.objects.filter(organization=org).select_related("source").order_by("asset_ref"))
    by_algorithm, by_status = {}, {}
    for a in assets:
        by_algorithm[a.algorithm] = by_algorithm.get(a.algorithm, 0) + 1
        by_status[a.quantum_status or "unknown"] = by_status.get(a.quantum_status or "unknown", 0) + 1
    top = sorted(by_algorithm.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
    story = [Paragraph("Algorithm Distribution", st["h1"]),
             Paragraph(f"The {len(top)} most frequently observed algorithms of {len(by_algorithm)} distinct.", st["body"]),
             _bar_chart(st, top, "Assets per algorithm", horizontal=True), Spacer(1, 8),
             Paragraph("Quantum Posture", st["h2"]),
             *_data_table(st, ["Quantum status", "Assets"],
                          [[escape(_pretty(k)), str(v)] for k, v in sorted(by_status.items(), key=lambda kv: -kv[1])], [.7, .3]),
             Paragraph("Asset Register", st["h1"])]
    rows = [[_link(a.asset_ref or a.name, f"/inventory?asset={a.id}"), escape(a.application or "-"),
             escape(a.algorithm), escape(_pretty(a.purpose) or "-"), escape(a.risk_level),
             escape((a.metadata or {}).get("confidence", "unknown"))] for a in assets]
    story += _data_table(st, ["Asset", "Application", "Algorithm", "Purpose", "Risk", "Evidence"], rows,
                         [.13, .2, .22, .2, .1, .15]) if rows else [Paragraph("No assets inventoried.", st["body"])]
    return story


def _section_migration(org, st, ctx):
    tasks = list(MigrationTask.objects.filter(organization=org).select_related("asset").order_by("priority", "due_date", "title"))
    by_status = {s: 0 for s in STATUS_ORDER}
    by_phase = {p: 0 for p in PHASE_ORDER}
    for t in tasks:
        by_status[t.status] = by_status.get(t.status, 0) + 1
        by_phase[t.phase] = by_phase.get(t.phase, 0) + 1
    story = [Paragraph("Status and Phase Breakdown", st["h1"]),
             _bar_chart(st, [(_pretty(k), v) for k, v in by_status.items()], "Tasks by status"), Spacer(1, 6),
             _bar_chart(st, [(_pretty(k).upper() if k == "pqc" else _pretty(k), v) for k, v in by_phase.items()],
                        "Tasks by phase", default_color="#6654b8"),
             Paragraph("Tasks", st["h1"])]
    rows = [[_link(t.title, f"/migration?task={t.id}"), escape(t.current_algorithm), escape(t.target_algorithm or "-"),
             escape(_pretty(t.phase)), escape(_pretty(t.status)), escape(t.due_date.isoformat() if t.due_date else "-")]
            for t in tasks]
    story += _data_table(st, ["Task", "Current", "Target", "Phase", "Status", "Due"], rows,
                         [.34, .14, .17, .11, .12, .12]) if rows else [Paragraph("No migration tasks yet.", st["body"])]
    open_tasks = [t for t in tasks if t.status not in ("verified", "completed") and t.due_date]
    story.append(Paragraph("Upcoming Deadlines", st["h1"]))
    rows = [[_link(t.title, f"/migration?task={t.id}"), escape(t.due_date.isoformat()), escape(_pretty(t.status)),
             escape(t.owner_name or "Unassigned")] for t in sorted(open_tasks, key=lambda t: t.due_date)[:15]]
    story += _data_table(st, ["Task", "Due", "Status", "Owner"], rows, [.5, .15, .15, .2]) if rows else \
        [Paragraph("No open tasks with a due date.", st["body"])]
    return story


def _section_executive(org, st, ctx):
    findings = list(RiskFinding.objects.filter(organization=org).select_related("asset").order_by("-score", "title")[:10])
    tasks = MigrationTask.objects.filter(organization=org)
    total = tasks.count()
    done = tasks.filter(status__in=("verified", "completed")).count()
    story = [Paragraph("Risk Distribution", st["h1"]),
             _bar_chart(st, _severity_items(ctx["counts"]), "Assets by risk level", color_map=SEVERITY_COLORS), Spacer(1, 8),
             Paragraph("Top Findings", st["h1"])]
    rows = [[_link(f.title, f"/risk?finding={f.id}"), escape(f.severity.title()), str(f.score),
             _link(f.asset.asset_ref or f.asset.name, f"/inventory?asset={f.asset_id}")] for f in findings]
    story += _data_table(st, ["Finding", "Severity", "Score", "Asset"], rows, [.6, .13, .09, .18]) if rows else \
        [Paragraph("No findings at medium severity or above.", st["body"])]
    story += [Paragraph("Migration Progress", st["h1"]),
              Paragraph(f"{done} of {total} migration task(s) verified or completed "
                        f"({round(100 * done / total) if total else 0}%).", st["body"])]
    events = list(MonitoringEvent.objects.filter(organization=org)[:10])
    story.append(Paragraph("Recent Monitoring Events", st["h2"]))
    rows = [[escape(e.occurred_at.strftime("%Y-%m-%d %H:%M")), escape(e.title), escape(e.severity),
             "simulated" if e.is_simulated else "observed"] for e in events]
    story += _data_table(st, ["When (UTC)", "Event", "Severity", "Source"], rows, [.18, .52, .13, .17]) if rows else \
        [Paragraph("No monitoring events recorded.", st["body"])]
    return story


SECTION_BUILDERS = {"quantum_risk": _section_quantum_risk, "cryptographic_inventory": _section_inventory,
                    "migration_roadmap": _section_migration, "executive_security": _section_executive}


def _pdf_bytes(payload, title, org):
    st = _styles()
    label = "DEMO / SYNTHETIC" if payload["is_demo"] else "EVIDENCE-BASED"
    summary = payload["summary"]
    assessment = RiskAssessment.objects.filter(organization=org).first()
    counts = (assessment.counts if assessment else {}) or {}
    headline = RiskFinding.objects.filter(organization=org).select_related("asset").order_by("-score").first()
    generated = timezone.now().strftime("%Y-%m-%d %H:%M UTC")
    ctx = {"payload": payload, "counts": counts}
    # Paragraph parses a markup subset: user- and scan-supplied text must be escaped.
    org_name = escape(payload["organization"])
    exposed = counts.get("critical", 0) + counts.get("high", 0)
    headline_text = (f" The highest-scoring finding is {_link(headline.title, f'/risk?finding={headline.id}')} "
                     f"({headline.score}/100)." if headline else " No findings reached medium severity.")
    executive = (f"{org_name} has an overall quantum risk score of <b>{summary['risk_score']}/100</b> "
                 f"(<b>{escape(summary['risk_level'])}</b>) across <b>{summary['assets']}</b> inventoried cryptographic "
                 f"asset(s), of which <b>{exposed}</b> are rated high or critical.{headline_text}")
    story = [Spacer(1, 70), Paragraph(escape(title), st["title"]), Spacer(1, 6),
             Paragraph(org_name, st["subtitle"]), Spacer(1, 10), _badge(label, payload["is_demo"]), Spacer(1, 8),
             Paragraph(f"Generated {generated} by QS-AMP", st["meta"]), Spacer(1, 24),
             Paragraph("<b>Executive summary</b>", st["body"]), Paragraph(executive, st["body"]),
             Spacer(1, 10), Paragraph(f"Data basis: {escape(payload['generated_from'])}.", st["note"]), PageBreak()]
    toc = TableOfContents()
    toc.levelStyles = [st["toc1"], st["toc2"]]
    story += [Paragraph("Contents", st["toc_title"]), toc, PageBreak(),
              Paragraph("Overview", st["h1"]), Paragraph(executive, st["body"]),
              _kv_table(st, [("Organization", payload["organization"]), ("Data label", label),
                             ("Overall risk", f"{summary['risk_score']}/100 ({summary['risk_level']})"),
                             ("Assets", summary["assets"]),
                             *[(f"{level.title()} assets", counts.get(level, 0)) for level in SEVERITY_ORDER],
                             ("Generated", generated)]),
              Spacer(1, 8)]
    story += SECTION_BUILDERS[payload["report_type"]](org, st, ctx)
    output = io.BytesIO()
    doc = ReportDoc(output, footer_text=f"QS-AMP | {payload['organization']} | {label}", title=title,
                    author="QS-AMP", subject=payload["report_type"].replace("_", " "))
    doc.multiBuild(story)
    return output.getvalue()


def _csv_bytes(payload):
    headers, rows = _table_for(payload)
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["data_label", "DEMO / SYNTHETIC" if payload["is_demo"] else "EVIDENCE-BASED"])
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue().encode()


def generate_report(org, user, report_type, file_format="pdf", title=""):
    if report_type not in REPORT_TYPES:
        raise ServiceError("invalid_report_type", "Unsupported report type.")
    if file_format not in FILE_FORMATS:
        raise ServiceError("invalid_file_format", f"Report format must be one of: {', '.join(sorted(FILE_FORMATS))}.")
    title = (str(title).strip() or report_type.replace("_", " ").title())[:200]
    payload = _payload(org, report_type)
    report = Report.objects.create(organization=org, report_type=report_type, file_format=file_format,
                                   title=title, generated_by=user, is_demo=org.is_demo)
    if file_format == "json":
        content = json.dumps(payload, indent=2, default=str).encode()
    elif file_format == "csv":
        content = _csv_bytes(payload)
    else:
        file_format = "pdf"
        report.file_format = "pdf"
        content = _pdf_bytes(payload, title, org)
    report.file.save(f"{report.id}.{file_format}", ContentFile(content), save=False)
    report.size_bytes = len(content)
    report.save()
    return report
