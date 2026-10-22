# -*- coding: utf-8 -*-
"""Builds the QS-AMP walkthrough guide PDF."""
import os

from PIL import Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (BaseDocTemplate, Frame, Image as RLImage, NextPageTemplate,
                                PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

HERE = os.path.dirname(os.path.abspath(__file__))
IMG = HERE  # cropped screenshots live alongside this script
OUT = os.path.join(os.path.dirname(HERE), "QS-AMP-Guide.pdf")

PAGE = landscape(letter)
PW, PH = PAGE
MARGIN = 0.6 * inch
CONTENT_W = PW - 2 * MARGIN

NAVY = colors.HexColor("#0B1E33")
TEAL = colors.HexColor("#0F8B8D")
BLUE = colors.HexColor("#1D6FE0")
SLATE = colors.HexColor("#44576B")
LIGHT = colors.HexColor("#EEF2F6")
RED = colors.HexColor("#C0392B")
AMBER = colors.HexColor("#B7791F")

ss = getSampleStyleSheet()
styles = {
    "cover_title": ParagraphStyle("cover_title", fontName="Helvetica-Bold", fontSize=34, leading=40,
                                  textColor=NAVY, alignment=TA_CENTER, spaceAfter=6),
    "cover_sub": ParagraphStyle("cover_sub", fontName="Helvetica", fontSize=15, leading=20,
                                textColor=SLATE, alignment=TA_CENTER, spaceAfter=4),
    "cover_meta": ParagraphStyle("cover_meta", fontName="Helvetica", fontSize=10.5, leading=15,
                                 textColor=SLATE, alignment=TA_CENTER),
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=NAVY,
                         spaceBefore=0, spaceAfter=10),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13.5, leading=17, textColor=TEAL,
                         spaceBefore=12, spaceAfter=6),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=14.5, textColor=colors.HexColor("#1A1A1A"),
                           spaceAfter=7, alignment=TA_LEFT),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8.7, leading=12.5, textColor=SLATE, spaceAfter=4),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=9.7, leading=14, textColor=colors.HexColor("#1A1A1A"),
                             spaceAfter=3, leftIndent=12, bulletIndent=0),
    "powered": ParagraphStyle("powered", fontName="Helvetica-Oblique", fontSize=9, leading=13,
                              textColor=BLUE, spaceBefore=2, spaceAfter=6),
    "caption": ParagraphStyle("caption", fontName="Helvetica-Oblique", fontSize=8.5, leading=11,
                              textColor=SLATE, spaceBefore=4, alignment=TA_CENTER),
    "toc_title": ParagraphStyle("toc_title", fontName="Helvetica-Bold", fontSize=19, leading=23,
                                textColor=NAVY, spaceAfter=14),
    "qa_q": ParagraphStyle("qa_q", fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=NAVY, spaceBefore=8, spaceAfter=2),
    "qa_a": ParagraphStyle("qa_a", fontName="Helvetica", fontSize=10, leading=14, textColor=colors.HexColor("#1A1A1A"), spaceAfter=2),
}

toc_style1 = ParagraphStyle("toc1", fontName="Helvetica-Bold", fontSize=11.5, leading=18, textColor=NAVY, leftIndent=0)
toc_style2 = ParagraphStyle("toc2", fontName="Helvetica", fontSize=10, leading=15, textColor=SLATE, leftIndent=16)


def P(text, style="body"):
    return Paragraph(text, styles[style])


def bullets(items):
    return [Paragraph(f"-&nbsp;&nbsp;{t}", styles["bullet"]) for t in items]


def img_flowable(filename, max_w=CONTENT_W * 0.92, max_h=4.35 * inch):
    path = os.path.join(IMG, filename)
    with Image.open(path) as im:
        w, h = im.size
    ratio = w / h
    disp_w, disp_h = max_w, max_w / ratio
    if disp_h > max_h:
        disp_h = max_h
        disp_w = max_h * ratio
    return RLImage(path, width=disp_w, height=disp_h, hAlign="CENTER")


def screenshot_block(caption_text, filename):
    return [img_flowable(filename), Paragraph(caption_text, styles["caption"]), Spacer(1, 10)]


cell_style = ParagraphStyle("cell", fontName="Helvetica", fontSize=9, leading=12.5, textColor=colors.HexColor("#1A1A1A"))
cell_style_b = ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=9, leading=12.5, textColor=colors.HexColor("#1A1A1A"))
th_style = ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9.3, leading=13, textColor=colors.white)


def kv_table(rows, col_widths=None, header=None, first_col_bold=False):
    def wrap(cell, is_header=False, is_first=False):
        if isinstance(cell, str):
            style = th_style if is_header else (cell_style_b if (is_first and first_col_bold) else cell_style)
            return Paragraph(cell, style)
        return cell
    data = []
    if header:
        data.append([wrap(c, is_header=True) for c in header])
    for row in rows:
        data.append([wrap(c, is_first=(i == 0)) for i, c in enumerate(row)])
    t = Table(data, colWidths=col_widths, hAlign="LEFT")
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#D8E0E8")),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY)]
    t.setStyle(TableStyle(style))
    return t


# ---------------------------------------------------------------------------
class GuideDoc(BaseDocTemplate):
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            style = flowable.style.name
            text = flowable.getPlainText()
            if style == "h1" and text not in ("QS-AMP", "Table of Contents"):
                self.notify("TOCEntry", (0, text, self.page))
                self.canv.bookmarkPage(text)
                self.canv.addOutlineEntry(text, text, level=0)
            elif style == "h2":
                self.notify("TOCEntry", (1, text, self.page))


def header_footer(canv, doc):
    canv.saveState()
    canv.setStrokeColor(colors.HexColor("#D8E0E8"))
    canv.setLineWidth(0.6)
    if doc.page > 1:
        canv.line(MARGIN, PH - 0.42 * inch, PW - MARGIN, PH - 0.42 * inch)
        canv.setFont("Helvetica-Bold", 8.5)
        canv.setFillColor(NAVY)
        canv.drawString(MARGIN, PH - 0.34 * inch, "QS-AMP")
        canv.setFont("Helvetica", 8.5)
        canv.setFillColor(SLATE)
        canv.drawRightString(PW - MARGIN, PH - 0.34 * inch, "Quantum Security Assessment & Migration Platform")
        canv.line(MARGIN, 0.4 * inch, PW - MARGIN, 0.4 * inch)
        canv.setFont("Helvetica", 8)
        canv.drawRightString(PW - MARGIN, 0.26 * inch, f"Page {doc.page - 1}")
        canv.drawString(MARGIN, 0.26 * inch, "Internal engineering guide - not for external distribution")
    canv.restoreState()


def cover(canv, doc):
    canv.saveState()
    canv.setFillColor(NAVY)
    canv.rect(0, 0, PW, PH, fill=1, stroke=0)
    canv.setFillColor(TEAL)
    canv.rect(0, PH - 0.14 * inch, PW, 0.14 * inch, fill=1, stroke=0)
    canv.setFillColor(colors.white)
    canv.setFont("Helvetica-Bold", 15)
    canv.roundRect(MARGIN, PH - 1.35 * inch, 0.55 * inch, 0.55 * inch, 8, fill=0, stroke=1)
    canv.setFont("Helvetica-Bold", 20)
    canv.drawCentredString(MARGIN + 0.275 * inch, PH - 1.19 * inch, "Q")
    canv.restoreState()


doc = GuideDoc(OUT, pagesize=PAGE, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=0.75 * inch, bottomMargin=0.65 * inch,
              title="QS-AMP Guide", author="QS-AMP Engineering")
frame_cover = Frame(0, 0, PW, PH, id="cover", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
frame_body = Frame(MARGIN, 0.65 * inch, CONTENT_W, PH - 1.5 * inch, id="body")
doc.addPageTemplates([
    PageTemplate(id="Cover", frames=[frame_cover], onPage=cover),
    PageTemplate(id="Body", frames=[frame_body], onPage=header_footer),
])

story = []

# ============================================================= COVER
story.append(NextPageTemplate("Body"))
cover_story = [
    Spacer(1, 2.1 * inch),
    Paragraph("QS-AMP", ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=46, leading=50,
                                       textColor=colors.white, alignment=TA_CENTER)),
    Spacer(1, 6),
    Paragraph("Quantum Security Assessment &amp; Migration Platform",
             ParagraphStyle("t2", fontName="Helvetica", fontSize=16, leading=20, textColor=colors.HexColor("#9FD8D9"),
                            alignment=TA_CENTER)),
    Spacer(1, 0.55 * inch),
    Paragraph("Engineering Walkthrough Guide",
             ParagraphStyle("t3", fontName="Helvetica-Bold", fontSize=13, leading=18, textColor=colors.white,
                            alignment=TA_CENTER)),
    Paragraph("What it is, how it is built, and what every screen does - written for hand-off and TL review.",
             ParagraphStyle("t4", fontName="Helvetica", fontSize=10.5, leading=15, textColor=colors.HexColor("#C7D3DE"),
                            alignment=TA_CENTER)),
    Spacer(1, 1.6 * inch),
    Paragraph("React 19 + Vite  |  Django 5 + DRF  |  PostgreSQL  |  JWT Auth  |  CycloneDX CBOM  |  ML-KEM / ML-DSA / SLH-DSA",
             ParagraphStyle("t5", fontName="Helvetica", fontSize=9, leading=13, textColor=colors.HexColor("#7E93A6"),
                            alignment=TA_CENTER)),
]
story += cover_story
story.append(NextPageTemplate("Body"))
story.append(PageBreak())

# ============================================================= TOC
story.append(Paragraph("Table of Contents", styles["toc_title"]))
toc = TableOfContents()
toc.levelStyles = [toc_style1, toc_style2]
story.append(toc)
story.append(PageBreak())

# ============================================================= 1. WHAT IS QS-AMP
story.append(Paragraph("1. What Is QS-AMP", styles["h1"]))
story.append(P(
    "QS-AMP is an internal web application that answers one question for a security team: "
    "<b>\"Where does our software use cryptography, and how exposed is it once large quantum computers exist?\"</b> "
    "It scans real sources (websites, ZIP uploads, public Git repositories), records every algorithm/key/certificate/"
    "protocol it finds as a structured inventory, scores each finding for quantum risk, recommends the correct "
    "post-quantum replacement for that specific use, and tracks the migration work through to completion."))
story.append(P(
    "It is built as a full-stack product, not a slide deck: a Django REST API backed by PostgreSQL, a React "
    "single-page app, real TLS probing, a real (if unoptimised) ML-KEM/ML-DSA benchmark, and a CycloneDX 1.6 "
    "CBOM (Cryptography Bill of Materials) export - the same industry format NIST and OWASP use for crypto inventories."))
story.append(Paragraph("Why this exists (the problem)", styles["h2"]))
story += bullets([
    "<b>\"Harvest now, decrypt later\"</b>: an attacker can record TLS/VPN traffic today and decrypt it once a "
    "cryptographically-relevant quantum computer exists. Anything protecting long-lived confidential data (RSA/ECDH "
    "key exchange today) is exposed retroactively, not just going forward.",
    "NIST finalised the first post-quantum standards in August 2024 (FIPS&nbsp;203 ML-KEM, FIPS&nbsp;204 ML-DSA, "
    "FIPS&nbsp;205 SLH-DSA). Organisations now need to know <i>where</i> RSA/ECDSA/ECDH are actually used before they "
    "can plan a migration - most have no such inventory.",
    "Migrating blindly is dangerous: a KEM (key exchange) is not a signature algorithm. QS-AMP's core design rule is "
    "that it never recommends a replacement without first knowing the <i>purpose</i> the classical algorithm serves."])
story.append(Paragraph("Who uses it, and the two states of the app", styles["h2"]))
story.append(P(
    "The intended user is a security engineer or architect. The app has exactly two states, by design:"))
story += bullets([
    "<b>State 1 - empty workspace.</b> A brand-new organisation sees only a landing page: a headline, an explanation, "
    "and an \"Add your first asset\" button. There is no sidebar and nothing to configure yet.",
    "<b>State 2 - active workspace.</b> The moment one source is added and its first scan completes, the full "
    "13-item sidebar (Overview through Settings) appears and stays available from then on."])
story += screenshot_block("State 1 - the empty workspace a brand-new organisation sees (root route, no sources yet).", "16-onboarding-empty.png")
story.append(PageBreak())

# ============================================================= 2. ARCHITECTURE
story.append(Paragraph("2. Architecture &amp; Tech Stack", styles["h1"]))
story.append(P("QS-AMP is a conventional three-tier web app. Nothing exotic, which is deliberate - every "
              "piece can be explained and defended in a design review."))
story.append(kv_table(header=["Layer", "Technology", "Notes"], col_widths=[1.4 * inch, 2.0 * inch, CONTENT_W - 3.4 * inch], rows=[
    ["Frontend", "React 19 + Vite 7", "Single-page app, plain CSS (no Tailwind/CSS framework), React Router 7 for routing."],
    ["Charts", "Recharts 3", "All dashboard bar/line/donut charts."],
    ["Graphs", "@xyflow/react (React Flow)", "CBOM component graph and the crypto dependency map are real interactive node graphs, not images."],
    ["Motion", "Framer Motion 12", "Page transitions, card entrances, the scan-progress animation."],
    ["Icons", "lucide-react", "Every icon in the app."],
    ["Uploads", "react-dropzone", "Drag-and-drop for ZIP and CBOM file uploads."],
    ["API layer", "Django 5 + Django REST Framework", "One Django \"app\" per domain (see section 5); ViewSets + serializers + django-filter."],
    ["Auth", "djangorestframework-simplejwt + pyotp", "JWT access/refresh tokens; optional TOTP-based MFA; hashed API keys as an alternative to JWT."],
    ["Database", "PostgreSQL", "Every organisation-owned table carries an explicit organization_id foreign key and is filtered through it on every query (see section 6)."],
    ["Background work", "Celery + Redis (optional)", "Scans and monitoring runs work inline via a worker thread in dev; the same code path is Celery-ready for production."],
    ["Reports", "ReportLab", "Generates the actual PDF files served from /api/reports/."],
    ["PQC libraries", "kyber-py, dilithium-py (pure Python reference impls)", "Used for real ML-KEM / ML-DSA benchmark timings; architecture also has an adapter slot for native liboqs."],
]))
story.append(Paragraph("Request flow", styles["h2"]))
story.append(P(
    "Browser (React) -&gt; Axios client (attaches JWT + active-organization header) -&gt; Django URL routing "
    "(<font face='Courier'>/api/&lt;module&gt;/</font>) -&gt; DRF permission check (role + organisation membership) "
    "-&gt; a <i>service</i> module holds the actual business logic (never the view) -&gt; PostgreSQL. Every write "
    "also drops a row in the audit log."))
story.append(Paragraph("Project layout", styles["h2"]))
story.append(P("<font face='Courier' size=8.3>"
              "backend/apps/ &nbsp;&nbsp;accounts - organizations - discovery - inventory - cbom - risk - "
              "comparison - benchmarks - monitoring - migration - reports - alerts - integrations - audit<br/>"
              "frontend/src/ pages (one file per screen) - components (shared UI: DataTable, drawers, badges) - "
              "api (Axios client) - context (auth/session)</font>"))
story.append(PageBreak())

# ============================================================= 3. END TO END FLOW
story.append(Paragraph("3. End-to-End: What Happens When You Add a Source", styles["h1"]))
story.append(P(
    "This is the sequence the whole app is built around. Use it as the one-paragraph answer if your TL asks "
    "\"walk me through how this actually works\"."))
steps = [
    ("1. Add a source", "User picks Website, ZIP or Public Repository and submits a target. This creates an "
     "<font face='Courier'>AssetSource</font> row and immediately queues a <font face='Courier'>ScanJob</font>."),
    ("2. Discovery runs", "Website -&gt; a real TLS handshake against the host (certificate, protocol, cipher). "
     "ZIP -&gt; safely extracted (Zip-Slip / zip-bomb / path-traversal guarded) and statically scanned for crypto "
     "API usage. Public repo -&gt; a real <font face='Courier'>git clone --depth 1</font> of the branch, then the "
     "same static scan. Every finding is written as a <font face='Courier'>CryptoAsset</font> with an evidence "
     "location (file path / TLS handshake)."),
    ("3. CBOM is generated", "The inventory for that source is serialised into a CycloneDX 1.6 document "
     "(algorithms, keys, certificates, protocols, libraries, applications, files, and the dependency edges between them)."),
    ("4. Risk is scored", "Every asset is re-scored against nine weighted, explainable factors (quantum "
     "vulnerability, algorithm strength, business criticality, data sensitivity, internet exposure, HNDL exposure, "
     "certificate expiry, migration complexity, dependency count). Findings above the Medium threshold are recorded."),
    ("5. PQC recommendation", "For each vulnerable asset, the purpose (key exchange vs. signature vs. symmetric vs. "
     "hash) decides which PQC family is even considered - RSA/ECDH used for key exchange only ever sees ML-KEM "
     "candidates; ECDSA/RSA used for signing only ever sees ML-DSA / SLH-DSA."),
    ("6. Migration + monitoring", "High-risk findings can become a Kanban migration task; if continuous monitoring "
     "was enabled on the source, it is re-scanned on schedule and any drift raises a monitoring event / alert."),
]
rows = [[P(f"<b>{a}</b>"), P(b, "small")] for a, b in steps]
story.append(Table(rows, colWidths=[1.9 * inch, CONTENT_W - 1.9 * inch],
                   style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 6),
                                     ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                                     ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#D8E0E8"))])))
story.append(Paragraph("Worked example (the demo data set)", styles["h2"]))
story.append(P(
    "The seeded demo organisation, <i>Acme Financial Technologies</i>, has a <font face='Courier'>payments-api</font> "
    "application using RSA-2048 for key exchange. QS-AMP: (a) flags it quantum-vulnerable, (b) recommends "
    "ML-KEM-512/768/1024 - never a signature algorithm, because the recorded purpose is key exchange, "
    "(c) shows the real FIPS 203 key/ciphertext sizes side-by-side with RSA's, and (d) offers to create a migration "
    "task moving it through Classical -&gt; Hybrid -&gt; PQC."))
story.append(PageBreak())

# ============================================================= 4. ONBOARDING SCREENS
story.append(Paragraph("4. Onboarding &amp; Adding a Source", styles["h1"]))
story.append(P("The \"Add source\" modal is a tabbed picker. Only sources the backend can genuinely scan are offered: "
              "Website, ZIP archive, and Public Repository (a Cloud/mock-connector option existed in an earlier draft "
              "and was removed because nothing implemented it end to end)."))
story += screenshot_block("The Add-source modal: Website tab selected, with scan options and a continuous-monitoring toggle.", "17-add-source-modal.png")
story.append(P("Submitting the form creates the source and immediately starts a scan job. The UI then switches to a "
              "full-screen discovery animation that polls the job's progress (stage, percentage, live counters for "
              "files scanned / algorithms found / assets discovered) until it reports <i>completed</i> or <i>failed</i>."))
story.append(PageBreak())

# ============================================================= 5. MODULE WALKTHROUGH
module_intro = ("5. Module-by-Module Walkthrough", "h1")
story.append(Paragraph(module_intro[0], styles[module_intro[1]]))
story.append(P("This section mirrors the left sidebar, one screen at a time. Each entry says what it's for and what "
              "backend module drives it, so you can trace any number on screen back to real code."))
story.append(PageBreak())


def module_section(title, purpose, powered_by, screenshot, caption, extra=None):
    story.append(Paragraph(title, styles["h1"]))
    story.append(P(purpose))
    story.append(Paragraph(f"<b>Powered by:</b> {powered_by}", styles["powered"]))
    if extra:
        story.extend(bullets(extra))
    story.extend(screenshot_block(caption, screenshot))
    story.append(PageBreak())


module_section(
    "5.1 Overview (Dashboard)",
    "The executive summary. Six KPI tiles (total assets, critical assets, high risk, PQC readiness, quantum "
    "exposure score, migration progress), a radial quantum-risk gauge, an algorithm-distribution bar chart, a risk "
    "donut, a readiness trend line, and a table of the most recent findings.",
    "<font face='Courier'>/api/dashboard/</font> aggregates live counts from the Inventory, Risk and Migration "
    "modules - nothing on this page is hand-typed demo copy; every number recalculates from the database.",
    "02-dashboard.png",
    "Overview dashboard for the demo organisation: 128 assets, 32 high-risk findings, 57/100 quantum exposure.")

module_section(
    "5.2 Discovery",
    "Lists every connected source (website / ZIP / repository) with its status, asset count, risk score and last "
    "scan time, plus a scan-history table. \"Scan now\" re-runs discovery on demand.",
    "<font face='Courier'>apps.discovery</font> - <font face='Courier'>AssetSource</font>, "
    "<font face='Courier'>ScanJob</font>, <font face='Courier'>ScanResult</font> models; "
    "<font face='Courier'>discovery_service.py</font> for the website/ZIP/repo scan implementations.",
    "03-discovery.png",
    "Discovery page: connected sources for the demo org, each independently re-scannable.")

module_section(
    "5.3 Crypto Inventory",
    "The master, searchable table of every cryptographic asset ever observed - algorithm, application, purpose, key "
    "size, risk, and quantum status. Filterable by risk level; clicking a row opens a detail drawer with full "
    "evidence (file location or TLS handshake data) and a \"Compare with PQC\" action.",
    "<font face='Courier'>apps.inventory</font> - the <font face='Courier'>CryptoAsset</font> model, plus "
    "<font face='Courier'>catalog.py</font> (the algorithm reference data: family, primitive, quantum status for "
    "every known algorithm, classical and post-quantum).",
    "04-inventory.png",
    "Crypto asset inventory: 128 assets, sorted by risk, each traceable to an application and evidence source.")

module_section(
    "5.4 CBOM Explorer",
    "Generates and browses CycloneDX 1.6 Cryptography Bills of Materials - the standard machine-readable format for "
    "a crypto inventory. Supports uploading an existing CBOM (JSON or XML) as well as generating one from the live "
    "inventory, with JSON/XML export and schema validation.",
    "<font face='Courier'>apps.cbom</font> - <font face='Courier'>CBOMDocument</font>/"
    "<font face='Courier'>CBOMComponent</font>/<font face='Courier'>CBOMDependency</font>; "
    "<font face='Courier'>cbom_service.py</font> builds and parses real CycloneDX structures (not a custom format).",
    "05-cbom-filled.png",
    "CBOM explorer: a generated organisation-wide CBOM plus one imported from a public-repository scan.")

module_section(
    "5.5 Risk Assessment",
    "The transparent scoring engine's output. Every finding shows its final 0-100 score broken into the nine "
    "weighted factors that produced it, in plain language - never a black-box number.",
    "<font face='Courier'>apps.risk</font> - <font face='Courier'>risk_service.py</font>: "
    "<font face='Courier'>score_asset()</font> computes and explains every factor; weights and severity thresholds "
    "are configurable per organisation under Settings.",
    "06-risk.png",
    "Risk assessment: overall organisation score plus the ranked list of individual findings.")

module_section(
    "5.6 PQC Comparison",
    "The purpose-aware recommendation engine. Pick a classical asset from inventory; QS-AMP shows only the PQC "
    "families that are actually applicable to its recorded purpose, with FIPS-standard key/ciphertext sizes and (if "
    "any exist) real benchmark numbers, clearly labelled by data source.",
    "<font face='Courier'>apps.comparison</font> - <font face='Courier'>comparison_service.py</font>: "
    "<font face='Courier'>recommend_pqc()</font> and <font face='Courier'>compare_classical_vs_pqc()</font>. A "
    "KEM-vs-signature mismatch is rejected server-side with an explicit error, not silently allowed.",
    "07-comparison-filled.png",
    "PQC comparison for a payments RSA-2048 key-exchange asset: only ML-KEM candidates are offered, with size deltas.",
    extra=["Verified live: comparing ECDSA-P256 (a signature) against ML-KEM-768 (a KEM) is rejected with "
           "\"incompatible_primitives\" - this rule is enforced in the API, not just the UI."])

module_section(
    "5.7 Dependencies (Architecture graph)",
    "An interactive node graph (React Flow) per application: which certificates, libraries and algorithms it uses, "
    "colour-coded by risk. Lets you see the blast radius of a single weak algorithm across an application.",
    "<font face='Courier'>apps.inventory.architecture_service.py</font> builds "
    "<font face='Courier'>ArchitectureNode</font>/<font face='Courier'>ArchitectureEdge</font> rows from the live "
    "inventory; rendered client-side with <font face='Courier'>@xyflow/react</font>.",
    "08-architecture.png",
    "Crypto dependency map for admin-console: certificates and a BouncyCastle library feeding RSA/ECDSA/3DES usage.")

module_section(
    "5.8 Monitoring",
    "Continuous-monitoring status and a live event timeline (certificate changes, new dependencies, new algorithms, "
    "risk changes). Sources can opt into scheduled re-scans; a demo-mode simulator produces realistic events when no "
    "real schedule has fired yet, always labelled as simulated.",
    "<font face='Courier'>apps.monitoring</font> - <font face='Courier'>MonitoringConfiguration</font>/"
    "<font face='Courier'>MonitoringEvent</font>; <font face='Courier'>monitoring_service.py</font> "
    "(<font face='Courier'>simulate_scan</font> for demo events, <font face='Courier'>real_scan</font>/"
    "<font face='Courier'>run_due_scans</font> for the real scheduled path).",
    "09-monitoring.png",
    "Monitoring: configuration status and the live event feed for the demo organisation.")

module_section(
    "5.9 Migration Planner",
    "A Kanban board (Backlog -&gt; Planned -&gt; In Progress -&gt; Testing -&gt; Verified -&gt; Completed) "
    "tracking every asset's move from its current algorithm to a PQC target, plus a 7-phase progress rail "
    "(Inventory, Assessment, Planning, Hybrid, PQC, Verification, Decommission).",
    "<font face='Courier'>apps.migration</font> - <font face='Courier'>MigrationProject</font>/"
    "<font face='Courier'>MigrationTask</font>/<font face='Courier'>MigrationDependency</font>. Targets are stored "
    "as recommendation candidates, never asserted as the single correct answer.",
    "10-migration.png",
    "Migration planner: 24 tasks across six Kanban columns, 17% overall progress.")

module_section(
    "5.10 Benchmarks",
    "Runs and stores real algorithm timing measurements - key generation, encapsulation/decapsulation, sign/verify - "
    "using whatever cryptographic implementation is actually available in the environment.",
    "<font face='Courier'>apps.benchmarks</font> - <font face='Courier'>BenchmarkRunner</font> pattern in "
    "<font face='Courier'>benchmark_service.py</font> with pluggable adapters: pyca/cryptography (OpenSSL, classical "
    "algorithms), kyber-py/dilithium-py (pure-Python ML-KEM/ML-DSA), an optional native liboqs adapter, and a clearly "
    "labelled synthetic Demo adapter used only when nothing real is available.",
    "11-benchmarks.png",
    "Benchmark run configuration and results, each row labelled by data source (measured vs. demo).",
    extra=["Verified live: an ML-KEM-768 key-generation benchmark actually executed the kyber-py implementation on "
           "the host and returned a real measured timing - not a placeholder."])

module_section(
    "5.11 Reports",
    "Generates four report types (Executive Security, Cryptographic Inventory, Quantum Risk, Migration Roadmap) as "
    "downloadable PDF, CSV or JSON files - each one a real file on disk, not a client-side print dialog.",
    "<font face='Courier'>apps.reports</font> - <font face='Courier'>Report</font> model; "
    "<font face='Courier'>report_service.py</font> renders PDFs with ReportLab from the same live data every other "
    "screen reads.",
    "12-reports.png",
    "Reports library: generated PDF/CSV artifacts, each downloadable and re-fetchable later.")

module_section(
    "5.12 Alerts",
    "A triage queue for anything that needs a human decision - new vulnerable algorithm, certificate expiring, new "
    "crypto dependency, risk increase, scan failure. Supports acknowledge / resolve / assign / mute.",
    "<font face='Courier'>apps.alerts</font> - <font face='Courier'>Alert</font> model; "
    "<font face='Courier'>alert_service.py</font> creates alerts from risk re-scoring and monitoring events, with "
    "de-duplication so the same finding doesn't spam the queue.",
    "13-alerts.png",
    "Alerts queue: open findings by severity, ready to acknowledge, resolve or assign.")

module_section(
    "5.13 Settings",
    "Organisation-wide configuration that works even before any source exists: general settings, team roles "
    "(Owner/Admin/Security&nbsp;Analyst/Developer/Auditor/Viewer), risk factor weights and severity thresholds, "
    "scanning defaults, notification rules, API keys, and mock integrations (GitHub, Slack, AWS/Azure/GCP, etc.).",
    "<font face='Courier'>apps.organizations</font> - role permissions in "
    "<font face='Courier'>permissions.py</font>, configurable defaults in <font face='Courier'>defaults.py</font>; "
    "<font face='Courier'>apps.integrations</font> for the connector cards.",
    "14-settings.png",
    "Settings: organisation, security and risk-weight configuration.")

# ============================================================= 6. REAL VS SIMULATED
story.append(Paragraph("6. What Is Real vs. Simulated - Be Ready for This Question", styles["h1"]))
story.append(P("Every TL asks this. Here is the honest breakdown, verified by exercising the running app end to end, "
              "not just reading the code."))
story.append(kv_table(header=["Capability", "Status"], col_widths=[3.0 * inch, CONTENT_W - 3.0 * inch], rows=[
    ["Website TLS scan", "Real: opens an actual TLS handshake against the target host and reads the live certificate/cipher/protocol."],
    ["ZIP source scan", "Real: safely extracts the archive (Zip-Slip / zip-bomb / path-traversal guarded) and statically greps for crypto API usage."],
    ["Public repository scan", "Real: runs an actual `git clone --depth 1` of the given URL/branch, then the same static scan."],
    ["CBOM generation/import/export", "Real CycloneDX 1.6 structures - validated, not a made-up JSON shape."],
    ["Risk scoring", "Real, deterministic and fully explainable - not random or hard-coded per algorithm."],
    ["PQC recommendation sizes", "Real specification data from FIPS 203/204/205 - not estimated."],
    ["Benchmark timings", "Real measurements when a supporting library is available (OpenSSL via pyca/cryptography for "
     "classical algorithms; kyber-py/dilithium-py for ML-KEM/ML-DSA). Falls back to a clearly labelled synthetic "
     "\"Demo benchmark\" only when nothing real can run - the two are never mixed in the UI."],
    ["Continuous monitoring schedule", "The scheduling and event model are real; in local/demo mode, events are produced by "
     "a simulator (explicitly labelled) instead of waiting for a real interval to elapse - the same code path supports "
     "real scheduled re-scans via Celery beat / a cron command."],
    ["Cloud connectors (AWS/Azure/GCP) on the Integrations page", "Deliberately mocked - shows a \"connection configured\" "
     "state, does not call a real cloud API. This was a known, intentional MVP scope limit."],
    ["\"Cloud / Infrastructure\" as an addable discovery source", "Removed. It existed as an option with no backing "
     "implementation and has been deleted from both the source-type list and the Add-source UI."],
]))
story.append(PageBreak())

# ============================================================= 7. SECURITY
story.append(Paragraph("7. Security &amp; Correctness Highlights", styles["h1"]))
story.append(Paragraph("Security controls", styles["h2"]))
story += bullets([
    "<b>Authentication:</b> JWT access + refresh tokens (djangorestframework-simplejwt), optional TOTP MFA (pyotp), "
    "and hashed API keys (only a SHA-256 hash is ever stored; the raw key is shown once at creation).",
    "<b>Passwords:</b> hashed with Django's PBKDF2 hasher; never logged or stored in plaintext.",
    "<b>Organisation isolation (multi-tenancy):</b> every org-owned table carries an explicit "
    "<font face='Courier'>organization</font> foreign key, and a shared mixin (<font face='Courier'>OrgScopedMixin</font>) "
    "filters every queryset by the caller's active organisation before it ever reaches a serializer.",
    "<b>Role-based permissions:</b> Owner / Admin / Security Analyst / Developer / Auditor / Viewer, enforced per "
    "endpoint (read vs. write roles), not just hidden in the UI.",
    "<b>File-upload safety:</b> ZIP uploads are checked for Zip-Slip (path traversal), decompression bombs, symlinks "
    "and disallowed executable extensions before a single byte is written to disk; uploads live under a media "
    "directory outside the served source tree.",
    "<b>Consistent error format:</b> every API error returns the same JSON envelope "
    "(<font face='Courier'>{\"success\": false, \"error\": {\"code\", \"message\"}}</font>), so the frontend never "
    "has to guess a shape.",
    "<b>Audit log:</b> every create/update/delete across the org-scoped modules is recorded with who, what and when."])
story.append(Paragraph("Cryptographic correctness (the part most tools get wrong)", styles["h2"]))
story += bullets([
    "The recommendation engine never treats \"post-quantum\" as one interchangeable bucket. A KEM (ML-KEM) is only "
    "ever offered for key-exchange/encryption uses; a signature scheme (ML-DSA/SLH-DSA) is only ever offered for "
    "signing uses. Mismatched pairs are rejected by the API itself, confirmed by direct testing.",
    "Claims are hedged deliberately - the app says an algorithm is \"designed/standardised for post-quantum "
    "security\" or \"believed secure under current analysis\", never \"quantum-proof\". This matches how NIST and "
    "the security community describe these algorithms.",
    "Symmetric ciphers (AES) and hash functions (SHA-2/3) are analysed separately from public-key algorithms, "
    "because Grover's algorithm affects them differently (a smaller effective security margin, not a full break) - "
    "the engine never recommends a PQC algorithm as a replacement for AES or SHA-256."])
story.append(PageBreak())

# ============================================================= 8. TL Q&A CHEAT SHEET
story.append(Paragraph("8. Quick Answers for Common Questions", styles["h1"]))
qa = [
    ("What is this, in one sentence?",
     "A platform that scans real code/websites/repos for cryptography, scores the quantum risk of what it finds, and "
     "tells you the correct post-quantum replacement and migration plan for each specific use."),
    ("Is any of this simulated or fake?",
     "The scanning, inventory, CBOM, risk scoring, PQC recommendation sizes and most benchmarks are real, verified "
     "by exercising the running app. Continuous-monitoring events default to a clearly-labelled simulator until a "
     "real interval elapses, and cloud connectors are intentionally mocked in this MVP. See section 6 for the full list."),
    ("Why can't I just tell it to replace RSA with a PQC algorithm automatically?",
     "Because RSA is used for two different jobs - key exchange and signing - and they map to different PQC "
     "families (ML-KEM vs. ML-DSA/SLH-DSA). QS-AMP determines the recorded purpose first and only then narrows the "
     "candidate list; this is enforced server-side, not just suggested in the UI."),
    ("What database does it use, and is tenant data actually isolated?",
     "PostgreSQL. Every organisation-owned table has an explicit organization_id and a shared query mixin filters by "
     "it on every request, before serialization - there is no code path that returns another organisation's rows."),
    ("How do I run it locally?",
     "Backend: create a PostgreSQL database, copy backend/.env.example to .env and fill in the DB credentials, then "
     "python manage.py migrate && python manage.py seed_demo && python manage.py runserver. Frontend: "
     "npm install && npm run dev in frontend/, pointed at the backend's /api/ base URL via VITE_API_BASE_URL. "
     "docker-compose.yml at the repo root wires Postgres + Redis + backend + frontend together for one-command startup."),
    ("What's the biggest known gap right now?",
     "GitHub OAuth-based repository connection (as opposed to a public repo URL, which works today) and the mocked "
     "cloud connectors are the two places where the UI's ambition is ahead of a real backend integration. Everything "
     "else on the sidebar is backed by real, working code."),
]
for q, a in qa:
    story.append(Paragraph(f"Q: {q}", styles["qa_q"]))
    story.append(Paragraph(f"A: {a}", styles["qa_a"]))

# ============================================================= build with TOC pass
def build():
    doc.multiBuild(story)
    print("wrote", OUT)


if __name__ == "__main__":
    build()
