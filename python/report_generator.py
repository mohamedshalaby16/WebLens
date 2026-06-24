import io
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

from models import WebLensReport

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm

# ── Palette ───────────────────────────────────────────────────────────────────
DARK_BG     = colors.HexColor("#0f172a")
NAVY        = colors.HexColor("#1e3a8a")
BLUE        = colors.HexColor("#2563eb")
BLUE_LIGHT  = colors.HexColor("#dbeafe")
TEAL        = colors.HexColor("#0d9488")
GREEN       = colors.HexColor("#166534")
GREEN_BG    = colors.HexColor("#f0fdf4")
ORANGE      = colors.HexColor("#b45309")
ORANGE_BG   = colors.HexColor("#fff7ed")
RED         = colors.HexColor("#b91c1c")
RED_BG      = colors.HexColor("#fef2f2")
DARK_RED    = colors.HexColor("#7f1d1d")
DARK_RED_BG = colors.HexColor("#fef2f2")
SLATE       = colors.HexColor("#475569")
SLATE_LIGHT = colors.HexColor("#f1f5f9")
TEXT        = colors.HexColor("#1e293b")
MUTED       = colors.HexColor("#64748b")
RULE_COL    = colors.HexColor("#bfdbfe")
WHITE       = colors.white


def S(name, **kw):
    return ParagraphStyle(name, **kw)


def _verdict_colors(verdict: str) -> tuple:
    mapping = {
        "Safe":     (GREEN,    GREEN_BG),
        "Low":      (TEAL,     colors.HexColor("#f0fdfa")),
        "Moderate": (ORANGE,   ORANGE_BG),
        "High":     (RED,      RED_BG),
        "Critical": (DARK_RED, DARK_RED_BG),
    }
    return mapping.get(verdict, (NAVY, BLUE_LIGHT))


def _score_bar(score: int, verdict: str) -> Table:
    fg, _ = _verdict_colors(verdict)
    filled = max(1, round(score / 10))
    empty  = 10 - filled

    bar_cells = (
        [Paragraph("█", ParagraphStyle("b", fontName="Helvetica-Bold",
            fontSize=11, textColor=fg))] * filled +
        [Paragraph("░", ParagraphStyle("e", fontName="Helvetica",
            fontSize=11, textColor=colors.HexColor("#e2e8f0")))] * empty
    )
    t = Table([bar_cells], colWidths=[1.5*cm] * 10)
    t.setStyle(TableStyle([
        ('TOPPADDING',    (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ('LEFTPADDING',   (0,0), (-1,-1), 0),
        ('RIGHTPADDING',  (0,0), (-1,-1), 0),
    ]))
    return t


def _rule(color=RULE_COL, t=1.0):
    return HRFlowable(width="100%", thickness=t,
                      color=color, spaceAfter=4, spaceBefore=2)


def _section_header(title: str) -> list:
    return [
        _rule(BLUE, 1.2),
        Paragraph(title, ParagraphStyle("sh",
            fontName="Helvetica-Bold", fontSize=13,
            textColor=NAVY, spaceBefore=14, spaceAfter=5)),
    ]


def _info_table(rows: list[tuple[str, str]]) -> Table:
    tdata = []
    for label, value in rows:
        tdata.append([
            Paragraph(label, ParagraphStyle("lbl",
                fontName="Helvetica-Bold", fontSize=9.5,
                textColor=MUTED)),
            Paragraph(str(value), ParagraphStyle("val",
                fontName="Helvetica", fontSize=9.5,
                textColor=TEXT, leading=13)),
        ])
    t = Table(tdata, colWidths=[5*cm, 12.5*cm])
    t.setStyle(TableStyle([
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [SLATE_LIGHT, WHITE]),
        ('TOPPADDING',     (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',  (0,0), (-1,-1), 6),
        ('LEFTPADDING',    (0,0), (-1,-1), 8),
        ('RIGHTPADDING',   (0,0), (-1,-1), 8),
        ('GRID',           (0,0), (-1,-1), 0.3,
         colors.HexColor("#e2e8f0")),
        ('VALIGN',         (0,0), (-1,-1), 'TOP'),
    ]))
    return t


def generate_pdf(report: WebLensReport) -> bytes:
    """
    Generate a PDF report from a WebLensReport object.
    Returns the PDF as bytes.
    """
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=MARGIN,
        title=f"WebLens Report — {report.url}",
        author="WebLens Platform",
    )

    story = []

    # ── Cover header ──────────────────────────────────────────────────────────
    cover_rows = [[
        Paragraph("WebLens", ParagraphStyle("ct",
            fontName="Helvetica-Bold", fontSize=26,
            textColor=WHITE, alignment=TA_CENTER)),
        Paragraph("Web Intelligence & Phishing Risk Report",
            ParagraphStyle("cs", fontName="Helvetica", fontSize=11,
            textColor=colors.HexColor("#93c5fd"),
            alignment=TA_CENTER, spaceAfter=4)),
    ]]
    cover = Table(
        [[Paragraph("WebLens", ParagraphStyle("ct2",
            fontName="Helvetica-Bold", fontSize=26,
            textColor=WHITE, alignment=TA_CENTER, spaceAfter=6))],
         [Paragraph("Web Intelligence & Phishing Risk Report",
            ParagraphStyle("cs2", fontName="Helvetica", fontSize=11,
            textColor=colors.HexColor("#93c5fd"),
            alignment=TA_CENTER))]],
        colWidths=[PAGE_W - 2*MARGIN]
    )
    cover.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), DARK_BG),
        ('TOPPADDING',    (0,0), (-1,-1), 18),
        ('BOTTOMPADDING', (0,0), (-1,-1), 18),
        ('LEFTPADDING',   (0,0), (-1,-1), 20),
        ('RIGHTPADDING',  (0,0), (-1,-1), 20),
    ]))
    story.append(cover)
    story.append(Spacer(1, 10))

    # ── Job metadata ──────────────────────────────────────────────────────────
    story += _section_header("Job Information")
    story.append(_info_table([
        ("Job ID",    report.job_id),
        ("URL",       report.url),
        ("Timestamp", report.timestamp),
        ("Status",    report.status.upper()),
    ]))

    # ── Clone info ────────────────────────────────────────────────────────────
    story += _section_header("Clone Summary")
    story.append(_info_table([
        ("Fetcher Used",       report.clone.fetcher_used),
        ("Page Title",         report.clone.page_title or "—"),
        ("Assets Downloaded",  str(report.clone.assets_downloaded)),
        ("Assets Failed",      str(report.clone.assets_failed)),
        ("Forms Found",        str(report.clone.forms_found)),
        ("Links Found",        str(report.clone.links_found)),
        ("Clone Path",         report.clone.clone_path),
    ]))

    # ── Intelligence ──────────────────────────────────────────────────────────
    story += _section_header("Page Intelligence")
    story.append(_info_table([
        ("Page Type",      report.intelligence.page_type.title()),
        ("Technology Stack",
         ", ".join(report.intelligence.tech_stack) if report.intelligence.tech_stack else "None detected"),
        ("External Links", str(report.intelligence.external_links)),
        ("Internal Links", str(report.intelligence.internal_links)),
        ("Summary",        report.intelligence.summary),
    ]))

    # Forms found
    if report.intelligence.forms:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Forms Detected", ParagraphStyle("fh",
            fontName="Helvetica-Bold", fontSize=10,
            textColor=NAVY, spaceAfter=4)))
        for i, form in enumerate(report.intelligence.forms, 1):
            form_rows = [
                (f"Form {i} — Action", form.action or "—"),
                ("Method",            form.method),
                ("Fields",            ", ".join(form.fields) if form.fields else "—"),
            ]
            story.append(_info_table(form_rows))
            story.append(Spacer(1, 4))

    # ── Phishing risk ─────────────────────────────────────────────────────────
    story += _section_header("Phishing Risk Assessment")

    fg, bg = _verdict_colors(report.phishing_risk.verdict)
    score  = report.phishing_risk.score

    # Score bar + verdict
    score_data = [[
        _score_bar(score, report.phishing_risk.verdict),
        Paragraph(
            f"{score} / 100",
            ParagraphStyle("sc", fontName="Helvetica-Bold",
                fontSize=13, textColor=fg)),
        Paragraph(
            report.phishing_risk.verdict.upper(),
            ParagraphStyle("vd", fontName="Helvetica-Bold",
                fontSize=13, textColor=fg)),
    ]]
    score_t = Table(score_data, colWidths=[15.5*cm, 2.5*cm, 3*cm])
    score_t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), bg),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
        ('RIGHTPADDING',  (0,0), (-1,-1), 12),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(score_t)
    story.append(Spacer(1, 8))

    # Red flags
    if report.phishing_risk.red_flags:
        story.append(Paragraph("Red Flags Detected", ParagraphStyle("rfh",
            fontName="Helvetica-Bold", fontSize=10,
            textColor=RED, spaceAfter=4)))
        flag_rows = [[
            Paragraph(f"⚠  {flag}", ParagraphStyle("fl",
                fontName="Helvetica", fontSize=9.5,
                textColor=RED, leading=13))
        ] for flag in report.phishing_risk.red_flags]
        ft = Table(flag_rows, colWidths=[PAGE_W - 2*MARGIN])
        ft.setStyle(TableStyle([
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [RED_BG, WHITE]),
            ('TOPPADDING',     (0,0), (-1,-1), 5),
            ('BOTTOMPADDING',  (0,0), (-1,-1), 5),
            ('LEFTPADDING',    (0,0), (-1,-1), 10),
            ('RIGHTPADDING',   (0,0), (-1,-1), 10),
            ('GRID',           (0,0), (-1,-1), 0.3,
             colors.HexColor("#fecaca")),
        ]))
        story.append(ft)
        story.append(Spacer(1, 8))
    else:
        story.append(Paragraph(
            "✓  No red flags detected.",
            ParagraphStyle("nf", fontName="Helvetica",
                fontSize=10, textColor=GREEN,
                backColor=GREEN_BG,
                borderPadding=(8, 10, 8, 10), spaceAfter=8)
        ))

    # Explanation
    story.append(Paragraph("Assessment Explanation", ParagraphStyle("eh",
        fontName="Helvetica-Bold", fontSize=10,
        textColor=NAVY, spaceAfter=4)))
    story.append(Paragraph(
        report.phishing_risk.explanation,
        ParagraphStyle("ex", fontName="Helvetica", fontSize=10,
            textColor=TEXT, leading=15, alignment=TA_JUSTIFY,
            backColor=BLUE_LIGHT,
            borderPadding=(10, 12, 10, 12),
            spaceBefore=12)
            
    ))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(_rule(RULE_COL, 0.5))
    story.append(Paragraph(
        "Generated by WebLens — Web Intelligence & Phishing Risk Platform",
        ParagraphStyle("ft", fontName="Helvetica", fontSize=8,
            textColor=MUTED, alignment=TA_CENTER)
    ))

    doc.build(story)
    return buffer.getvalue()