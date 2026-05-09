"""Penetration testing report: session transcript → LLM JSON → fixed-layout PDF (ReportLab)."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

_REPORTLAB_INSTALL_HINT = (
    "Install on the agent host: pip install 'reportlab>=4.0.0' "
    "or pip install -r agent/requirements.txt "
    "or pip install -r agent/dependencies/requirements.txt (from the NyxStrike/CipherStrike repo)."
)


def _ensure_reportlab_available() -> None:
    """Fail fast with an operator-actionable message (PDF layout depends on ReportLab)."""
    try:
        import reportlab  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "Missing optional dependency 'reportlab' required for penetration-report PDF generation. "
            + _REPORTLAB_INSTALL_HINT
        ) from e

_JSON_FENCE = re.compile(r"\{[\s\S]*\}")

# Drop or neutralize operator-platform leakage (never surface raw agent/toolchain failures to clients).
_OP_LEAK_MATCH = re.compile(
    r"(?i)\bnyxstrike\b|nyx\s*strike|\btraceback\b|\bstderr\b|\bstderr:\b|"
    r"reportlab\s*(missing|not\s+installed|error)|json\s+parse|parseable\s+json|"
    r"\bllm\b.*\b(return|fail)|model\s+did\s+not\s+return|agent\s+microservice|"
    r"tool\s+invocation\s+fail|cipherstrike_bridge|internal\s+server\s+error\s*\(\d+\)",
)
_NYX_TOKEN = re.compile(r"(?i)\bnyxstrike\b|nyx\s*strike")


def _xml_escape(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sanitize_client_sentence(s: str) -> str:
    """Remove platform/agent noise; keep assessment substance."""
    t = (s or "").strip()
    if not t:
        return ""
    t = _NYX_TOKEN.sub("", t)
    t = re.sub(r"\s{2,}", " ", t).strip()
    if not t:
        return ""
    if _OP_LEAK_MATCH.search(t):
        if len(t) <= 320:
            return ""
        return ""
    return t


def _sanitize_str_list(items: List[str]) -> List[str]:
    out: List[str] = []
    for x in items:
        s = _sanitize_client_sentence(str(x))
        if s:
            out.append(s)
    return out


def _sanitize_client_report_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """Post-process LLM output so delivered PDFs stay client-centric."""
    rt = _sanitize_client_sentence(str(data.get("report_title") or ""))
    data["report_title"] = rt if rt else "PENETRATION TESTING REPORT"
    cn = _sanitize_client_sentence(str(data.get("client_name") or ""))
    if not cn:
        cn = str(data.get("client_name") or "").strip()
    data["client_name"] = cn or "Client"
    tp = _sanitize_client_sentence(str(data.get("target_primary") or ""))
    if not tp:
        tp = str(data.get("target_primary") or "").strip()
    data["target_primary"] = tp or "See scope documentation"
    spr = _sanitize_client_sentence(str(data.get("security_posture_rating") or ""))
    if not spr:
        spr = str(data.get("security_posture_rating") or "").strip()
    data["security_posture_rating"] = spr or "Not rated"
    og = _sanitize_client_sentence(str(data.get("overall_grade") or ""))
    if not og:
        og = str(data.get("overall_grade") or "").strip()
    data["overall_grade"] = og or data["security_posture_rating"]

    data["executive_summary"] = _sanitize_str_list(_as_str_list(data.get("executive_summary")))
    data["strengths"] = _sanitize_str_list(_as_str_list(data.get("strengths")))
    data["areas_of_concern"] = _sanitize_str_list(_as_str_list(data.get("areas_of_concern")))
    data["recommendations_immediate"] = _sanitize_str_list(_as_str_list(data.get("recommendations_immediate")))
    data["recommendations_short_term"] = _sanitize_str_list(_as_str_list(data.get("recommendations_short_term")))
    data["recommendations_long_term"] = _sanitize_str_list(_as_str_list(data.get("recommendations_long_term")))
    data["conclusion_paragraphs"] = _sanitize_str_list(_as_str_list(data.get("conclusion_paragraphs")))
    data["appendix_scope"] = _sanitize_str_list(_as_str_list(data.get("appendix_scope")))
    data["appendix_limitations"] = _sanitize_str_list(_as_str_list(data.get("appendix_limitations")))
    note = _sanitize_client_sentence(str(data.get("transcript_coverage_note") or ""))
    data["transcript_coverage_note"] = note

    recon = data.get("recon_sections")
    if isinstance(recon, list):
        for sec in recon:
            if not isinstance(sec, dict):
                continue
            sec["narrative_paragraphs"] = _sanitize_str_list(_as_str_list(sec.get("narrative_paragraphs")))
            sec["bullets"] = _sanitize_str_list(_as_str_list(sec.get("bullets")))
            stitle = _sanitize_client_sentence(str(sec.get("subsection_title") or ""))
            sec["subsection_title"] = stitle if stitle else "Reconnaissance"
            ntr = sec.get("notes_table_rows")
            if isinstance(ntr, list):
                for row in ntr:
                    if isinstance(row, dict):
                        for k in ("col_a", "col_b"):
                            if k in row:
                                row[k] = _sanitize_client_sentence(str(row[k]))

    tf = data.get("technical_findings")
    if isinstance(tf, list):
        for block in tf:
            if not isinstance(block, dict):
                continue
            block["title"] = _sanitize_client_sentence(str(block.get("title") or "")) or "Application security finding"
            block["narrative_paragraphs"] = _sanitize_str_list(_as_str_list(block.get("narrative_paragraphs")))
            tt = block.get("tools_table")
            if isinstance(tt, list):
                for trow in tt:
                    if isinstance(trow, dict):
                        for k in ("tool", "test_type", "status", "findings"):
                            if k in trow:
                                trow[k] = _sanitize_client_sentence(str(trow.get(k) or ""))

    rm = data.get("risk_matrix_rows")
    if isinstance(rm, list):
        for r in rm:
            if isinstance(r, dict):
                for k in ("finding", "recommended_action", "risk_level", "priority"):
                    if k in r:
                        r[k] = _sanitize_client_sentence(str(r.get(k) or ""))

    ap = data.get("appendix_tools")
    if isinstance(ap, list):
        for a in ap:
            if isinstance(a, dict):
                if a.get("description"):
                    a["description"] = _sanitize_client_sentence(str(a["description"]))
                if a.get("tool"):
                    a["tool"] = _sanitize_client_sentence(str(a["tool"]))

    rows = data.get("assessment_overview_rows")
    if isinstance(rows, list):
        for r in rows:
            if isinstance(r, dict):
                for k in ("metric", "value"):
                    if k in r:
                        r[k] = _sanitize_client_sentence(str(r.get(k) or ""))
        data["assessment_overview_rows"] = [
            x
            for x in rows
            if isinstance(x, dict) and (str(x.get("metric") or "").strip() or str(x.get("value") or "").strip())
        ]

    return data

# Matches client/src/app/globals.css (@theme / Stitch export) — use these tokens only (no ad‑hoc colors).
_CIPHERSTRIKE_THEME = {
    "primary": "#684cb6",
    "on_primary": "#ffffff",
    "primary_dim": "#5b3fa9",
    "primary_container": "#e9ddff",
    "on_primary_container": "#22005d",
    "surface": "#fdfcff",
    "surface_container": "#f1f0f7",
    "surface_container_high": "#ebe9f4",
    "surface_variant": "#e2e1ec",
    "on_surface": "#1b1b21",
    "on_surface_variant": "#45464f",
    "outline": "#767680",
    "outline_variant": "#c6c5d0",
    "error": "#a8364b",
}


def _theme_hex(key: str) -> Any:
    from reportlab.lib import colors

    return colors.HexColor(_CIPHERSTRIKE_THEME[key])


def _cipherstrike_table_surface_style(*, num_rows: int) -> Any:
    """Backgrounds + grid + padding only; typography comes from Paragraph cells (readable wrapping)."""
    from reportlab.platypus import TableStyle

    hp = _theme_hex("primary")
    surf = _theme_hex("surface")
    surf_c = _theme_hex("surface_container")
    grid = _theme_hex("outline_variant")

    cmd: list[tuple[Any, ...]] = [
        ("BACKGROUND", (0, 0), (-1, 0), hp),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, grid),
    ]
    if num_rows > 1:
        cmd.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [surf, surf_c]))
    return TableStyle(cmd)


def extract_json_object(text: str) -> Dict[str, Any] | None:
    if not text or not isinstance(text, str):
        return None
    raw = text.strip()
    m = _JSON_FENCE.search(raw)
    if m:
        raw = m.group(0)
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


_LLM_SYSTEM = """You are the author of a formal penetration test report for CLIENT DELIVERY: security operations leadership,
product/engineering leads, and executives. Write like a polished red-team / offensive-security consulting memo—precise, calm,
business-professional, and centered on the client's systems and risk—not lab notes or vendor troubleshooting.

Given the FULL session transcript (user messages, assistant replies, tool outputs), produce ONE JSON object only.
No markdown fences, no commentary outside JSON.

ABSOLUTE PROHIBITIONS (client-facing sections):
- Never name or allude to NyxStrike, agent runtimes, LLMs, JSON formatting, ReportLab, bridges, microservices, tracebacks,
  stderr, stack traces, HTTP 500s, or other internal platform errors. Those details must NEVER appear in executive_summary,
  strengths, areas_of_concern, recon narratives, technical_findings narratives or tools_table "findings", risk_matrix_rows,
  recommendations, conclusion, or transcript_coverage_note.
- If the transcript contains platform/agent failures, IGNORE them for narrative sections; optionally summarize ONLY neutral
  testing limitations under appendix_limitations (e.g. "Automated scanning coverage was partial during the engagement window")
  without naming internal components.

VOICE & FRAMING:
- Focus on the TARGET ENVIRONMENT: observations, likelihood, business/security impact, validation steps, and remediation owners.
- Reframe incomplete tooling outcomes as CLIENT RISK & COVERAGE GAPS (what remains unknown or unvalidated), never as
  "tool X failed".
- Keep tools_table factual but client-safe: status columns may be concise; the "findings" column must describe impact and
  evidence for the organization—not raw command output.

CONTENT PRIORITY:
1) Executive summary: scope + asset + the highest-signal outcomes for defenders (paths, auth/admin exposure, vuln-class signals).
2) assessment_overview_rows: executive-readable metrics (target, phase, validation status).
3) strengths / areas_of_concern: about THE APPLICATION and its exposure, not the engagement toolchain.
4) recon_sections: assets, paths, and why they matter to blue teams; minimize tool name-dropping in prose.
5) technical_findings: themes titled for stakeholder clarity; narratives are client-centric.
6) risk_matrix_rows: each finding reads as organizational risk; recommended_action is practical for the client's teams.
7) recommendations_*: prioritized remediation—ownership-ready (engineering, IT, AppSec), not operator configuration trivia.

Include substantive transcript-backed detail: hosts, URLs, IPs, severities, templates, headers, paths—accurately.

Schema (all keys required; use empty strings or empty arrays where unknown):
{
  "report_title": "PENETRATION TESTING REPORT",
  "client_name": "string",
  "target_primary": "string (primary domain/host or scope)",
  "assessment_date_iso": "YYYY-MM-DD or empty",
  "executive_summary": ["paragraph strings"],
  "assessment_overview_rows": [{"metric": "string", "value": "string"}],
  "security_posture_rating": "string e.g. B+",
  "strengths": ["bullet strings"],
  "areas_of_concern": ["bullet strings"],
  "recon_sections": [
    {"subsection_title": "2.1 Title", "narrative_paragraphs": ["..."], "bullets": ["optional"], "notes_table_rows": [{"col_a": "", "col_b": ""}]}
  ],
  "technical_findings": [
    {"title": "3.x Title", "narrative_paragraphs": ["..."], "tools_table": [{"tool": "", "test_type": "", "status": "", "findings": ""}]}
  ],
  "risk_matrix_rows": [{"priority": "1", "finding": "", "risk_level": "", "recommended_action": ""}],
  "recommendations_immediate": ["0-30 days"],
  "recommendations_short_term": ["30-90 days"],
  "recommendations_long_term": ["90+ days"],
  "conclusion_paragraphs": ["..."],
  "overall_grade": "string",
  "appendix_tools": [{"tool": "", "description": ""}],
  "appendix_scope": ["scope bullet strings"],
  "appendix_limitations": ["limitation bullet strings"],
  "transcript_coverage_note": "empty if full; otherwise one short neutral sentence on coverage—no internal systems"
}

Rules:
- Derive appendix_tools from techniques/tools referenced (neutral methodology labels).
- Counts must match the transcript when stated; otherwise "Not quantified in session".
- Never invent critical exploits not evidenced in the transcript; use "not observed in completed testing" where appropriate.
"""


def _as_str_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v] if v.strip() else []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v).strip()] if str(v).strip() else []


def _normalize_report_data(raw: Dict[str, Any], *, fallback_client: str, fallback_target: str) -> Dict[str, Any]:
    out = dict(raw)
    out["report_title"] = str(out.get("report_title") or "PENETRATION TESTING REPORT").strip()
    out["client_name"] = str(out.get("client_name") or fallback_client or "Client").strip()
    out["target_primary"] = str(out.get("target_primary") or fallback_target or "See transcript").strip()
    date_iso = str(out.get("assessment_date_iso") or "").strip()
    if not date_iso:
        date_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out["assessment_date_iso"] = date_iso
    out["executive_summary"] = _as_str_list(out.get("executive_summary"))
    rows = out.get("assessment_overview_rows")
    if not isinstance(rows, list):
        rows = []
    norm_rows = []
    for r in rows:
        if isinstance(r, dict):
            norm_rows.append(
                {
                    "metric": str(r.get("metric") or "").strip(),
                    "value": str(r.get("value") or "").strip(),
                }
            )
    out["assessment_overview_rows"] = norm_rows
    out["security_posture_rating"] = str(out.get("security_posture_rating") or "Not rated").strip()
    out["strengths"] = _as_str_list(out.get("strengths"))
    out["areas_of_concern"] = _as_str_list(out.get("areas_of_concern"))
    rec = out.get("recon_sections")
    if not isinstance(rec, list):
        rec = []
    recon_out = []
    for sec in rec:
        if not isinstance(sec, dict):
            continue
        ntr = sec.get("notes_table_rows")
        if not isinstance(ntr, list):
            ntr = []
        tbl = []
        for row in ntr:
            if isinstance(row, dict):
                ca = str(row.get("col_a") or row.get("Subdomain") or row.get("metric") or "").strip()
                cb = str(row.get("col_b") or row.get("Notes") or row.get("value") or "").strip()
                if not ca and not cb and row:
                    vals = [str(v) for v in row.values()]
                    ca = vals[0] if vals else ""
                    cb = vals[1] if len(vals) > 1 else ""
                tbl.append({"col_a": ca, "col_b": cb})
        recon_out.append(
            {
                "subsection_title": str(sec.get("subsection_title") or "Reconnaissance").strip(),
                "narrative_paragraphs": _as_str_list(sec.get("narrative_paragraphs")),
                "bullets": _as_str_list(sec.get("bullets")),
                "notes_table_rows": tbl,
            }
        )
    out["recon_sections"] = recon_out
    tf = out.get("technical_findings")
    if not isinstance(tf, list):
        tf = []
    tf_out = []
    for block in tf:
        if not isinstance(block, dict):
            continue
        tt = block.get("tools_table")
        if not isinstance(tt, list):
            tt = []
        tools_norm = []
        for trow in tt:
            if isinstance(trow, dict):
                tools_norm.append(
                    {
                        "tool": str(trow.get("tool") or "").strip(),
                        "test_type": str(trow.get("test_type") or "").strip(),
                        "status": str(trow.get("status") or "").strip(),
                        "findings": str(trow.get("findings") or "").strip(),
                    }
                )
        tf_out.append(
            {
                "title": str(block.get("title") or "Finding").strip(),
                "narrative_paragraphs": _as_str_list(block.get("narrative_paragraphs")),
                "tools_table": tools_norm,
            }
        )
    out["technical_findings"] = tf_out
    rm = out.get("risk_matrix_rows")
    if not isinstance(rm, list):
        rm = []
    rm_out = []
    for r in rm:
        if isinstance(r, dict):
            rm_out.append(
                {
                    "priority": str(r.get("priority") or "").strip(),
                    "finding": str(r.get("finding") or "").strip(),
                    "risk_level": str(r.get("risk_level") or "").strip(),
                    "recommended_action": str(r.get("recommended_action") or "").strip(),
                }
            )
    out["risk_matrix_rows"] = rm_out
    out["recommendations_immediate"] = _as_str_list(out.get("recommendations_immediate"))
    out["recommendations_short_term"] = _as_str_list(out.get("recommendations_short_term"))
    out["recommendations_long_term"] = _as_str_list(out.get("recommendations_long_term"))
    out["conclusion_paragraphs"] = _as_str_list(out.get("conclusion_paragraphs"))
    out["overall_grade"] = str(out.get("overall_grade") or out["security_posture_rating"]).strip()
    ap = out.get("appendix_tools")
    if not isinstance(ap, list):
        ap = []
    ap_out = []
    for a in ap:
        if isinstance(a, dict):
            ap_out.append(
                {
                    "tool": str(a.get("tool") or "").strip(),
                    "description": str(a.get("description") or "").strip(),
                }
            )
    out["appendix_tools"] = ap_out
    out["appendix_scope"] = _as_str_list(out.get("appendix_scope"))
    out["appendix_limitations"] = _as_str_list(out.get("appendix_limitations"))
    out["transcript_coverage_note"] = str(out.get("transcript_coverage_note") or "").strip()
    return _sanitize_client_report_payload(out)


def _llm_fill_report(transcript: str, llm_client: Any) -> Dict[str, Any]:
    user_content = (
        "Produce the JSON report for CLIENT DELIVERY. Audience: client security leadership and technical owners. "
        "They need clear risk and remediation guidance for THEIR environment—not internal agent/platform errors "
        "(omit those entirely from client sections; neutral engagement limitations only in appendix_limitations).\n\n"
        "--- TRANSCRIPT ---\n"
        + transcript.strip()
    )
    raw = llm_client.chat(
        [
            {"role": "system", "content": _LLM_SYSTEM},
            {"role": "user", "content": user_content},
        ],
        num_ctx=getattr(llm_client, "num_ctx_analyse", None) or 16384,
    )
    text = raw if isinstance(raw, str) else str((raw or {}).get("content") or "")
    parsed = extract_json_object(text) or {}
    if not parsed:
        logger.warning("pt_report_pdf: LLM returned no JSON; using minimal shell")
        return {
            "report_title": "PENETRATION TESTING REPORT",
            "executive_summary": [
                "A complete structured summary could not be produced automatically from the engagement record for this run. "
                "Please contact your assessment delivery contact for the full findings package and narrative."
            ],
            "assessment_overview_rows": [],
            "security_posture_rating": "Not assessed",
            "strengths": [],
            "areas_of_concern": [],
            "recon_sections": [],
            "technical_findings": [],
            "risk_matrix_rows": [],
            "recommendations_immediate": [],
            "recommendations_short_term": [],
            "recommendations_long_term": [],
            "conclusion_paragraphs": [],
            "overall_grade": "Not assessed",
            "appendix_tools": [],
            "appendix_scope": [],
            "appendix_limitations": [],
            "transcript_coverage_note": "",
        }
    return parsed


def _build_pdf_bytes(data: Dict[str, Any], generated_by: str) -> bytes:
    try:
        from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.pdfgen import canvas as pdfcanvas
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table
    except ImportError as e:
        raise RuntimeError(
            "Could not import 'reportlab' while building the PDF. " + _REPORTLAB_INSTALL_HINT
        ) from e

    styles = getSampleStyleSheet()
    on_surface = _theme_hex("on_surface")
    on_surface_variant = _theme_hex("on_surface_variant")
    primary = _theme_hex("primary")
    outline_variant = _theme_hex("outline_variant")

    h_cover = ParagraphStyle(
        name="CoverTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        spaceAfter=12,
        textColor=primary,
    )
    h1 = ParagraphStyle(
        name="H1",
        parent=styles["Heading1"],
        fontSize=14,
        leading=18,
        spaceBefore=12,
        spaceAfter=8,
        textColor=on_surface,
    )
    h2 = ParagraphStyle(
        name="H2",
        parent=styles["Heading2"],
        fontSize=11,
        leading=14,
        spaceBefore=10,
        spaceAfter=6,
        textColor=primary,
    )
    body = ParagraphStyle(
        name="Body",
        parent=styles["Normal"],
        fontSize=10,
        leading=13,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
        textColor=on_surface,
    )
    small = ParagraphStyle(
        name="Small",
        parent=styles["Normal"],
        fontSize=9,
        leading=11,
        textColor=on_surface_variant,
        alignment=TA_CENTER,
    )

    class NumberedCanvas(pdfcanvas.Canvas):
        def __init__(self, *args, **kwargs):
            pdfcanvas.Canvas.__init__(self, *args, **kwargs)
            self._saved_page_states: List[Dict[str, Any]] = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            n = len(self._saved_page_states)
            for s in self._saved_page_states:
                self.__dict__.update(s)
                self._draw_footer(n)
                pdfcanvas.Canvas.showPage(self)
            pdfcanvas.Canvas.save(self)

        def _draw_footer(self, page_count: int):
            self.saveState()
            self.setStrokeColor(outline_variant)
            self.setLineWidth(0.5)
            y_rule = 0.52 * inch
            self.line(0.75 * inch, y_rule, letter[0] - 0.75 * inch, y_rule)
            self.setFillColor(on_surface_variant)
            self.setFont("Helvetica", 9)
            self.drawCentredString(letter[0] / 2.0, 0.42 * inch, f"{self._pageNumber} / {page_count}")
            self.restoreState()

    def _draw_header_band(canvas: Any, doc_: Any) -> None:
        canvas.saveState()
        band_h = 6
        w, h = letter
        canvas.setFillColor(primary)
        canvas.rect(0, h - band_h, w, band_h, fill=1, stroke=0)
        canvas.restoreState()

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.78 * inch,
        bottomMargin=0.65 * inch,
    )
    story: List[Any] = []

    def p(text: str, style=body):
        t = (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        story.append(Paragraph(t, style))
        story.append(Spacer(1, 4))

    def bullet_list(items: List[str]):
        for it in items:
            p(f"• {it}", body)

    # Cover
    story.append(Spacer(1, 1.2 * inch))
    p(str(data.get("report_title") or "PENETRATION TESTING REPORT"), h_cover)
    p(str(data.get("client_name") or ""), ParagraphStyle("cn", parent=h_cover, fontSize=14))
    p(str(data.get("target_primary") or ""), ParagraphStyle("tg", parent=body, alignment=TA_CENTER, fontSize=12))
    p(
        "CONFIDENTIAL",
        ParagraphStyle("conf", parent=body, alignment=TA_CENTER, fontSize=11, textColor=_theme_hex("error")),
    )
    p(f"Date: {data.get('assessment_date_iso')}", ParagraphStyle("dt", parent=body, alignment=TA_CENTER))
    p(f"Generated by: {generated_by}", small)
    story.append(Spacer(1, 0.4 * inch))

    # 1 Executive summary
    p("1. EXECUTIVE SUMMARY", h1)
    for para in data.get("executive_summary") or []:
        p(str(para), body)
    p("1.1 Assessment Overview", h2)
    ov = data.get("assessment_overview_rows") or []
    if ov:
        tdata = [["Metric", "Value"]] + [[r.get("metric", ""), r.get("value", "")] for r in ov]
        tw = doc.width
        tbl = Table(tdata, colWidths=[tw * 0.35, tw * 0.65])
        tbl.setStyle(_cipherstrike_table_style(num_rows=len(tdata)))
        story.append(tbl)
        story.append(Spacer(1, 8))
    p("1.2 Security Posture Assessment", h2)
    p(f"Overall Security Rating: {data.get('security_posture_rating')}", body)
    p("Strengths:", ParagraphStyle("lb", parent=body, fontName="Helvetica-Bold"))
    bullet_list(data.get("strengths") or [])
    p("Areas of Concern:", ParagraphStyle("lb2", parent=body, fontName="Helvetica-Bold"))
    bullet_list(data.get("areas_of_concern") or [])

    # 2 Recon
    p("2. RECONNAISSANCE FINDINGS", h1)
    for sec in data.get("recon_sections") or []:
        p(str(sec.get("subsection_title") or ""), h2)
        for para in sec.get("narrative_paragraphs") or []:
            p(str(para), body)
        bullet_list(sec.get("bullets") or [])
        nrows = sec.get("notes_table_rows") or []
        if nrows:
            tdata = [["Item", "Detail"]] + [[r.get("col_a", ""), r.get("col_b", "")] for r in nrows]
            tw = doc.width
            tbl = Table(tdata, colWidths=[tw * 0.4, tw * 0.6])
            tbl.setStyle(_cipherstrike_table_style(num_rows=len(tdata)))
            story.append(tbl)
            story.append(Spacer(1, 6))

    # 3 Application security findings (stakeholder-facing section titles)
    p("3. APPLICATION SECURITY FINDINGS", h1)
    for block in data.get("technical_findings") or []:
        p(str(block.get("title") or ""), h2)
        for para in block.get("narrative_paragraphs") or []:
            p(str(para), body)
        tt = block.get("tools_table") or []
        if tt:
            tdata = [["Tool", "Test type", "Status", "Impact / evidence"]] + [
                [r.get("tool", ""), r.get("test_type", ""), r.get("status", ""), r.get("findings", "")]
                for r in tt
            ]
            tw = doc.width
            tbl = Table(tdata, colWidths=[tw * 0.18, tw * 0.22, tw * 0.15, tw * 0.45])
            tbl.setStyle(
                _cipherstrike_table_style(num_rows=len(tdata), header_fontsize=8, body_fontsize=7)
            )
            story.append(tbl)
            story.append(Spacer(1, 6))

    # 4 Risk
    p("4. RISK ASSESSMENT & RECOMMENDATIONS", h1)
    p("4.1 Risk Priority Matrix", h2)
    rm = data.get("risk_matrix_rows") or []
    if rm:
        tdata = [["Priority", "Finding", "Risk", "Recommended action"]] + [
            [r.get("priority", ""), r.get("finding", ""), r.get("risk_level", ""), r.get("recommended_action", "")]
            for r in rm
        ]
        tw = doc.width
        tbl = Table(tdata, colWidths=[tw * 0.08, tw * 0.32, tw * 0.12, tw * 0.48])
        tbl.setStyle(_cipherstrike_table_style(num_rows=len(tdata), header_fontsize=8, body_fontsize=7))
        story.append(tbl)
        story.append(Spacer(1, 8))
    p("4.2 Detailed Recommendations", h2)
    p("IMMEDIATE ACTIONS (0-30 days):", ParagraphStyle("im", parent=body, fontName="Helvetica-Bold"))
    bullet_list(data.get("recommendations_immediate") or [])
    p("SHORT-TERM ACTIONS (30-90 days):", ParagraphStyle("st", parent=body, fontName="Helvetica-Bold"))
    bullet_list(data.get("recommendations_short_term") or [])
    p("LONG-TERM ACTIONS (90+ days):", ParagraphStyle("lt", parent=body, fontName="Helvetica-Bold"))
    bullet_list(data.get("recommendations_long_term") or [])

    # 5 Conclusion
    p("5. CONCLUSION", h1)
    for para in data.get("conclusion_paragraphs") or []:
        p(str(para), body)
    p(f"Overall Security Grade: {data.get('overall_grade')}", ParagraphStyle("gr", parent=body, fontName="Helvetica-Bold"))

    # Appendices
    p("APPENDIX A: TOOLS REFERENCED (METHODOLOGY)", h1)
    ap = data.get("appendix_tools") or []
    for a in ap:
        p(f"• {a.get('tool', '')} — {a.get('description', '')}", body)
    p("APPENDIX B: SCOPE & LIMITATIONS", h1)
    p("Assessment Scope:", ParagraphStyle("sc", parent=body, fontName="Helvetica-Bold"))
    bullet_list(data.get("appendix_scope") or [])
    p("Limitations:", ParagraphStyle("lm", parent=body, fontName="Helvetica-Bold"))
    bullet_list(data.get("appendix_limitations") or [])
    note = str(data.get("transcript_coverage_note") or "").strip()
    if note:
        p("Note on transcript coverage:", ParagraphStyle("nt", parent=body, fontName="Helvetica-Bold"))
        p(note, body)

    doc.build(
        story,
        canvasmaker=NumberedCanvas,
        onFirstPage=_draw_header_band,
        onLaterPages=_draw_header_band,
    )
    pdf = buf.getvalue()
    buf.close()
    return pdf


def generate_penetration_report(
    *,
    session_transcript: str,
    client_name: str = "",
    target_label: str = "",
    generated_by: str = "CipherStrike",
    ui_context: str = "",
    llm_client: Any,
) -> Tuple[bytes, str, str]:
    """Return (pdf_bytes, filename, summary_for_llm)."""
    if not session_transcript or not str(session_transcript).strip():
        raise ValueError("session_transcript is required")

    _ensure_reportlab_available()

    extra = ""
    if ui_context and ui_context.strip():
        extra = "\n\nAdditional UI context:\n" + ui_context.strip()

    raw_llm = _llm_fill_report(session_transcript.strip() + extra, llm_client)
    data = _normalize_report_data(raw_llm, fallback_client=client_name, fallback_target=target_label)
    pdf = _build_pdf_bytes(data, generated_by=generated_by or "CipherStrike")

    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", data["target_primary"])[:48] or "report"
    filename = f"Penetration_Test_Report_{safe_target}.pdf"

    summary = (
        f"Generated penetration test PDF ({filename}). "
        f"Target: {data['target_primary']}. Grade: {data.get('overall_grade')}. "
        f"{data.get('transcript_coverage_note') or ''}".strip()
    )
    return pdf, filename, summary
