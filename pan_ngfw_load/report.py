"""Assemble report sections into a PDF (reportlab platypus)."""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from . import __version__
from .dataset import Dataset

INK = colors.HexColor("#0b0b0b")
INK2 = colors.HexColor("#52514e")
RULE = colors.HexColor("#d8d7d2")
HEAD_BG = colors.HexColor("#eef3fb")
LEVEL_COL = {"info": "#2a78d6", "notice": "#eda100", "warning": "#d03b3b"}
DPI = 200  # chart PNG resolution

_ss = getSampleStyleSheet()
STY = {
    "title": ParagraphStyle("t", parent=_ss["Title"], fontSize=22, leading=26, alignment=TA_LEFT, textColor=INK),
    "subtitle": ParagraphStyle("st", parent=_ss["Normal"], fontSize=11, leading=15, textColor=INK2),
    "h1": ParagraphStyle("h1", parent=_ss["Heading1"], fontSize=15, leading=19, textColor=INK, spaceBefore=4, spaceAfter=6),
    "h2": ParagraphStyle("h2", parent=_ss["Heading2"], fontSize=11.5, leading=15, textColor=INK, spaceBefore=8, spaceAfter=4),
    "body": ParagraphStyle("b", parent=_ss["BodyText"], fontSize=9, leading=12.5, textColor=INK, spaceAfter=4),
    "small": ParagraphStyle("s", parent=_ss["BodyText"], fontSize=7.5, leading=10, textColor=INK2),
    "cell": ParagraphStyle("c", parent=_ss["BodyText"], fontSize=7.5, leading=9.5, textColor=INK),
    "find": ParagraphStyle("f", parent=_ss["BodyText"], fontSize=9, leading=12.5, textColor=INK, leftIndent=10),
}


@dataclass
class Ctx:
    ds: Dataset
    outdir: Path
    settings: dict = field(default_factory=dict)  # analysis thresholds (see cli._settings)
    findings: list[tuple[str, str, str]] = field(default_factory=list)  # (level, section, text)
    _n: int = 0
    _section: str = ""  # TITLE of the section being built
    _sec_no: int = 0

    @property
    def chartdir(self) -> Path:
        p = self.outdir / "charts"
        p.mkdir(parents=True, exist_ok=True)
        return p

    # --- flowable helpers used by sections ---------------------------------
    def h1(self, t):
        """Section titles are numbered in the order they appear, so a skipped section leaves no gap."""
        if t == self._section and not t.startswith("Appendix"):
            self._sec_no += 1
            t = f"{self._sec_no}&nbsp;&nbsp;{t}"
        return Paragraph(t, STY["h1"])
    def h2(self, t): return Paragraph(t, STY["h2"])
    def p(self, t): return Paragraph(t, STY["body"])
    def small(self, t): return Paragraph(t, STY["small"])

    def find(self, level: str, section: str, text: str):
        """Register a finding (shown in the summary) - level: info | notice | warning."""
        self.findings.append((level, section, text))

    def figure(self, f, name: str, caption: str | None = None, width_cm: float = 17.0):
        self._n += 1
        path = self.chartdir / f"{self._n:02d}_{name}.png"
        f.tight_layout()
        # 'tight' also keeps legends/labels placed outside the axes; the image is then shown at its
        # drawn size (fonts at their real point size), only shrunk if it is wider than the page
        f.savefig(path, dpi=DPI, bbox_inches="tight", pad_inches=0.04)
        plt.close(f)
        pw, ph = ImageReader(str(path)).getSize()
        w = min(pw / DPI * inch, width_cm * cm)
        img = Image(str(path), width=w, height=w * ph / pw)
        items = [img]
        if caption:
            items.append(Paragraph(caption, STY["small"]))
        items.append(Spacer(1, 6))
        return KeepTogether(items)

    def table(self, df: pd.DataFrame, col_widths: list[float] | None = None, max_rows: int = 40, fmt: dict | None = None):
        fmt = fmt or {}
        df = df.head(max_rows)
        data = [[Paragraph(f"<b>{c}</b>", STY["cell"]) for c in df.columns]]
        for _, r in df.iterrows():
            row = []
            for c in df.columns:
                v = r[c]
                if c in fmt:
                    v = fmt[c](v)
                elif isinstance(v, float):
                    v = f"{v:,.2f}"
                elif isinstance(v, (pd.Timestamp, datetime)):
                    v = v.strftime("%Y-%m-%d %H:%M")
                row.append(Paragraph(str(v), STY["cell"]))
            data.append(row)
        widths = _fit_headers([str(c) for c in df.columns], col_widths) if col_widths else None
        t = Table(data, colWidths=[w * cm for w in widths] if widths else None, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return t


CELL_PAD = 12  # points: reportlab's default left + right cell padding


def _fit_headers(headers: list[str], widths: list[float]) -> list[float]:
    """Widen columns whose header has a word longer than the column (it would be split mid-word) and take the
    space from the widest columns, so the table keeps its total width."""
    widths = list(widths[:len(headers)]) + [widths[-1]] * max(0, len(headers) - len(widths))
    need = [(max(stringWidth(w, "Helvetica-Bold", STY["cell"].fontSize) for w in h.split() or [""]) + CELL_PAD + 4) / cm
            for h in headers]
    extra = sum(max(0.0, n - w) for n, w in zip(need, widths))
    if extra <= 0:
        return widths
    out = [max(w, n) for w, n in zip(widths, need)]
    for _ in range(len(out)):  # take the extra from the columns with the most room above their own need
        if extra <= 1e-6:
            break
        i = max(range(len(out)), key=lambda k: out[k] - need[k])
        give = min(extra, out[i] - need[i])
        if give <= 0:
            break
        out[i] -= give
        extra -= give
    return out


def _footer(meta):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(INK2)
        canvas.drawString(1.6 * cm, 1.0 * cm, f"{meta.get('hostname', '?')} - {meta.get('bundle', '')} - pan-ngfw-load {__version__}")
        canvas.drawRightString(A4[0] - 1.6 * cm, 1.0 * cm, f"Page {doc.page}")
        canvas.restoreState()
    return draw


LEAD_STYLES = {"h1", "h2", "s"}  # headings and the small lead-in lines above tables


def _is_lead(f) -> bool:
    return isinstance(f, Paragraph) and f.style.name in LEAD_STYLES


def keep_leads_with_content(items: list) -> list:
    """Never leave a heading (or a lead-in line) alone at the bottom of a page: bind it, plus any
    paragraphs that follow it, to the next chart or table. Applies to every section."""
    out, i = [], 0
    while i < len(items):
        if not _is_lead(items[i]):
            out.append(items[i])
            i += 1
            continue
        group, j = [items[i]], i + 1
        while j < len(items) and isinstance(items[j], Paragraph):
            group.append(items[j])
            j += 1
        if j < len(items) and not isinstance(items[j], PageBreak):
            group.append(items[j])
            j += 1
        out.append(KeepTogether(group))
        i = j
    return out


def build_pdf(ctx: Ctx, sections: list, path: Path, title: str, layout_log: list | None = None) -> None:
    meta = ctx.ds.meta
    body = []
    for mod in sections:
        ctx._section = mod.TITLE
        try:
            flow = mod.build(ctx)
        except Exception as e:  # a broken section must not kill the report
            traceback.print_exc()
            ctx.find("warning", mod.TITLE, f"section failed: {type(e).__name__}: {e}")
            flow = [ctx.h1(mod.TITLE), ctx.p(f"<font color='#d03b3b'>Section failed: {type(e).__name__}: {e}</font>")]
        if flow:
            body.extend(flow)
            body.append(PageBreak())

    front = [
        Paragraph(title, STY["title"]),
        Paragraph(f"{meta.get('model', '?')} <b>{meta.get('hostname', '?')}</b> (SN {meta.get('serial', '?')}) - "
                  f"PAN-OS {meta.get('sw_version', '?')}", STY["subtitle"]),
        Paragraph((f"Live collection via XML API, latest sample {_fmt(meta.get('tsf_time'))}; "
                   if ctx.ds.source == "live" else
                   f"Tech support file {meta.get('bundle', '?')}, taken {_fmt(meta.get('tsf_time'))}; ") +
                  f"last boot {_fmt(meta.get('boot_time'))} (uptime {meta.get('uptime', '?')})", STY["subtitle"]),
        Paragraph(f"Report: <b>{ctx.settings.get('report_kind', 'standard')}</b>"
                  + (", with sub-interface detail" if ctx.settings.get("subinterfaces") else "")
                  + (" - run with --extended for drops/errors, interfaces, IPsec VPN and capacity"
                     if ctx.settings.get("report_kind") == "standard" else ""), STY["subtitle"]),
        Paragraph(f"Created with pan-ngfw-load {__version__} - an independent tool, not an official Palo Alto "
                  "Networks product (see the appendix).", STY["small"]),
        Spacer(1, 14), ctx.h1("Summary of findings"),
    ]
    order = {"warning": 0, "notice": 1, "info": 2}
    for level, sec, text in sorted(ctx.findings, key=lambda f: order.get(f[0], 3)):
        col = LEVEL_COL.get(level, "#52514e")
        front.append(Paragraph(f"<font color='{col}'><b>{level.upper()}</b></font> &nbsp;<i>{sec}</i> - {text}", STY["find"]))
    if ctx.ds.notes:
        front.append(Spacer(1, 6))
        for n in ctx.ds.notes:
            front.append(Paragraph(f"Note: {n}", STY["small"]))
    front.append(PageBreak())

    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=1.6 * cm, rightMargin=1.6 * cm,
                            topMargin=1.5 * cm, bottomMargin=1.6 * cm, title=title,
                            author="pan-ngfw-load", subject=meta.get("hostname", ""))
    if layout_log is not None:  # for tests: (page, kind, text) of every heading and image as placed
        def after(f):
            if isinstance(f, Paragraph) and f.style.name in ("h1", "h2"):
                layout_log.append((doc.page, f.style.name, f.getPlainText()[:60]))
            elif isinstance(f, Image):
                layout_log.append((doc.page, "img", Path(f.filename).stem))
            elif isinstance(f, Table):
                layout_log.append((doc.page, "table", ""))
        doc.afterFlowable = after
    doc.build(front + keep_leads_with_content(body), onFirstPage=_footer(meta), onLaterPages=_footer(meta))


def _fmt(v):
    return v.strftime("%Y-%m-%d %H:%M") if isinstance(v, (datetime, pd.Timestamp)) else str(v)
