"""The report as one self-contained HTML file: the same content as the PDF (title, summary, sections, tables,
charts, appendix), continuous instead of paged. Charts are embedded as base64 PNG, the style sheet is inline - the
file needs nothing else to open."""

from __future__ import annotations

import base64
import html
import re
from pathlib import Path

from reportlab.platypus import Image, KeepTogether, Paragraph, Table

# paragraph style name -> HTML element (styles not listed: body text)
TAGS = {"t": "h1", "h1": "h2", "h1p": "h3", "part": "h2", "h2": "h3", "h2p": "h4", "h3": "h4",
        "st": "p.sub", "s": "p.small", "f": "p.find", "b": "p", "toct": None}

CSS = """
:root { --ink:#0b0b0b; --ink2:#52514e; --rule:#d8d7d2; --head:#eef3fb; --bg:#fcfcfb; --link:#2a78d6; }
@media (prefers-color-scheme: dark) {
  :root { --ink:#e8e7e3; --ink2:#a9a8a3; --rule:#3a3936; --head:#1f2a3a; --bg:#151514; --link:#6aa7f0; }
  img.chart { background:#fcfcfb; border-radius:4px; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 -apple-system, "Segoe UI", Helvetica, Arial,
       sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 26px; margin: 8px 0 4px; }
h2 { font-size: 21px; margin: 40px 0 8px; padding-top: 12px; border-top: 2px solid var(--rule); }
h3 { font-size: 17px; margin: 24px 0 6px; }
h4 { font-size: 15px; margin: 18px 0 4px; }
p { margin: 6px 0; max-width: 80ch; }
p.sub { color: var(--ink2); margin: 2px 0; }
p.small { color: var(--ink2); font-size: 13px; }
p.find { margin: 3px 0 3px 12px; max-width: none; }
a { color: var(--link); }
nav.toc { margin: 16px 0 8px; padding: 12px 16px; border: 1px solid var(--rule); border-radius: 6px; }
nav.toc ol { margin: 4px 0 0 18px; padding: 0; columns: 2 320px; }
nav.toc li { margin: 2px 0; }
.scroll { overflow-x: auto; margin: 6px 0 12px; }
table { border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; vertical-align: top; padding: 3px 8px; border-bottom: 1px solid var(--rule); }
th { background: var(--head); white-space: nowrap; }
td { white-space: normal; }
figure { margin: 10px 0 16px; }
img.chart { max-width: 100%; height: auto; display: block; }
figcaption { color: var(--ink2); font-size: 13px; margin-top: 4px; max-width: 80ch; }
footer { color: var(--ink2); font-size: 12px; margin-top: 48px; border-top: 1px solid var(--rule); padding-top: 8px; }
"""


def _markup(text: str) -> str:
    """reportlab paragraph markup -> HTML (font colour, links; b, i, br, sup, sub stay as they are)."""
    t = re.sub(r"<font\s+color=['\"]?([#\w]+)['\"]?\s*>", r'<span style="color:\1">', text or "")
    t = t.replace("</font>", "</span>")
    t = re.sub(r"<link\s+href=['\"]([^'\"]+)['\"][^>]*>", r'<a href="\1">', t).replace("</link>", "</a>")
    t = re.sub(r"<(/?)super>", r"<\1sup>", t)
    return re.sub(r"&(?!(?:[a-zA-Z]+|#\d+);)", "&amp;", t)  # a bare '&' in the text


class _Writer:
    def __init__(self):
        self.out: list[str] = []
        self.toc: list[tuple[str, str, int]] = []  # (anchor, text, level)
        self.n = 0

    def paragraph(self, p: Paragraph):
        tag = TAGS.get(p.style.name, "p")
        if tag is None:
            return
        body = _markup(p.text)
        if not re.sub(r"<[^>]+>|&nbsp;|\s", "", body):
            return
        if tag.startswith("h") and tag != "h1":
            self.n += 1
            anchor = f"s{self.n}"
            if tag in ("h2", "h3") and p.style.name in ("h1", "part", "h1p"):
                self.toc.append((anchor, re.sub(r"<[^>]+>", "", body).replace("&nbsp;", " "),
                                 0 if p.style.name in ("h1", "part") else 1))
            self.out.append(f'<{tag} id="{anchor}">{body}</{tag}>')
        elif "." in tag:
            el, cls = tag.split(".")
            self.out.append(f'<{el} class="{cls}">{body}</{el}>')
        else:
            self.out.append(f"<{tag}>{body}</{tag}>")

    def table(self, t: Table):
        rows = t._cellvalues
        if not rows:
            return
        cell = lambda c: _markup(c.text) if isinstance(c, Paragraph) else html.escape(str(c))
        head = "".join(f"<th>{cell(c)}</th>" for c in rows[0])
        body = "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in r) + "</tr>" for r in rows[1:])
        self.out.append(f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')

    def image(self, img: Image, caption: str = ""):
        data = base64.b64encode(Path(img.filename).read_bytes()).decode()
        alt = html.escape(Path(img.filename).stem.split("_", 1)[-1].replace("_", " "))
        cap = f"<figcaption>{caption}</figcaption>" if caption else ""
        self.out.append(f'<figure><img class="chart" alt="{alt}" src="data:image/png;base64,{data}">{cap}</figure>')

    def walk(self, items):
        for f in items:
            if isinstance(f, KeepTogether):
                content = list(f._content)
                imgs = [x for x in content if isinstance(x, Image)]
                if imgs and len(imgs) == 1:  # chart with its caption
                    caps = [_markup(x.text) for x in content if isinstance(x, Paragraph) and x.style.name == "s"]
                    rest = [x for x in content if not (isinstance(x, Image) or
                                                       (isinstance(x, Paragraph) and x.style.name == "s"))]
                    self.walk(rest)
                    self.image(imgs[0], " ".join(caps))
                else:
                    self.walk(content)
            elif isinstance(f, Paragraph):
                self.paragraph(f)
            elif isinstance(f, Table):
                self.table(f)
            elif isinstance(f, Image):
                self.image(f)
            # Spacer, PageBreak, TableOfContents: no meaning in a continuous page


def write(front: list, body: list, title: str, footer: str, path: Path) -> Path:
    """front: title page and summary flowables, body: the sections (as built for the PDF)."""
    w = _Writer()
    w.walk(front)
    head = w.out
    w.out = []
    w.walk(body)
    toc = "".join(
        f'<li><a href="#{a}">{html.escape(t)}</a></li>' if lvl == 0 else "" for a, t, lvl in w.toc
        if not t.startswith("Summary"))
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width, initial-scale=1">'
           f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body><main>"
           + "".join(head)
           + (f'<nav class="toc"><b>Contents</b><ol>{toc}</ol></nav>' if toc else "")
           + "".join(w.out)
           + f"<footer>{html.escape(footer)}</footer></main></body></html>")
    path.write_text(doc, encoding="utf-8")
    return path
