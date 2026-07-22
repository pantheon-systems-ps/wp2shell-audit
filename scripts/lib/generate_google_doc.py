#!/usr/bin/env python3
"""Generate formatted Google Docs from markdown audit reports.

Uses the Google Docs API via gws CLI to create documents with Poppins
typography, dark purple table headers, health indicator cell coloring,
and footer. No cover page or logo — see the wp2shell-audit README for why.

Requires: gws CLI authenticated (gws auth login)

Usage:
    Single:  python3 generate_google_doc.py --input report.md [--title "Title"] [--folder ID]
    Batch:   python3 generate_google_doc.py --batch "output/content/*-audit-*.md" --folder ID
"""

import argparse
import datetime
import glob
import json
import os
import re
import subprocess
import sys

# ── Pantheon Brand Constants ─────────────────────────────────────────

FONT = "Poppins"

C_DARK      = {"red": 0.137, "green": 0.137, "blue": 0.176}   # #23232D
C_DARK_PURP = {"red": 0.188, "green": 0.090, "blue": 0.631}   # #3017A1
C_MED_PURP  = {"red": 0.373, "green": 0.255, "blue": 0.898}   # #5F41E5
C_LIGHT_BG  = {"red": 0.957, "green": 0.957, "blue": 0.988}   # #F4F4FC
C_PINK      = {"red": 0.871, "green": 0.0,   "blue": 0.576}   # #DE0093
C_GREEN     = {"red": 0.129, "green": 0.549, "blue": 0.373}   # #218C5F
C_YELLOW    = {"red": 1.0,   "green": 0.863, "blue": 0.157}   # #FFDC28
C_BLUE      = {"red": 0.059, "green": 0.384, "blue": 0.996}   # #0F62FE
C_MED_GRAY  = {"red": 0.875, "green": 0.875, "blue": 0.925}   # #DFDFEC
C_WHITE     = {"red": 1.0,   "green": 1.0,   "blue": 1.0}     # #FFFFFF
C_SUB_GRAY  = {"red": 0.427, "green": 0.427, "blue": 0.471}   # #6D6D78

HEADING_CFG = {
    1: {"size": 18, "before": 20, "after": 8},
    2: {"size": 14, "before": 16, "after": 6},
    3: {"size": 12, "before": 12, "after": 4},
    4: {"size": 11, "before": 10, "after": 4, "italic": True, "no_bold": True},
    5: {"size": 11, "before": 8, "after": 4, "italic": True, "no_bold": True},
    6: {"size": 11, "before": 8, "after": 4, "italic": True, "no_bold": True},
}
BODY_SIZE = 11
TABLE_SIZE = 9
TABLE_BORDER_WIDTH = 1.5


# ── GWS API Helpers ──────────────────────────────────────────────────

def gws(service, resource, method, params=None, body=None):
    """Run a gws CLI command and return parsed JSON."""
    cmd = ["gws", service, resource, method]
    if params:
        cmd.extend(["--params", json.dumps(params)])
    if body:
        cmd.extend(["--json", json.dumps(body)])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"gws {method} failed: {r.stderr.strip()}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}


def gws_upload(file_path, name, mime_type):
    """Upload a file to Google Drive and return parsed JSON."""
    cmd = [
        "gws", "drive", "files", "create",
        "--upload", file_path,
        "--json", json.dumps({"name": name, "mimeType": mime_type}),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"gws upload failed: {r.stderr.strip()}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}


def create_doc(title):
    resp = gws("docs", "documents", "create", body={"title": title})
    return resp["documentId"]


def batch_update(doc_id, requests):
    if not requests:
        return {"replies": []}
    return gws("docs", "documents", "batchUpdate",
               params={"documentId": doc_id},
               body={"requests": requests})


def get_doc(doc_id):
    return gws("docs", "documents", "get", params={"documentId": doc_id})


def move_to_folder(file_id, folder_id):
    gws("drive", "files", "update",
        params={"fileId": file_id, "addParents": folder_id})


# ── Markdown Parser ──────────────────────────────────────────────────

def utf16_len(s):
    """Length of a string in UTF-16 code units (Google Docs API uses UTF-16 positions)."""
    return sum(2 if ord(c) > 0xFFFF else 1 for c in s)


INLINE_RE = re.compile(
    r'\*\*\*(.+?)\*\*\*'       # group 1: bold+italic
    r'|\*\*(.+?)\*\*'          # group 2: bold
    r'|\*([^*\n]+?)\*'         # group 3: italic
    r'|`([^`\n]+?)`'           # group 4: code
    r'|\[([^\]]+)\]\(([^)]+)\)'  # group 5,6: link text, url
)


def parse_inline(text):
    runs = []
    last = 0
    for m in INLINE_RE.finditer(text):
        if m.start() > last:
            runs.append({"text": text[last:m.start()]})
        if m.group(1):
            runs.append({"text": m.group(1), "bold": True, "italic": True})
        elif m.group(2):
            runs.append({"text": m.group(2), "bold": True})
        elif m.group(3):
            runs.append({"text": m.group(3), "italic": True})
        elif m.group(4):
            runs.append({"text": m.group(4), "code": True})
        elif m.group(5):
            runs.append({"text": m.group(5), "link": m.group(6)})
        last = m.end()
    if last < len(text):
        runs.append({"text": text[last:]})
    return runs or [{"text": text}]


def _strip_markdown_wrapper(content):
    """If the entire document is wrapped in a ```markdown ... ``` fence
    (per the deep-dive report template), unwrap it so headings/tables
    inside aren't silently dropped by the code-fence consumer below.
    """
    stripped = content.strip()
    if not stripped.startswith("```markdown"):
        return content
    body = stripped[len("```markdown"):].lstrip("\n")
    if body.endswith("```"):
        body = body[:-3].rstrip()
    return body


def parse_markdown(content):
    content = _strip_markdown_wrapper(content)
    lines = content.split("\n")
    elements = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if re.match(r'^-{3,}\s*$', stripped):
            elements.append({"type": "hr"})
            i += 1
            continue

        if stripped.startswith("```"):
            lang = stripped[3:].strip().lower()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing ```
            if lang == "mermaid":
                pie_title = ""
                pie_slices = []
                for cl in code_lines:
                    cl = cl.strip()
                    tm = re.match(r'^pie\s+title\s+(.+)$', cl)
                    if tm:
                        pie_title = tm.group(1).strip()
                        continue
                    sm = re.match(r'^"([^"]+)"\s*:\s*(\d+(?:\.\d+)?)', cl)
                    if sm:
                        pie_slices.append((sm.group(1), float(sm.group(2))))
                if pie_slices:
                    elements.append({"type": "mermaid_pie", "title": pie_title, "slices": pie_slices})
            elif code_lines:
                elements.append({"type": "code", "lang": lang, "lines": code_lines})
            continue

        hm = re.match(r'^(#{1,6})\s+(.+)$', stripped)
        if hm:
            elements.append({
                "type": "heading",
                "level": len(hm.group(1)),
                "runs": parse_inline(hm.group(2).strip()),
            })
            i += 1
            continue

        if stripped.startswith("|"):
            tlines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                tlines.append(lines[i])
                i += 1
            if len(tlines) >= 2:
                headers = [parse_inline(c.strip()) for c in tlines[0].strip().strip("|").split("|")]
                rows = []
                for tl in tlines[2:]:
                    cells = [parse_inline(c.strip()) for c in tl.strip().strip("|").split("|")]
                    while len(cells) < len(headers):
                        cells.append([{"text": ""}])
                    rows.append(cells[:len(headers)])
                elements.append({"type": "table", "headers": headers, "rows": rows})
            continue

        if re.match(r'^[-*+]\s', stripped):
            items = []
            while i < len(lines) and re.match(r'^\s*[-*+]\s', lines[i]):
                txt = re.sub(r'^\s*[-*+]\s+', '', lines[i])
                items.append(parse_inline(txt.strip()))
                i += 1
            elements.append({"type": "bullets", "items": items})
            continue

        if re.match(r'^\d+\.\s', stripped):
            items = []
            while i < len(lines) and re.match(r'^\s*\d+\.\s', lines[i]):
                txt = re.sub(r'^\s*\d+\.\s+', '', lines[i])
                items.append(parse_inline(txt.strip()))
                i += 1
            elements.append({"type": "numbered", "items": items})
            continue

        para_lines = []
        while i < len(lines):
            l = lines[i].strip()
            if not l or l.startswith("#") or l.startswith("|") or re.match(r'^-{3,}$', l):
                break
            if re.match(r'^[-*+]\s', l) or re.match(r'^\d+\.\s', l):
                break
            para_lines.append(l)
            i += 1
        if para_lines:
            elements.append({"type": "para", "runs": parse_inline(" ".join(para_lines))})

    return elements


# ── Request Builders ─────────────────────────────────────────────────

def _loc(index, seg=None):
    loc = {"index": index}
    if seg:
        loc["segmentId"] = seg
    return loc


def _range(start, end, seg=None):
    r = {"startIndex": start, "endIndex": end}
    if seg:
        r["segmentId"] = seg
    return r


def rq_insert(index, text, seg=None):
    return {"insertText": {"location": _loc(index, seg), "text": text}}


def rq_text_style(start, end, font=None, size=None, bold=None, italic=None,
                  color=None, link=None, underline=None, seg=None, weight=None):
    ts, fields = {}, []
    if font:
        ts["weightedFontFamily"] = {"fontFamily": font, "weight": weight or 400}
        fields.append("weightedFontFamily")
    if size:
        ts["fontSize"] = {"magnitude": size, "unit": "PT"}
        fields.append("fontSize")
    if bold is not None:
        ts["bold"] = bold
        fields.append("bold")
    if italic is not None:
        ts["italic"] = italic
        fields.append("italic")
    if color:
        ts["foregroundColor"] = {"color": {"rgbColor": color}}
        fields.append("foregroundColor")
    if link:
        ts["link"] = {"url": link}
        fields.append("link")
    if underline is not None:
        ts["underline"] = underline
        fields.append("underline")
    return {"updateTextStyle": {
        "range": _range(start, end, seg), "textStyle": ts,
        "fields": ",".join(fields),
    }}


def rq_para_style(start, end, named=None, before=None, after=None,
                  border_bottom=None, border_top=None, alignment=None,
                  line_spacing=None, indent_start=None, seg=None):
    ps, fields = {}, []
    if named:
        ps["namedStyleType"] = named
        fields.append("namedStyleType")
    if before is not None:
        ps["spaceAbove"] = {"magnitude": before, "unit": "PT"}
        fields.append("spaceAbove")
    if after is not None:
        ps["spaceBelow"] = {"magnitude": after, "unit": "PT"}
        fields.append("spaceBelow")
    if indent_start is not None:
        ps["indentStart"] = {"magnitude": indent_start, "unit": "PT"}
        fields.append("indentStart")
    if border_bottom:
        ps["borderBottom"] = {
            "color": {"color": {"rgbColor": border_bottom}},
            "width": {"magnitude": 0.5, "unit": "PT"},
            "padding": {"magnitude": 4, "unit": "PT"},
            "dashStyle": "SOLID",
        }
        fields.append("borderBottom")
    if border_top:
        ps["borderTop"] = {
            "color": {"color": {"rgbColor": border_top}},
            "width": {"magnitude": 0.5, "unit": "PT"},
            "padding": {"magnitude": 4, "unit": "PT"},
            "dashStyle": "SOLID",
        }
        fields.append("borderTop")
    if alignment:
        ps["alignment"] = alignment
        fields.append("alignment")
    if line_spacing is not None:
        ps["lineSpacing"] = line_spacing
        fields.append("lineSpacing")
    return {"updateParagraphStyle": {
        "range": _range(start, end, seg), "paragraphStyle": ps,
        "fields": ",".join(fields),
    }}


def rq_table_cell_style(table_start, row, col, row_span=1, col_span=1,
                         bg_color=None, border_color=None, border_width=None):
    style, fields = {}, []
    if bg_color:
        style["backgroundColor"] = {"color": {"rgbColor": bg_color}}
        fields.append("backgroundColor")
    if border_color and border_width:
        border = {
            "color": {"color": {"rgbColor": border_color}},
            "width": {"magnitude": border_width, "unit": "PT"},
            "dashStyle": "SOLID",
        }
        for side in ["borderTop", "borderBottom", "borderLeft", "borderRight"]:
            style[side] = border
            fields.append(side)
    return {"updateTableCellStyle": {
        "tableRange": {
            "tableCellLocation": {
                "tableStartLocation": {"index": table_start},
                "rowIndex": row, "columnIndex": col,
            },
            "rowSpan": row_span, "columnSpan": col_span,
        },
        "tableCellStyle": style,
        "fields": ",".join(fields),
    }}



def delete_drive_file(file_id):
    if file_id:
        try:
            gws("drive", "files", "delete", params={"fileId": file_id})
        except Exception:
            pass


def upload_chart(png_path):
    """Upload a chart PNG to Drive and return (file_id, public_uri)."""
    resp = gws_upload(png_path, os.path.basename(png_path), "image/png")
    file_id = resp.get("id")
    if not file_id:
        return None, None
    gws("drive", "permissions", "create",
        params={"fileId": file_id},
        body={"role": "reader", "type": "anyone"})
    info = gws("drive", "files", "get",
               params={"fileId": file_id, "fields": "webContentLink"})
    return file_id, info.get("webContentLink")


def render_mermaid_pie(title, slices):
    """Render a mermaid pie chart to a temp PNG using matplotlib."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = [s[0] for s in slices]
    values = [s[1] for s in slices]
    total = sum(values)

    # Pantheon brand colors: HIGH=pink, MEDIUM=yellow, LOW=purple, extras=blue/green
    colors = ["#DE0093", "#FFDC28", "#5F41E5", "#0F62FE", "#218C5F"]

    fig, ax = plt.subplots(figsize=(7, 3.5))
    fig.patch.set_facecolor("white")

    wedges, _ = ax.pie(
        values,
        labels=None,
        colors=colors[: len(slices)],
        startangle=90,
        wedgeprops={"linewidth": 2, "edgecolor": "white"},
    )

    ax.set_title(title, fontsize=11, fontweight="bold", color="#23232D", pad=12)

    legend_labels = [
        f"{lbl}  ({int(v)}, {v / total * 100:.0f}%)"
        for lbl, v in zip(labels, values)
    ]
    ax.legend(
        wedges, legend_labels,
        loc="center left", bbox_to_anchor=(1.0, 0.5),
        fontsize=9, frameon=False,
    )

    plt.tight_layout()
    tmp_path = os.path.join(os.getcwd(), f".tmp-chart-{os.getpid()}.png")
    plt.savefig(tmp_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return tmp_path



# ── Document Builder ─────────────────────────────────────────────────

def build_document(doc_id, elements):

    # Phase 1: Margins + create header/footer
    resp = batch_update(doc_id, [
        {"updateDocumentStyle": {
            "documentStyle": {
                "marginTop": {"magnitude": 72, "unit": "PT"},
                "marginBottom": {"magnitude": 72, "unit": "PT"},
                "marginLeft": {"magnitude": 90, "unit": "PT"},
                "marginRight": {"magnitude": 90, "unit": "PT"},
                "pageSize": {
                    "width": {"magnitude": 612, "unit": "PT"},
                    "height": {"magnitude": 792, "unit": "PT"},
                },
            },
            "fields": "marginTop,marginBottom,marginLeft,marginRight,pageSize",
        }},
        {"createHeader": {"type": "DEFAULT", "sectionBreakLocation": {"index": 0}}},
        {"createFooter": {"type": "DEFAULT", "sectionBreakLocation": {"index": 0}}},
    ])
    header_id = resp["replies"][1]["createHeader"]["headerId"]
    footer_id = resp["replies"][2]["createFooter"]["footerId"]

    batch_update(doc_id, [{"updateNamedStyle": {
        "namedStyle": {
            "namedStyleType": "TITLE",
            "paragraphStyle": {"lineSpacing": 100},
        },
        "fields": "namedStyleType,paragraphStyle.lineSpacing",
    }}])

    # No cover page — body content starts at the very beginning of the doc.
    insert_offset = 1

    # Phase 2: Build text content
    segments = []
    table_slots = []
    chart_slots = []
    heading_texts = {}

    for el in elements:
        t = el["type"]
        if t == "heading":
            text = "".join(r["text"] for r in el["runs"]) + "\n"
            heading_texts[text.strip()] = el["level"]
            segments.append((text, {"heading": el["level"], "runs": el["runs"]}))
        elif t == "para":
            for run in el["runs"]:
                segments.append((run["text"], {"run": run}))
            segments.append(("\n", {}))
        elif t == "bullets":
            for item_runs in el["items"]:
                for run in item_runs:
                    segments.append((run["text"], {"run": run, "list": "bullet"}))
                segments.append(("\n", {"list": "bullet"}))
        elif t == "numbered":
            for item_runs in el["items"]:
                for run in item_runs:
                    segments.append((run["text"], {"run": run, "list": "number"}))
                segments.append(("\n", {"list": "number"}))
        elif t == "table":
            if segments and segments[-1] == ("\n", {}):
                offset = sum(len(s[0]) for s in segments) - 1
                segments[-1] = ("\n", {"placeholder": True})
            else:
                offset = sum(len(s[0]) for s in segments)
                segments.append(("\n", {"placeholder": True}))
            table_slots.append((offset, el))
        elif t == "mermaid_pie":
            if segments and segments[-1] == ("\n", {}):
                offset = sum(len(s[0]) for s in segments) - 1
                segments[-1] = ("\n", {"placeholder": True})
            else:
                offset = sum(len(s[0]) for s in segments)
                segments.append(("\n", {"placeholder": True}))
            chart_slots.append((offset, el))
        elif t == "code":
            for code_line in el["lines"]:
                if code_line:
                    segments.append((code_line, {"run": {"text": code_line, "code": True}, "code_block": True}))
                segments.append(("\n", {"code_block": True}))
        elif t == "hr":
            segments.append(("\n", {}))

    full_text = "".join(s[0] for s in segments)
    if not full_text.strip():
        return

    # Phase 3: Insert body text + styling
    reqs = [rq_insert(insert_offset, full_text)]

    body_end = insert_offset + utf16_len(full_text)
    reqs.append(rq_text_style(insert_offset, body_end, font=FONT, size=BODY_SIZE, color=C_DARK))
    reqs.append(rq_para_style(insert_offset, body_end, line_spacing=100, after=6))

    idx = insert_offset
    bullet_ranges = []
    number_ranges = []
    code_block_ranges = []

    for text, meta in segments:
        end = idx + utf16_len(text)
        if not meta or meta.get("placeholder"):
            idx = end
            continue

        if "heading" in meta:
            lv = meta["heading"]
            cfg = HEADING_CFG[lv]
            is_h4 = cfg.get("no_bold", False)
            reqs.append(rq_para_style(idx, end,
                named=f"HEADING_{lv}", before=cfg["before"], after=cfg["after"]))
            reqs.append(rq_text_style(idx, end,
                font=FONT, size=cfg["size"],
                bold=not is_h4,
                italic=cfg.get("italic", False),
                color=C_DARK, weight=600 if not is_h4 else 400))
            ri = idx
            for run in meta.get("runs", []):
                re2 = ri + len(run["text"])
                if run.get("italic"):
                    reqs.append(rq_text_style(ri, re2, italic=True))
                if run.get("code"):
                    reqs.append(rq_text_style(ri, re2, font="Courier New"))
                ri = re2

        elif "run" in meta:
            run = meta["run"]
            if run.get("bold"):
                reqs.append(rq_text_style(idx, end, bold=True))
            if run.get("italic"):
                reqs.append(rq_text_style(idx, end, italic=True))
            if run.get("code"):
                reqs.append(rq_text_style(idx, end, font="Courier New", size=BODY_SIZE - 1))
            if run.get("link"):
                reqs.append(rq_text_style(idx, end, color=C_BLUE, underline=True, link=run["link"]))

        if meta.get("list") == "bullet":
            if not bullet_ranges or bullet_ranges[-1][1] != idx:
                bullet_ranges.append([idx, end])
            else:
                bullet_ranges[-1][1] = end
        elif meta.get("list") == "number":
            if not number_ranges or number_ranges[-1][1] != idx:
                number_ranges.append([idx, end])
            else:
                number_ranges[-1][1] = end
        elif meta.get("code_block"):
            if not code_block_ranges or code_block_ranges[-1][1] != idx:
                code_block_ranges.append([idx, end])
            else:
                code_block_ranges[-1][1] = end

        idx = end

    for s, e in bullet_ranges:
        reqs.append({"createParagraphBullets": {
            "range": _range(s, e), "bulletPreset": "BULLET_DISC_CIRCLE_SQUARE"}})
    for s, e in number_ranges:
        reqs.append({"createParagraphBullets": {
            "range": _range(s, e), "bulletPreset": "NUMBERED_DECIMAL_ALPHA_ROMAN"}})
    for s, e in code_block_ranges:
        reqs.append(rq_para_style(s, e,
            before=4, after=4, line_spacing=100, indent_start=18))

    batch_update(doc_id, reqs)

    # Phase 4: Footer
    year = datetime.date.today().year
    footer_text = f"\u00a9 {year} Pantheon Systems, Inc."
    batch_update(doc_id, [
        rq_insert(0, footer_text, seg=footer_id),
        rq_text_style(0, utf16_len(footer_text), font=FONT, size=8,
                      color=C_SUB_GRAY, seg=footer_id),
        rq_para_style(0, utf16_len(footer_text) + 1, alignment="END",
                      border_top=C_MED_GRAY, seg=footer_id),
    ])

    # Phase 4b: Insert chart images (reverse order; each is net-zero on indices)
    for char_offset, cel in sorted(chart_slots, key=lambda x: x[0], reverse=True):
        abs_idx = insert_offset + char_offset
        png_path = render_mermaid_pie(cel["title"], cel["slices"])
        chart_file_id = None
        try:
            chart_file_id, chart_uri = upload_chart(png_path)
            if chart_uri:
                batch_update(doc_id, [
                    {"deleteContentRange": {"range": _range(abs_idx, abs_idx + 1)}},
                    {"insertInlineImage": {
                        "location": _loc(abs_idx),
                        "uri": chart_uri,
                        "objectSize": {"width": {"magnitude": 400, "unit": "PT"}},
                    }},
                ])
        finally:
            if chart_file_id:
                delete_drive_file(chart_file_id)
            if os.path.exists(png_path):
                os.remove(png_path)

    # Phase 5: Insert tables (reverse order so indices stay valid)
    if table_slots:
        treqs = []
        for char_offset, tel in reversed(table_slots):
            abs_idx = insert_offset + char_offset
            nrows = 1 + len(tel["rows"])
            ncols = len(tel["headers"])
            treqs.append({"deleteContentRange": {"range": _range(abs_idx, abs_idx + 1)}})
            treqs.append({"insertTable": {
                "rows": nrows, "columns": ncols,
                "location": _loc(abs_idx),
            }})
        batch_update(doc_id, treqs)

        # Phase 6: Populate tables with branded styling
        data_tables = [t[1] for t in table_slots]

        for tbl_idx in range(len(data_tables) - 1, -1, -1):
            doc = get_doc(doc_id)
            body_tables = [el for el in doc["body"]["content"] if "table" in el]
            if tbl_idx >= len(body_tables):
                continue

            dtbl = body_tables[tbl_idx]
            data = data_tables[tbl_idx]
            table_start = dtbl["startIndex"]
            all_data = [data["headers"]] + data["rows"]
            trows = dtbl["table"]["tableRows"]
            ncols = len(data["headers"])

            creqs = []

            # Cell text (reverse order to avoid index shifting)
            for ri in range(len(trows) - 1, -1, -1):
                if ri >= len(all_data):
                    continue
                cells = trows[ri]["tableCells"]
                for ci in range(len(cells) - 1, -1, -1):
                    if ci >= len(all_data[ri]):
                        continue
                    cell_runs = all_data[ri][ci]  # list of run dicts
                    cell_text = "".join(r["text"] for r in cell_runs)
                    if not cell_text:
                        continue
                    cs = cells[ci]["content"][0]["startIndex"]
                    creqs.append(rq_insert(cs, cell_text))
                    is_header = (ri == 0)
                    creqs.append(rq_text_style(cs, cs + utf16_len(cell_text),
                        font=FONT, size=TABLE_SIZE,
                        color=C_WHITE if is_header else C_DARK,
                        bold=is_header, weight=700 if is_header else 400))
                    # Apply per-run inline styles (links, bold, italic)
                    run_cursor = cs
                    for run in cell_runs:
                        run_end = run_cursor + utf16_len(run["text"])
                        if run.get("link"):
                            creqs.append(rq_text_style(run_cursor, run_end,
                                color=C_BLUE, underline=True, link=run["link"]))
                        elif not is_header and run.get("bold"):
                            creqs.append(rq_text_style(run_cursor, run_end, bold=True))
                        elif not is_header and run.get("italic"):
                            creqs.append(rq_text_style(run_cursor, run_end, italic=True))
                        run_cursor = run_end

            # Row styling: dark purple header, light gray body, white borders
            creqs.insert(0, rq_table_cell_style(table_start, 0, 0,
                row_span=1, col_span=ncols,
                bg_color=C_DARK_PURP,
                border_color=C_WHITE, border_width=TABLE_BORDER_WIDTH))
            for ri in range(1, len(trows)):
                creqs.insert(0, rq_table_cell_style(table_start, ri, 0,
                    row_span=1, col_span=ncols,
                    bg_color=C_LIGHT_BG,
                    border_color=C_WHITE, border_width=TABLE_BORDER_WIDTH))

            # Pin header row so it repeats across page breaks
            creqs.append({"pinTableHeaderRows": {
                "tableStartLocation": {"index": table_start},
                "pinnedHeaderRowsCount": 1,
            }})

            if creqs:
                batch_update(doc_id, creqs)

    # Phase 7: Health indicator cell coloring
    colorize_health_indicators(doc_id)

    # Phase 8: Fix heading styles lost during table insertion
    fix_heading_styles(doc_id, heading_texts)

    # Phase 9: Add spacing after tables
    add_table_spacing(doc_id)


def fix_heading_styles(doc_id, heading_texts):
    """Re-apply explicit text formatting to all headings.

    Phase 3 applies heading styles, but table insertion can cause the explicit
    text style (Poppins, specific size) to be lost while the namedStyleType
    survives. This pass re-applies text formatting to every HEADING_X paragraph
    and also promotes any NORMAL_TEXT paragraph whose content matches a heading.
    """
    doc = get_doc(doc_id)
    reqs = []
    for el in doc["body"]["content"]:
        if "paragraph" not in el:
            continue
        para = el["paragraph"]
        style_type = para.get("paragraphStyle", {}).get("namedStyleType", "NORMAL_TEXT")
        start, end = el["startIndex"], el["endIndex"]

        if style_type.startswith("HEADING_"):
            # Re-apply explicit text formatting to every already-HEADING paragraph
            # to ensure named-style inheritance didn't override our Poppins styling.
            try:
                lv = int(style_type.split("_")[1])
            except (IndexError, ValueError):
                continue
            if lv not in HEADING_CFG:
                continue
            cfg = HEADING_CFG[lv]
            is_h4 = cfg.get("no_bold", False)
            reqs.append(rq_para_style(start, end,
                named=f"HEADING_{lv}", before=cfg["before"], after=cfg["after"]))
            reqs.append(rq_text_style(start, end,
                font=FONT, size=cfg["size"],
                bold=not is_h4,
                italic=cfg.get("italic", False),
                color=C_DARK, weight=600 if not is_h4 else 400))
        else:
            # Check if a NORMAL_TEXT paragraph should be a heading (lost its style)
            para_text = ""
            for pe in para.get("elements", []):
                tr = pe.get("textRun")
                if tr:
                    para_text += tr.get("content", "")
            para_text = para_text.strip()
            if para_text in heading_texts:
                lv = heading_texts[para_text]
                cfg = HEADING_CFG[lv]
                is_h4 = cfg.get("no_bold", False)
                reqs.append(rq_para_style(start, end,
                    named=f"HEADING_{lv}", before=cfg["before"], after=cfg["after"]))
                reqs.append(rq_text_style(start, end,
                    font=FONT, size=cfg["size"],
                    bold=not is_h4,
                    italic=cfg.get("italic", False),
                    color=C_DARK, weight=600 if not is_h4 else 400))
    if reqs:
        batch_update(doc_id, reqs)


def add_table_spacing(doc_id):
    doc = get_doc(doc_id)
    reqs = []
    content = doc["body"]["content"]
    for i, el in enumerate(content):
        if "table" in el and i + 1 < len(content):
            next_el = content[i + 1]
            if "paragraph" in next_el:
                named = next_el["paragraph"].get("paragraphStyle", {}).get("namedStyleType", "")
                if not named.startswith("HEADING"):
                    start = next_el["startIndex"]
                    end = next_el["endIndex"]
                    reqs.append(rq_para_style(start, end, before=10))
    if reqs:
        batch_update(doc_id, reqs)


def colorize_health_indicators(doc_id):
    doc = get_doc(doc_id)
    reqs = []
    indicators = {
        "🟢": (C_GREEN, C_WHITE),
        "🟡": (C_YELLOW, C_DARK),
        "🔴": (C_PINK, C_WHITE),
        "Green": (C_GREEN, C_WHITE),
        "Yellow": (C_YELLOW, C_DARK),
        "Red": (C_PINK, C_WHITE),
    }

    for el in doc["body"]["content"]:
        if "table" not in el:
            continue
        table_start = el["startIndex"]
        for ri, row in enumerate(el["table"]["tableRows"]):
            for ci, cell in enumerate(row["tableCells"]):
                cell_text = ""
                for content_el in cell["content"]:
                    if "paragraph" in content_el:
                        for pe in content_el["paragraph"].get("elements", []):
                            tr = pe.get("textRun")
                            if tr:
                                cell_text += tr.get("content", "")
                cell_text = cell_text.strip()

                for keyword, (bg_color, txt_color) in indicators.items():
                    if re.match(rf'{re.escape(keyword)}(?!\w)', cell_text):
                        reqs.append(rq_table_cell_style(
                            table_start, ri, ci, bg_color=bg_color))
                        for content_el in cell["content"]:
                            if "paragraph" in content_el:
                                for pe in content_el["paragraph"].get("elements", []):
                                    tr = pe.get("textRun")
                                    if tr and tr.get("content", "").strip():
                                        reqs.append(rq_text_style(
                                            pe["startIndex"], pe["endIndex"],
                                            color=txt_color, bold=True))
                        break

    if reqs:
        batch_update(doc_id, reqs)


# ── Main ─────────────────────────────────────────────────────────────

def extract_title(content):
    m = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    return m.group(1).strip() if m else "Untitled Report"


def process_file(path, title=None, folder_id=None):
    with open(path) as f:
        content = f.read()

    doc_title = title or extract_title(content)
    print(f"Creating: {doc_title}")

    doc_id = create_doc(doc_title)
    elements = parse_markdown(content)
    build_document(doc_id, elements)

    if folder_id:
        move_to_folder(doc_id, folder_id)

    # No default sharing — doc is private to its creator until they share it.
    url = f"https://docs.google.com/document/d/{doc_id}/edit"
    print(f"  Done: {url}")
    return doc_id, url


def main():
    ap = argparse.ArgumentParser(description="Generate formatted Google Docs")
    ap.add_argument("--input", help="Markdown file path")
    ap.add_argument("--title", help="Document title (default: from H1)")
    ap.add_argument("--folder", help="Google Drive folder ID")
    ap.add_argument("--batch", help="Glob pattern for batch mode")
    ap.add_argument("--delete-after", action="store_true",
                    help="Delete the source markdown file after successful doc creation")
    args = ap.parse_args()

    if not args.input and not args.batch:
        ap.error("--input or --batch required")

    if args.input:
        _, url = process_file(args.input, args.title, args.folder)
        print(f"\nDocument: {url}")
        if args.delete_after:
            os.remove(args.input)
    elif args.batch:
        files = sorted(glob.glob(args.batch))
        if not files:
            print(f"No files match: {args.batch}", file=sys.stderr)
            sys.exit(1)
        print(f"Processing {len(files)} files...")
        results = []
        for f in files:
            try:
                doc_id, url = process_file(f, folder_id=args.folder)
                results.append((os.path.basename(f), url))
                if args.delete_after:
                    os.remove(f)
            except Exception as e:
                print(f"  FAILED {os.path.basename(f)}: {e}", file=sys.stderr)
                results.append((os.path.basename(f), "FAILED"))
        ok = len([r for r in results if r[1] != "FAILED"])
        print(f"\n=== {ok}/{len(results)} complete ===")
        for name, url in results:
            print(f"  {name}: {url}")


if __name__ == "__main__":
    main()
