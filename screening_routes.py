import csv
import io
from datetime import datetime

from flask import Blueprint, abort, g, jsonify, render_template, request, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

import db
from auth_helpers import login_required
from sanctions_screener import risk_label, screen_name
from screening_engine import get_entries

screening_bp = Blueprint("screening", __name__)


@screening_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", free_quota=db.FREE_SCREENING_QUOTA)


@screening_bp.route("/api/screen", methods=["POST"])
@login_required
def api_screen():
    user = g.user
    if not db.can_screen(user):
        return jsonify({
            "error": "Free quota used up. Upgrade to Pro for unlimited screening.",
            "quota_exhausted": True,
        }), 402

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    try:
        threshold = int(data.get("threshold", 80))
    except (TypeError, ValueError):
        threshold = 80
    threshold = max(0, min(100, threshold))

    if not name:
        return jsonify({"error": "A name is required."}), 400
    if len(name) > 200:
        return jsonify({"error": "Name is too long (max 200 characters)."}), 400

    entries, used_demo_data = get_entries()
    matches = screen_name(name, entries, threshold)

    matches_payload = [
        {
            "name": m["name"], "score": m["match_score"], "source": m["source"],
            "risk": risk_label(m["match_score"]),
            "primary_name": m.get("primary_name"), "programs": m.get("programs"),
        }
        for m in matches[:25]
    ]

    db.log_screening(user["id"], name, len(matches), matches_payload[0] if matches_payload else None, kind="single")

    if not db.is_pro(user):
        db.increment_screenings_used(user["id"])
        user = db.get_user_by_id(user["id"])  # refresh for accurate remaining count

    return jsonify({
        "query": name,
        "threshold": threshold,
        "used_demo_data": used_demo_data,
        "match_count": len(matches),
        "matches": matches_payload,
        "is_pro": db.is_pro(user),
        "remaining_free_screenings": db.remaining_free_screenings(user),
    })


@screening_bp.route("/api/screen-batch", methods=["POST"])
@login_required
def api_screen_batch():
    user = g.user
    if not db.can_batch_screen(user):
        return jsonify({
            "error": "Batch screening is a Pro feature. Upgrade to screen a full CSV at once.",
            "requires_pro": True,
        }), 402

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    name_column = (request.form.get("name_column") or "name").strip()
    try:
        threshold = int(request.form.get("threshold", 80))
    except (TypeError, ValueError):
        threshold = 80
    threshold = max(0, min(100, threshold))

    try:
        raw = file.stream.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        return jsonify({"error": "Could not read file as UTF-8 CSV."}), 400

    reader = csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames or name_column not in reader.fieldnames:
        return jsonify({
            "error": f'Column "{name_column}" not found.',
            "available_columns": reader.fieldnames or [],
        }), 400

    entries, _ = get_entries()

    out_rows = []
    for row in reader:
        name = (row.get(name_column) or "").strip()
        matches = screen_name(name, entries, threshold) if name else []
        top = matches[0] if matches else None
        out_row = dict(row)
        out_row["screening_match_count"] = len(matches)
        out_row["top_match_name"] = top["name"] if top else ""
        out_row["top_match_score"] = top["match_score"] if top else ""
        out_row["top_match_source"] = top["source"] if top else ""
        out_row["risk_flag"] = risk_label(top["match_score"]) if top else "LOW - no match"
        out_rows.append(out_row)
        if len(out_rows) >= 5000:
            break

    if not out_rows:
        return jsonify({"error": "No rows found in the uploaded file."}), 400

    flagged = sum(1 for r in out_rows if r["screening_match_count"] > 0)
    db.log_screening(
        user["id"],
        f"Batch: {file.filename} ({len(out_rows)} rows, {flagged} flagged)",
        flagged,
        None,
        kind="batch",
    )

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(out_rows[0].keys()))
    writer.writeheader()
    writer.writerows(out_rows)

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="screening_results.csv")


@screening_bp.route("/api/status")
def api_status():
    entries, used_demo = get_entries()
    return jsonify({"loaded_entries": len(entries), "used_demo_data": used_demo})


@screening_bp.route("/dashboard/history")
@login_required
def history():
    rows = db.get_history(g.user["id"], limit=200)
    return render_template("history.html", rows=rows)


@screening_bp.route("/dashboard/history/export.csv")
@login_required
def history_export_csv():
    rows = db.get_history(g.user["id"], limit=5000)
    output = io.StringIO()
    fieldnames = ["created_at", "kind", "query_name", "match_count", "top_match_name", "top_match_score", "top_match_source", "risk_label"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="screening_history.csv")


def _build_report_pdf(entry: dict) -> io.BytesIO:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.85 * inch, bottomMargin=0.85 * inch,
                             leftMargin=0.9 * inch, rightMargin=0.9 * inch)
    styles = getSampleStyleSheet()
    brass = colors.HexColor("#8C7440")
    ink = colors.HexColor("#1B2A2F")
    muted = colors.HexColor("#6B6354")

    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], textColor=ink, fontSize=20, spaceAfter=4)
    eyebrow_style = ParagraphStyle("Eyebrow", parent=styles["Normal"], textColor=brass, fontSize=10,
                                    spaceAfter=18, fontName="Helvetica-Bold")
    body_style = ParagraphStyle("Body", parent=styles["Normal"], textColor=ink, fontSize=10.5, leading=15)
    muted_style = ParagraphStyle("Muted", parent=styles["Normal"], textColor=muted, fontSize=9, leading=13)
    section_style = ParagraphStyle("Section", parent=styles["Heading2"], textColor=ink, fontSize=12, spaceBefore=16, spaceAfter=8)

    flagged = entry["match_count"] and entry["match_count"] > 0
    verdict = "FLAGGED — REVIEW REQUIRED" if flagged else "NO MATCH FOUND"
    verdict_color = colors.HexColor("#7A3530") if flagged else colors.HexColor("#3D5A45")

    elements = [
        Paragraph("SANCTUM — SCREENING REPORT", eyebrow_style),
        Paragraph(entry["query_name"] if entry["kind"] == "single" else "Batch Screening Summary", title_style),
        Paragraph(f"Generated {datetime.now().strftime('%d %B %Y, %H:%M UTC')} · Record #{entry['id']}", muted_style),
        Spacer(1, 18),
    ]

    verdict_table = Table([[verdict]], colWidths=[6.2 * inch])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F5F2E9")),
        ("TEXTCOLOR", (0, 0), (-1, -1), verdict_color),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 13),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("BOX", (0, 0), (-1, -1), 1, verdict_color),
    ]))
    elements.append(verdict_table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Screening Details", section_style))
    detail_rows = [
        ["Screened name / file", entry["query_name"]],
        ["Type", "Single name" if entry["kind"] == "single" else "Batch (CSV)"],
        ["Matches found", str(entry["match_count"])],
    ]
    if entry.get("top_match_name"):
        detail_rows += [
            ["Top match", entry["top_match_name"]],
            ["Match score", f"{entry['top_match_score']:.1f} / 100" if entry.get("top_match_score") is not None else "—"],
            ["Source list", entry.get("top_match_source") or "—"],
            ["Risk level", entry.get("risk_label") or "—"],
        ]
    detail_table = Table(detail_rows, colWidths=[1.8 * inch, 4.4 * inch])
    detail_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), ink),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#D8D2C2")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(detail_table)
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("Sources Checked", section_style))
    elements.append(Paragraph(
        "OFAC Specially Designated Nationals (SDN) List · UN Security Council Consolidated List", body_style))

    elements.append(Paragraph("Notice", section_style))
    elements.append(Paragraph(
        "This report reflects a name-similarity screening only, as of the date above. "
        "A result of \"no match found\" is not a guarantee of compliance and does not replace "
        "date-of-birth, ID-document, or beneficial-ownership checks. This is not legal advice. "
        "Every flagged match requires human review before any business decision.",
        muted_style))

    doc.build(elements)
    buf.seek(0)
    return buf


@screening_bp.route("/dashboard/history/<int:log_id>/report.pdf")
@login_required
def history_report_pdf(log_id):
    entry = db.get_history_entry(g.user["id"], log_id)
    if not entry:
        abort(404)
    pdf_buf = _build_report_pdf(entry)
    return send_file(pdf_buf, mimetype="application/pdf", as_attachment=True,
                      download_name=f"sanctum-report-{log_id}.pdf")
