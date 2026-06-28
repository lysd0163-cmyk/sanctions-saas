from flask import Blueprint, jsonify, render_template, request, session
from db import log_site_visit
from sanctions_screener import risk_label, screen_name
from screening_engine import get_entries

landing_bp = Blueprint("landing", __name__)

ANONYMOUS_DEMO_LIMIT = 3


@landing_bp.route("/")
def index():
    log_site_visit(
    request.remote_addr,
    request.path,
    request.headers.get("User-Agent", "")
    )
    return render_template("landing.html")


@landing_bp.route("/api/demo-screen", methods=["POST"])
def demo_screen():
    """Limited, no-login screening endpoint for the hero widget on the public
    landing page, capped per browser session, so visitors can try the tool
    before creating an account."""
    used = session.get("demo_uses", 0)
    if used >= ANONYMOUS_DEMO_LIMIT:
        return jsonify({
            "error": f"Free preview limit reached ({ANONYMOUS_DEMO_LIMIT} checks). Create a free account to keep going.",
            "limit_reached": True,
        }), 403

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "A name is required."}), 400
    if len(name) > 200:
        return jsonify({"error": "Name is too long (max 200 characters)."}), 400

    session["demo_uses"] = used + 1

    entries, used_demo_data = get_entries()
    matches = screen_name(name, entries, 80)

    return jsonify({
        "query": name,
        "used_demo_data": used_demo_data,
        "match_count": len(matches),
        "matches": [
            {"name": m["name"], "score": m["match_score"], "source": m["source"], "risk": risk_label(m["match_score"])}
            for m in matches[:10]
        ],
        "checks_remaining": max(0, ANONYMOUS_DEMO_LIMIT - session["demo_uses"]),
    })
