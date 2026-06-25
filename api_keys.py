"""Developer API keys: a Pro-only feature letting customers integrate
screening into their own systems. Keys are stored as a salted hash only
(never the raw key) - the raw key is shown exactly once, at creation time.
"""

import hashlib
import secrets

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for

import db
from auth_helpers import csrf_protect, login_required
from sanctions_screener import risk_label, screen_name
from screening_engine import get_entries

api_keys_bp = Blueprint("api_keys", __name__, url_prefix="/dashboard/api-keys")
public_api_bp = Blueprint("public_api", __name__, url_prefix="/v1")


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


@api_keys_bp.route("/")
@login_required
def index():
    if not db.is_pro(g.user):
        return render_template("api_keys.html", keys=[], locked=True, new_key=None)
    keys = db.get_api_keys(g.user["id"])
    return render_template("api_keys.html", keys=keys, locked=False, new_key=None)


@api_keys_bp.route("/create", methods=["POST"])
@login_required
@csrf_protect
def create():
    if not db.is_pro(g.user):
        flash("API access is a Pro feature.", "error")
        return redirect(url_for("billing.pricing"))

    label = (request.form.get("label") or "").strip() or "Unnamed key"
    raw_key = "sk_live_" + secrets.token_urlsafe(32)
    key_hash = _hash_key(raw_key)
    key_prefix = raw_key[:16]

    db.create_api_key(g.user["id"], key_hash, key_prefix, label)
    keys = db.get_api_keys(g.user["id"])
    return render_template("api_keys.html", keys=keys, locked=False, new_key=raw_key)


@api_keys_bp.route("/<int:key_id>/revoke", methods=["POST"])
@login_required
@csrf_protect
def revoke(key_id):
    db.revoke_api_key(g.user["id"], key_id)
    flash("API key revoked.", "info")
    return redirect(url_for("api_keys.index"))


# --------------------------------------------------------------------------
# Public developer API - authenticated with an API key, not a session cookie
# --------------------------------------------------------------------------

def _authenticate_api_key():
    """Returns the owning user dict, or None (and the response to return) on failure."""
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")

    raw_key = api_key_header
    if not raw_key and auth_header.startswith("Bearer "):
        raw_key = auth_header[len("Bearer "):]

    if not raw_key:
        return None

    key_row = db.get_api_key_by_hash(_hash_key(raw_key))
    if not key_row:
        return None

    user = db.get_user_by_id(key_row["user_id"])
    if not user or not db.is_pro(user):
        return None

    db.touch_api_key(key_row["id"])
    return user


@public_api_bp.route("/screen", methods=["POST"])
def v1_screen():
    user = _authenticate_api_key()
    if not user:
        return jsonify({"error": "Invalid, missing, or non-Pro API key."}), 401

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    threshold = max(0, min(100, int(data.get("threshold", 80) or 80)))

    if not name:
        return jsonify({"error": "A name is required."}), 400
    if len(name) > 200:
        return jsonify({"error": "Name is too long (max 200 characters)."}), 400

    entries, used_demo_data = get_entries()
    matches = screen_name(name, entries, threshold)
    matches_payload = [
        {"name": m["name"], "score": m["match_score"], "source": m["source"], "risk": risk_label(m["match_score"])}
        for m in matches[:25]
    ]
    db.log_screening(user["id"], name, len(matches), matches_payload[0] if matches_payload else None, kind="api")

    return jsonify({
        "query": name, "threshold": threshold, "used_demo_data": used_demo_data,
        "match_count": len(matches), "matches": matches_payload,
    })
