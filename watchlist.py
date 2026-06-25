"""Continuous monitoring: a user adds names to a watchlist, and a recurring
job (triggered by an external cron, not an in-process scheduler - see
README.md) re-screens every entry and emails the owner only when a name
that WASN'T matched last time becomes matched this time (a genuinely new
hit), rather than re-alerting on the same match every single day.
"""

import json
import os

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for

import db
from auth_helpers import csrf_protect, login_required
from email_client import send_email
from sanctions_screener import screen_name
from screening_engine import get_entries

watchlist_bp = Blueprint("watchlist", __name__, url_prefix="/dashboard/watchlist")

WATCHLIST_MATCH_THRESHOLD = 85


@watchlist_bp.route("/")
@login_required
def index():
    if not db.is_pro(g.user):
        return render_template("watchlist.html", entries=[], alerts=[], locked=True)
    entries = db.get_watchlist_entries(g.user["id"])
    alerts = db.get_watchlist_alerts(g.user["id"], limit=25)
    return render_template("watchlist.html", entries=entries, alerts=alerts, locked=False)


@watchlist_bp.route("/add", methods=["POST"])
@login_required
@csrf_protect
def add():
    if not db.is_pro(g.user):
        flash("Watchlist monitoring is a Pro feature.", "error")
        return redirect(url_for("billing.pricing"))

    name = (request.form.get("name") or "").strip()
    note = (request.form.get("note") or "").strip()
    if not name:
        flash("Enter a name to monitor.", "error")
        return redirect(url_for("watchlist.index"))
    if len(name) > 200:
        flash("Name is too long (max 200 characters).", "error")
        return redirect(url_for("watchlist.index"))

    db.add_watchlist_entry(g.user["id"], name, note)
    flash(f'Now monitoring "{name}".', "success")
    return redirect(url_for("watchlist.index"))


@watchlist_bp.route("/<int:entry_id>/delete", methods=["POST"])
@login_required
@csrf_protect
def delete(entry_id):
    entry = db.get_watchlist_entry(g.user["id"], entry_id)
    if not entry:
        abort(404)
    db.delete_watchlist_entry(g.user["id"], entry_id)
    flash("Removed from watchlist.", "info")
    return redirect(url_for("watchlist.index"))


def run_watchlist_check() -> dict:
    """Re-screen every watchlist entry across all users. Returns a summary
    dict. Called by the protected /jobs/run-watchlist-check endpoint below,
    which an external cron service hits on a schedule."""
    entries = db.get_watchlist_entries()
    entries_loaded, used_demo_data = get_entries()

    checked = 0
    new_alerts = 0

    for entry in entries:
        checked += 1
        matches = screen_name(entry["name"], entries_loaded, WATCHLIST_MATCH_THRESHOLD)
        current_names = sorted({m["name"] for m in matches})

        try:
            previous_names = set(json.loads(entry["last_match_names"] or "[]"))
        except (json.JSONDecodeError, TypeError):
            previous_names = set()

        newly_appeared = [m for m in matches if m["name"] not in previous_names]

        for m in newly_appeared:
            user = db.get_user_by_id(entry["user_id"])
            emailed = False
            if user:
                emailed = send_email(
                    user["email"],
                    f'Sanctum alert: new sanctions match for "{entry["name"]}"',
                    f'A name on your watchlist now matches a sanctions list entry it did not match before:\n\n'
                    f'  Watched name: {entry["name"]}\n'
                    f'  New match:    {m["name"]} ({m["source"]}, score {m["match_score"]:.1f})\n\n'
                    f'Log in to review: {os.environ.get("APP_BASE_URL", "")}{url_for("watchlist.index")}\n\n'
                    f'Reminder: this requires human review, it is not an automatic determination.',
                )
            db.create_watchlist_alert(
                entry["user_id"], entry["id"], entry["name"], m["name"], m["match_score"], m["source"], emailed
            )
            new_alerts += 1

        db.update_watchlist_check(entry["id"], json.dumps(current_names))

    return {"entries_checked": checked, "new_alerts": new_alerts, "used_demo_data": used_demo_data}
