"""Top-level routes meant to be called by infrastructure, not by browsers:
the recurring watchlist-monitoring job. Kept separate from the watchlist
blueprint so its path isn't nested under /dashboard/watchlist."""

import os
import secrets as secrets_module

from flask import Blueprint, jsonify, request

from watchlist import run_watchlist_check

jobs_bp = Blueprint("jobs", __name__)


@jobs_bp.route("/jobs/run-watchlist-check", methods=["POST"])
def run_check_job():
    """Protected by a shared secret header, not a login session - this is
    meant to be called by an external cron trigger, e.g.:

        curl -X POST https://yourapp.com/jobs/run-watchlist-check \\
             -H "X-Cron-Secret: $CRON_SECRET"

    See README.md for free scheduling options (cron-job.org, GitHub Actions,
    or your hosting platform's native cron jobs).
    """
    expected_secret = os.environ.get("CRON_SECRET")
    if not expected_secret:
        return jsonify({"error": "CRON_SECRET is not configured on this deployment."}), 500
    provided_secret = request.headers.get("X-Cron-Secret", "")
    if not secrets_module.compare_digest(provided_secret, expected_secret):
        return jsonify({"error": "Invalid cron secret."}), 403

    summary = run_watchlist_check()
    return jsonify(summary)
