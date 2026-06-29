from flask import Blueprint, render_template, g, abort
import db

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
def admin_dashboard():
    if not g.get("user") or not g.user.get("is_admin"):
        abort(403)

    conn = db.get_conn()

    active_users = conn.execute("""
SELECT COUNT(DISTINCT user_id)
FROM screening_logs
""").fetchone()[0]

returning_users = conn.execute("""
SELECT COUNT(*)
FROM (
    SELECT user_id
    FROM screening_logs
    GROUP BY user_id
    HAVING COUNT(*) > 1
)
""").fetchone()[0]
    total_screenings = conn.execute("SELECT COUNT(*) FROM screening_logs").fetchone()[0]
    
    active_subscriptions = conn.execute(
        "SELECT COUNT(*) FROM users WHERE subscription_status='active'"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "admin.html",
        active_users=active_users,
        returning_users=returning_users,

        total_screenings=total_screenings,
        
        active_subscriptions=active_subscriptions,
  )
