from flask import Blueprint, render_template, g, abort
import db

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
def admin_dashboard():
    if not g.get("user") or not g.user.get("is_admin"):
        abort(403)

    conn = db.get_conn()

    # إجمالي المستخدمين المسجلين
    total_users = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    # إجمالي الزوار (عدد الجلسات أو الزيارات الفريدة إن وجد جدول visits)
    try:
        total_visits = conn.execute(
            "SELECT COUNT(*) FROM visits"
        ).fetchone()[0]
    except Exception:
        total_visits = "—"  # إذا لم يكن جدول visits موجوداً بعد

    # المستخدمون النشطون (لديهم فحص واحد على الأقل)
    active_users = conn.execute("""
        SELECT COUNT(DISTINCT user_id)
        FROM screening_logs
    """).fetchone()[0]

    # المستخدمون العائدون (أجروا أكثر من فحص واحد)
    returning_users = conn.execute("""
        SELECT COUNT(*)
        FROM (
            SELECT user_id
            FROM screening_logs
            GROUP BY user_id
            HAVING COUNT(*) > 1
        )
    """).fetchone()[0]

    # إجمالي الفحوصات
    total_screenings = conn.execute(
        "SELECT COUNT(*) FROM screening_logs"
    ).fetchone()[0]

    # الاشتراكات النشطة
    active_subscriptions = conn.execute(
        "SELECT COUNT(*) FROM users WHERE subscription_status='active'"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_visits=total_visits,
        active_users=active_users,
        returning_users=returning_users,
        total_screenings=total_screenings,
        active_subscriptions=active_subscriptions,
    )
