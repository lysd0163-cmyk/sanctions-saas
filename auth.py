import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import db
from auth_helpers import csrf_protect, login_required, login_user, logout_user
from email_client import send_email

auth_bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@auth_bp.route("/signup", methods=["GET", "POST"])
@csrf_protect
def signup():
    if g.get("user"):
        return redirect(url_for("screening.dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        error = None
        if not EMAIL_RE.match(email):
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif db.get_user_by_email(email):
            error = "An account with that email already exists."

        if error:
            flash(error, "error")
            return render_template("signup.html", email=email)

        user_id = db.create_user(email, generate_password_hash(password))
        login_user({"id": user_id})
        flash("Account created. Welcome.", "success")
        return redirect(url_for("screening.dashboard"))

    return render_template("signup.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@csrf_protect
def login():
    if g.get("user"):
        return redirect(url_for("screening.dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = db.get_user_by_email(email)

        if user and check_password_hash(user["password_hash"], password):
            login_user(user)
            next_url = request.args.get("next")
            return redirect(next_url or url_for("screening.dashboard"))

        flash("Incorrect email or password.", "error")
        return render_template("login.html", email=email)

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("landing.index"))


RESET_TOKEN_TTL_MINUTES = 30


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@csrf_protect
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = db.get_user_by_email(email)

        # Always show the same message whether or not the account exists,
        # so this can't be used to enumerate registered emails.
        if user:
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)).isoformat()
            db.create_password_reset_token(user["id"], token_hash, expires_at)

            reset_url = url_for("auth.reset_password", token=raw_token, _external=True)
            send_email(
                user["email"],
                "Reset your Sanctum password",
                f"Someone requested a password reset for this account.\n\n"
                f"Reset your password here (expires in {RESET_TOKEN_TTL_MINUTES} minutes):\n{reset_url}\n\n"
                f"If you didn't request this, you can ignore this email.",
            )

        flash("If that email has an account, a reset link has been sent.", "info")
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@csrf_protect
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    reset_row = db.get_valid_reset_token(token_hash)

    if not reset_row:
        flash("That reset link is invalid or has expired. Request a new one.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", token=token)

        db.update_password(reset_row["user_id"], generate_password_hash(password))
        db.mark_reset_token_used(reset_row["id"])
        flash("Password updated. You can log in now.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=token)
