"""Lightweight, dependency-free auth helpers.

Login state lives in Flask's signed session cookie (signed with SECRET_KEY,
tamper-evident by default - this is the same mechanism Flask-Login itself
builds on, just without the extra package). CSRF protection is a standard
double-submit-style token stored in the session and checked on sensitive
POST forms.
"""

import secrets
from functools import wraps

from flask import g, redirect, request, session, url_for

import db


def load_logged_in_user() -> None:
    """Call once per request (from a before_request hook) to populate g.user."""
    user_id = session.get("user_id")
    g.user = db.get_user_by_id(user_id) if user_id else None


def login_user(user: dict) -> None:
    session.clear()
    session["user_id"] = user["id"]


def logout_user() -> None:
    session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            submitted = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not secrets.compare_digest(submitted, expected):
                return "Invalid or missing security token. Please refresh the page and try again.", 400
        return view(*args, **kwargs)
    return wrapped
