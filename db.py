"""Tiny sqlite3 data layer. Deliberately dependency-free (stdlib only) so the
whole app runs with nothing but `pip install flask` -- no ORM, no ODBC driver,
nothing that can fail to install on a constrained host.

Schema:
    users(id, email, password_hash, created_at,
          stripe_customer_id, stripe_subscription_id,
          subscription_status, screenings_used)
"""

import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.db"))

FREE_SCREENING_QUOTA = 10


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            subscription_status TEXT NOT NULL DEFAULT 'free',
            screenings_used INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS screening_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            query_name TEXT NOT NULL,
            match_count INTEGER NOT NULL DEFAULT 0,
            top_match_name TEXT,
            top_match_score REAL,
            top_match_source TEXT,
            risk_label TEXT,
            kind TEXT NOT NULL DEFAULT 'single',
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS watchlist_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            name TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            last_checked_at TEXT,
            last_match_names TEXT NOT NULL DEFAULT '[]'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS watchlist_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            watchlist_entry_id INTEGER NOT NULL REFERENCES watchlist_entries(id),
            watched_name TEXT NOT NULL,
            match_name TEXT NOT NULL,
            match_score REAL,
            match_source TEXT,
            created_at TEXT NOT NULL,
            emailed INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            key_hash TEXT UNIQUE NOT NULL,
            key_prefix TEXT NOT NULL,
            label TEXT,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0
        
    )
    conn.execute("""
    CREATE TABLE IF NOT EXISTS site_visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        page TEXT,
        user_agent TEXT,
        visited_at TEXT NOT NULL
    )
""")
    
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# User CRUD
# --------------------------------------------------------------------------

def create_user(email: str, password_hash: str) -> int:
    conn = get_conn()

    # أول مستخدم يصبح Admin، والبقية مستخدمون عاديون
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    is_admin = 1 if count == 0 else 0

    cur = conn.execute(
        "INSERT INTO users (email, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)",
        (
            email,
            password_hash,
            datetime.now(timezone.utc).isoformat(),
            is_admin,
        ),
    )

    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id
    


def get_user_by_id(user_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_stripe_customer_id(customer_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE stripe_customer_id = ?", (customer_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def increment_screenings_used(user_id: int) -> None:
    conn = get_conn()
    conn.execute("UPDATE users SET screenings_used = screenings_used + 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def set_subscription(user_id: int, *, customer_id: str = None, subscription_id: str = None, status: str = None) -> None:
    fields, values = [], []
    if customer_id is not None:
        fields.append("stripe_customer_id = ?")
        values.append(customer_id)
    if subscription_id is not None:
        fields.append("stripe_subscription_id = ?")
        values.append(subscription_id)
    if status is not None:
        fields.append("subscription_status = ?")
        values.append(status)
    if not fields:
        return
    values.append(user_id)
    conn = get_conn()
    conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()
    conn.close()


def set_subscription_status_by_customer(customer_id: str, status: str) -> None:
    conn = get_conn()
    conn.execute("UPDATE users SET subscription_status = ? WHERE stripe_customer_id = ?", (status, customer_id))
    conn.commit()
    conn.close()


def update_password(user_id: int, password_hash: str) -> None:
    conn = get_conn()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Password reset tokens
# --------------------------------------------------------------------------

def create_password_reset_token(user_id: int, token_hash: str, expires_at: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (user_id, token_hash, expires_at, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def get_valid_reset_token(token_hash: str):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used = 0 AND expires_at > ?",
        (token_hash, datetime.now(timezone.utc).isoformat()),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def mark_reset_token_used(token_id: int) -> None:
    conn = get_conn()
    conn.execute("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (token_id,))
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Screening history
# --------------------------------------------------------------------------

def log_screening(user_id: int, query_name: str, match_count: int, top_match: dict = None, kind: str = "single") -> None:
    conn = get_conn()
    conn.execute(
        """INSERT INTO screening_logs
           (user_id, query_name, match_count, top_match_name, top_match_score, top_match_source, risk_label, kind, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id, query_name, match_count,
            top_match.get("name") if top_match else None,
            top_match.get("score") if top_match else None,
            top_match.get("source") if top_match else None,
            top_match.get("risk") if top_match else ("LOW - no match" if match_count == 0 else None),
            kind,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def get_history(user_id: int, limit: int = 100):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM screening_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_history_entry(user_id: int, log_id: int):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM screening_logs WHERE id = ? AND user_id = ?", (log_id, user_id)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# --------------------------------------------------------------------------
# Watchlist monitoring
# --------------------------------------------------------------------------

def add_watchlist_entry(user_id: int, name: str, note: str = "") -> int:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO watchlist_entries (user_id, name, note, created_at) VALUES (?, ?, ?, ?)",
        (user_id, name, note, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    entry_id = cur.lastrowid
    conn.close()
    return entry_id


def get_watchlist_entries(user_id: int = None):
    conn = get_conn()
    if user_id is not None:
        rows = conn.execute(
            "SELECT * FROM watchlist_entries WHERE user_id = ? ORDER BY id DESC", (user_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM watchlist_entries ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_watchlist_entry(user_id: int, entry_id: int):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM watchlist_entries WHERE id = ? AND user_id = ?", (entry_id, user_id)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_watchlist_entry(user_id: int, entry_id: int) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM watchlist_entries WHERE id = ? AND user_id = ?", (entry_id, user_id))
    conn.commit()
    conn.close()


def update_watchlist_check(entry_id: int, last_match_names: str) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE watchlist_entries SET last_checked_at = ?, last_match_names = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), last_match_names, entry_id),
    )
    conn.commit()
    conn.close()


def create_watchlist_alert(user_id: int, entry_id: int, watched_name: str, match_name: str,
                            match_score: float, match_source: str, emailed: bool) -> None:
    conn = get_conn()
    conn.execute(
        """INSERT INTO watchlist_alerts
           (user_id, watchlist_entry_id, watched_name, match_name, match_score, match_source, created_at, emailed)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, entry_id, watched_name, match_name, match_score, match_source,
         datetime.now(timezone.utc).isoformat(), int(emailed)),
    )
    conn.commit()
    conn.close()


def get_watchlist_alerts(user_id: int, limit: int = 100):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM watchlist_alerts WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# API keys
# --------------------------------------------------------------------------

def create_api_key(user_id: int, key_hash: str, key_prefix: str, label: str = "") -> int:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO api_keys (user_id, key_hash, key_prefix, label, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, key_hash, key_prefix, label, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    key_id = cur.lastrowid
    conn.close()
    return key_id


def get_api_keys(user_id: int):
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, key_prefix, label, created_at, last_used_at, revoked FROM api_keys WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_api_key_by_hash(key_hash: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0", (key_hash,)).fetchone()
    conn.close()
    return dict(row) if row else None


def touch_api_key(key_id: int) -> None:
    conn = get_conn()
    conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), key_id))
    conn.commit()
    conn.close()


def revoke_api_key(user_id: int, key_id: int) -> None:
    conn = get_conn()
    conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?", (key_id, user_id))
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Derived properties (kept as plain functions since rows are plain dicts)
# --------------------------------------------------------------------------

def is_pro(user: dict) -> bool:
    return user["subscription_status"] == "active"


def remaining_free_screenings(user: dict) -> int:
    return max(0, FREE_SCREENING_QUOTA - user["screenings_used"])


def can_screen(user: dict) -> bool:
    return is_pro(user) or remaining_free_screenings(user) > 0


def can_batch_screen(user: dict) -> bool:
    return is_pro(user)
