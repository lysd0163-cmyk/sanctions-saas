"""Minimal Stripe API client using only the standard library.

Stripe's API is plain REST + form-encoding, so there's no need for the
`stripe` PyPI package just to create a Checkout Session or verify a webhook
signature. This keeps the app's only hard dependency as Flask itself.

Docs this follows:
- Checkout Sessions: https://docs.stripe.com/api/checkout/sessions/create
- Billing Portal:    https://docs.stripe.com/api/customer_portal/sessions/create
- Webhook signing:   https://docs.stripe.com/webhooks#verify-manually
"""

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

STRIPE_API_BASE = "https://api.stripe.com/v1"


class StripeError(Exception):
    pass


def _auth_header(secret_key: str) -> str:
    token = base64.b64encode(f"{secret_key}:".encode()).decode()
    return f"Basic {token}"


def _post(path: str, secret_key: str, params: dict) -> dict:
    url = f"{STRIPE_API_BASE}{path}"
    body = urllib.parse.urlencode(params, doseq=True).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", _auth_header(secret_key))
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()
        raise StripeError(f"Stripe API error ({e.code}): {detail}") from e
    except urllib.error.URLError as e:
        raise StripeError(f"Could not reach Stripe: {e}") from e


def create_checkout_session(secret_key: str, *, price_id: str, success_url: str,
                             cancel_url: str, client_reference_id: str,
                             customer_email: str = None, customer_id: str = None) -> dict:
    params = {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": 1,
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": client_reference_id,
    }
    if customer_id:
        params["customer"] = customer_id
    elif customer_email:
        params["customer_email"] = customer_email
    return _post("/checkout/sessions", secret_key, params)


def create_portal_session(secret_key: str, *, customer_id: str, return_url: str) -> dict:
    return _post("/billing_portal/sessions", secret_key, {"customer": customer_id, "return_url": return_url})


def verify_webhook_signature(payload: bytes, sig_header: str, webhook_secret: str, tolerance: int = 300) -> dict:
    """Verify a Stripe webhook signature and return the parsed event dict.
    Raises StripeError on any verification failure."""
    if not sig_header:
        raise StripeError("Missing Stripe-Signature header.")

    try:
        parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
    except ValueError:
        raise StripeError("Malformed Stripe-Signature header.")

    timestamp, signature = parts.get("t"), parts.get("v1")
    if not timestamp or not signature:
        raise StripeError("Malformed Stripe-Signature header.")

    signed_payload = f"{timestamp}.".encode() + payload
    expected_sig = hmac.new(webhook_secret.encode(), signed_payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        raise StripeError("Signature verification failed.")
    if abs(time.time() - int(timestamp)) > tolerance:
        raise StripeError("Webhook timestamp outside tolerance window.")

    return json.loads(payload.decode())
