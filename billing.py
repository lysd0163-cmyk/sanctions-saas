import os

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for

import db
import stripe_client
from auth_helpers import csrf_protect, login_required

billing_bp = Blueprint("billing", __name__, url_prefix="/billing")

PRO_PRICE_USD = os.environ.get("PRO_PRICE_DISPLAY", "49")


def _stripe_configured() -> bool:
    return bool(os.environ.get("STRIPE_SECRET_KEY")) and bool(os.environ.get("STRIPE_PRICE_ID"))


@billing_bp.route("/pricing")
def pricing():
    return render_template("pricing.html", pro_price=PRO_PRICE_USD, stripe_configured=_stripe_configured())


@billing_bp.route("/checkout", methods=["POST"])
@login_required
@csrf_protect
def checkout():
    if not _stripe_configured():
        flash("Billing isn't configured yet on this deployment. Add your Stripe keys to enable upgrades.", "error")
        return redirect(url_for("billing.pricing"))

    user = g.user
    try:
        session_obj = stripe_client.create_checkout_session(
            os.environ["STRIPE_SECRET_KEY"],
            price_id=os.environ["STRIPE_PRICE_ID"],
            success_url=url_for("billing.success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("billing.pricing", _external=True),
            client_reference_id=str(user["id"]),
            customer_email=None if user["stripe_customer_id"] else user["email"],
            customer_id=user["stripe_customer_id"],
        )
        return redirect(session_obj["url"], code=303)
    except stripe_client.StripeError as e:
        current_app.logger.warning("Stripe checkout error: %s", e)
        flash("Could not reach the billing service right now. Please try again shortly.", "error")
        return redirect(url_for("billing.pricing"))


@billing_bp.route("/success")
@login_required
def success():
    flash("If your payment went through, your account will show Pro within a few seconds (webhook delivery).", "success")
    return redirect(url_for("screening.dashboard"))


@billing_bp.route("/portal", methods=["POST"])
@login_required
@csrf_protect
def portal():
    user = g.user
    if not _stripe_configured() or not user["stripe_customer_id"]:
        flash("No active billing account found yet.", "error")
        return redirect(url_for("billing.manage"))

    try:
        session_obj = stripe_client.create_portal_session(
            os.environ["STRIPE_SECRET_KEY"],
            customer_id=user["stripe_customer_id"],
            return_url=url_for("billing.manage", _external=True),
        )
        return redirect(session_obj["url"], code=303)
    except stripe_client.StripeError as e:
        current_app.logger.warning("Stripe portal error: %s", e)
        flash("Could not open the billing portal right now.", "error")
        return redirect(url_for("billing.manage"))


@billing_bp.route("/manage")
@login_required
def manage():
    return render_template("billing.html", free_quota=db.FREE_SCREENING_QUOTA)


@billing_bp.route("/webhook", methods=["POST"])
def webhook():
    """Called directly by Stripe's servers, never by a browser - verified via
    HMAC signature instead of a session/CSRF token."""
    if not _stripe_configured():
        return "billing not configured", 200

    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        current_app.logger.warning("Webhook received but STRIPE_WEBHOOK_SECRET is not set - rejecting.")
        return "webhook secret not configured", 500

    try:
        event = stripe_client.verify_webhook_signature(
            request.data, request.headers.get("Stripe-Signature", ""), webhook_secret
        )
    except stripe_client.StripeError as e:
        current_app.logger.warning("Webhook rejected: %s", e)
        return "invalid signature", 400

    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        user_id = data.get("client_reference_id")
        if user_id:
            db.set_subscription(
                int(user_id),
                customer_id=data.get("customer"),
                subscription_id=data.get("subscription"),
                status="active",
            )

    elif event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
        customer_id = data.get("customer")
        if customer_id:
            if event_type == "customer.subscription.deleted":
                db.set_subscription_status_by_customer(customer_id, "canceled")
            else:
                status = data.get("status")
                if status in ("active", "past_due", "canceled"):
                    db.set_subscription_status_by_customer(customer_id, status)

    return "ok", 200
