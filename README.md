# Sanctum — Sanctions Screening SaaS

A complete, deployable SaaS product: accounts, subscriptions, billing,
screening history with PDF reports, continuous watchlist monitoring with
email alerts, and a developer API. Built with zero hard dependencies
beyond Flask itself — everything else (auth, sessions, CSRF, the database,
even the Stripe and email integrations) is plain Python standard library,
so there's nothing exotic that can fail to install on a constrained host.

## What's actually in it

| Feature | Status |
|---|---|
| Sign up / log in / log out | ✅ session-based, CSRF-protected |
| Forgot / reset password | ✅ token-based, 30-min expiry, single-use |
| Free tier (10 lifetime screenings) + Pro tier (unlimited + batch) | ✅ enforced server-side |
| Stripe subscriptions (Checkout + Billing Portal + webhook) | ✅ graceful "not configured" fallback if you haven't added keys yet |
| Screening history + CSV export | ✅ |
| Per-screening PDF report ("Sanctum — Screening Report") | ✅ |
| Watchlist monitoring with new-match email alerts | ✅ only alerts on *genuinely new* matches, not every day |
| Developer API (`/v1/screen`) with API keys | ✅ Pro-only, key shown once at creation |
| OFAC SDN + UN Consolidated List screening, fuzzy matching | ✅ (built and tested in the earlier MVP, unchanged here) |

## Run it locally

```bash
pip install -r requirements.txt --break-system-packages
python3 app.py
# open http://localhost:5000
```

A SQLite file (`app.db`) is created automatically on first run. Nothing
else is required to get the free tier fully working end to end.

## What needs YOUR configuration before it's "for real"

Everything below degrades gracefully when unset — the app never crashes,
it just tells the user (or shows in a local `outbox.log`) what would have
happened. Copy `.env.example` to `.env` and fill in what you have.

### 1. Stripe (for actual payments)
1. Create a Stripe account, create a Product with a recurring monthly Price.
2. Set `STRIPE_SECRET_KEY` and `STRIPE_PRICE_ID`.
3. Add a webhook endpoint in the Stripe dashboard pointing to
   `https://yourapp.com/billing/webhook`, listening for
   `checkout.session.completed`, `customer.subscription.updated`, and
   `customer.subscription.deleted`. Copy the signing secret into
   `STRIPE_WEBHOOK_SECRET`.
4. Until you do this, the Pricing page still renders and explains that
   billing isn't connected yet — it never shows a broken button.

### 2. Email (for password resets + watchlist alerts)
Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`.
This is plain SMTP — it works with **any** provider:

- **Resend** (recommended if you have nothing yet) — simplest signup,
  generous free tier, standard SMTP relay at `smtp.resend.com`.
- SendGrid, Mailgun, Amazon SES, Postmark — all work the same way.
- A Gmail account with an "app password" works fine for testing.

Until configured, reset links and alert emails are written to
`outbox.log` in the project folder instead of being sent — open that file
to see exactly what would have been emailed. This means you can test the
full forgot-password and monitoring-alert flows before signing up for any
email provider at all.

### 3. Watchlist monitoring (the recurring check)
This app does **not** run a background scheduler inside the web process
(that gets messy with multiple gunicorn workers). Instead, it exposes one
protected endpoint that a scheduler calls once a day:

```
POST /jobs/run-watchlist-check
Header: X-Cron-Secret: <your CRON_SECRET>
```

1. Generate a secret: `python3 -c "import secrets; print(secrets.token_hex(32))"`
2. Set it as `CRON_SECRET`.
3. Point any of these at it, once a day:
   - **cron-job.org** (free, two-minute setup, no code) — easiest option.
   - **GitHub Actions** scheduled workflow with a `curl` step.
   - Your hosting platform's native cron jobs (Render Cron Jobs, Railway Cron).

If `CRON_SECRET` isn't set, the endpoint returns an error instead of
running unprotected — it never executes without a secret configured.

### 4. EU sanctions list (optional, extra coverage)
Get a free token from https://webgate.ec.europa.eu/fsd/fsf/public/home
and set `EU_SANCTIONS_TOKEN`. OFAC + UN coverage works fully without this.

## Deploying for real

Standard Flask app — deploy anywhere that runs Python:

```bash
# Render / Railway: push to GitHub, point a Web Service at the repo
# Build: pip install -r requirements.txt
# Start: gunicorn app:app   (already in Procfile)
```

**Database note:** SQLite (`app.db`) is fine for getting started but lives
on local disk — most platforms wipe local disk on redeploy. For anything
beyond a first test, point `DATABASE_PATH` at a persistent volume, or
swap `db.py` for a real Postgres connection when you're ready to scale
past a single small server.

## Security notes (read before charging real customers)

- Passwords are hashed with Werkzeug's `generate_password_hash` (PBKDF2),
  never stored in plain text.
- CSRF tokens are required on every state-changing form (login, signup,
  password reset, checkout, portal, watchlist add/remove, API key
  create/revoke) — tested explicitly, not just assumed.
- API keys are stored as a SHA-256 hash only; the raw key is shown exactly
  once, at creation time, the same way Stripe/GitHub/etc. do it.
- The Stripe webhook verifies the HMAC signature manually (no SDK) and
  rejects anything that doesn't match — tested against valid, tampered,
  wrong-secret, and expired-timestamp payloads.
- `SECRET_KEY` in `.env.example` is a placeholder. Generate a real one
  (`python3 -c "import secrets; print(secrets.token_hex(32))"`) before
  deploying, or your sessions aren't actually tamper-proof.

## Still genuinely not included

- Email *verification* on signup (accounts work immediately on signup;
  there's no "confirm your email" step).
- Multi-seat / team accounts — one user = one account, no org structure.
- A marketing/SEO content strategy — that's a business decision, not
  something to hardcode into the app.
- Refund handling beyond what Stripe's dashboard gives you by default.

## One more reminder

Don't market this as "100% compliant" or "guaranteed safe" — that's
the exact kind of claim that creates legal liability rather than
preventing it. The in-app notices saying so are there on purpose. Keep
them, in the marketing copy too.
