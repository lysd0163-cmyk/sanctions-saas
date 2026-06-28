import os

from flask import Flask, g

import db
from auth_helpers import get_csrf_token, load_logged_in_user
from admin import admin_bp

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-this-in-production")
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB upload cap

    db.init_db()

    app.before_request(load_logged_in_user)

    @app.context_processor
    def inject_globals():
        return {"current_user": g.get("user"), "csrf_token": get_csrf_token}

    from auth import auth_bp
    from billing import billing_bp
    from landing import landing_bp
    from screening_routes import screening_bp
    from watchlist import watchlist_bp
    from jobs import jobs_bp
    from api_keys import api_keys_bp, public_api_bp

    app.register_blueprint(landing_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(screening_bp)
    app.register_blueprint(watchlist_bp)
    app.register_blueprint(jobs_bp)
    app.register_blueprint(api_keys_bp)
    app.register_blueprint(public_api_bp)
app.register_blueprint(admin_bp)
    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="0.0.0.0", port=port)
