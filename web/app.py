import os
from flask import Flask, render_template, jsonify
from ghostrelay.sessions import SESSION_STORE
from ghostrelay.responder_manager import ResponderManager

# Global responder manager instance
RESP = ResponderManager()


def create_app():
    app = Flask(__name__)

    # ---------------------
    # Dashboard route
    # ---------------------
    @app.route("/")
    def dashboard():
        session_count = len(SESSION_STORE.list_sessions())
        responder_running = RESP.running

        return render_template(
            "dashboard.html",
            session_count=session_count,
            responder_running=responder_running,
        )

    # ---------------------
    # API: Dashboard summary
    # ---------------------
    @app.route("/api/dashboard")
    def api_dashboard():
        return jsonify({
            "session_count": len(SESSION_STORE.list_sessions()),
            "responder_running": RESP.running,
        })

    # ---------------------
    # Register Blueprints
    # ---------------------
    from ghostrelay.web.routes.capture import capture_bp
    from ghostrelay.web.routes.sessions import sessions_bp
    from ghostrelay.web.routes.targets import targets_bp
    from ghostrelay.web.routes.relay import relay_bp

    app.register_blueprint(capture_bp, url_prefix="/capture")
    app.register_blueprint(sessions_bp, url_prefix="/sessions")
    app.register_blueprint(targets_bp, url_prefix="/targets")
    app.register_blueprint(relay_bp, url_prefix="/relay")

    return app


if __name__ == "__main__":
    app = create_app()
    port = 5005
    app.run(host="0.0.0.0", port=port, debug=True)

