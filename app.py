"""
app.py
======
Flask application factory for the AA-IDS backend.

SRS Requirements: Section 4.6 (Flask IDS Backend)
- FL-001 through FL-005: Request orchestration and API endpoints

Usage
-----
  Development:
    python app.py

  Production (gunicorn + eventlet):
    gunicorn -k eventlet -w 1 "app:create_app()"

  Testing:
    from app import create_app
    app = create_app()
    client = app.test_client()
"""

import logging
import os
import sys
from pathlib import Path

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO

# Ensure backend/ is on sys.path
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import config
from backend.api.routes import api_bp
from backend.sockets.events import init_socketio

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# Module-level SocketIO instance
socketio: SocketIO | None = None


def create_app(config_object: object | None = None) -> Flask:
    """
    Flask application factory.

    Parameters
    ----------
    config_object : optional object whose attributes override config defaults.
                    Used by the test suite to inject TESTING=True etc.

    Returns
    -------
    Flask — fully configured application with API Blueprint and SocketIO registered.
    """
    global socketio

    app = Flask(__name__)

    # Load configuration
    app.config["SECRET_KEY"] = config.FLASK_SECRET_KEY
    app.config["TESTING"] = False

    if config_object is not None:
        app.config.from_object(config_object)

    # CORS
    CORS(app, resources={r"/api/*": {"origins": config.SOCKETIO_CORS_ORIGINS}})

    # Socket.IO
    socketio = SocketIO(
        app,
        async_mode="threading",
        cors_allowed_origins=config.SOCKETIO_CORS_ORIGINS,
        logger=False,
        engineio_logger=False,
    )
    init_socketio(socketio)
    log.info("Flask-SocketIO initialised (async_mode=threading)")

    # Register API Blueprint only (no dashboard)
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    log.info("Blueprint 'api' registered at /api/v1")

    log.info(
        "AA-IDS Flask backend ready  |  ML_MODEL_PATH=%s  |  RULE_THRESHOLD=%s",
        config.ML_MODEL_PATH,
        config.RULE_ENGINE_THRESHOLD,
    )

    return app


if __name__ == "__main__":
    app = create_app()
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
        allow_unsafe_werkzeug=True,
    )
