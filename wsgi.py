"""WSGI entry point and convenient local development server."""

import os

from app import create_app

app = create_app()


if __name__ == "__main__":
    # Debug mode is intentionally off; use the Flask CLI when debugging locally.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
