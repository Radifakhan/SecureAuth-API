"""Application factory and shared extension setup."""

import click
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

from config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)


def create_app(test_config=None):
    """Build and configure one app instance (also makes isolated tests easy)."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)

    from app import models  # noqa: F401 - registers tables with SQLAlchemy
    from app.routes import api

    app.register_blueprint(api)

    @app.after_request
    def add_security_headers(response):
        """Set browser protections centrally, including on error responses."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    @app.cli.command("init-db")
    def init_db():
        """Create the database tables."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("create-admin")
    @click.option("--email", prompt=True, help="Email address for the admin.")
    @click.password_option()
    def create_admin(email, password):
        """Create an administrator without exposing role assignment publicly."""
        from app.models import User
        from app.validation import validate_email, validate_password

        email = email.strip().lower()
        errors = validate_email(email) + validate_password(password)
        if errors:
            raise click.ClickException("; ".join(errors))
        if User.query.filter_by(email=email).first():
            raise click.ClickException("An account with that email already exists.")
        db.session.add(User(email=email, password=password, role="admin"))
        db.session.commit()
        click.echo("Admin account created.")

    with app.app_context():
        db.create_all()

    return app

