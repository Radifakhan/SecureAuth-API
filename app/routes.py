"""Web page and version-one JSON API routes."""

from datetime import timedelta
from functools import wraps

from flask import Blueprint, jsonify, render_template, request
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from sqlalchemy import select

from app import db, limiter
from app.models import AuditLog, User, utc_now
from app.validation import validate_email, validate_password

api = Blueprint("api", __name__)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _json_body():
    """Return a validated JSON object or a client-safe 400 response."""
    if not request.is_json:
        return None, (jsonify(error="Content-Type must be application/json."), 400)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None, (jsonify(error="Request body must be a JSON object."), 400)
    return payload, None


def _record_audit(event_type, user=None):
    db.session.add(
        AuditLog(
            user_id=user.id if user else None,
            event_type=event_type,
            ip_address=request.remote_addr or "unknown",
        )
    )


def roles_required(*allowed_roles):
    """Require a valid JWT and a role included in the allowed-role list."""
    def decorator(view):
        @wraps(view)
        @jwt_required()
        def wrapped(*args, **kwargs):
            if get_jwt().get("role") not in allowed_roles:
                return jsonify(error="You do not have permission to access this resource."), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator


@api.get("/")
def index():
    return render_template("index.html")


@api.post("/api/auth/register")
def register():
    payload, error = _json_body()
    if error:
        return error

    email = payload.get("email")
    password = payload.get("password")
    errors = validate_email(email)
    errors.extend(validate_password(password))
    if errors:
        return jsonify(error="Input validation failed.", details=errors), 400

    normalized_email = email.strip().lower()
    if db.session.execute(select(User).filter_by(email=normalized_email)).scalar_one_or_none():
        return jsonify(error="An account with that email already exists."), 409

    user = User(email=normalized_email, password=password)
    db.session.add(user)
    db.session.commit()
    return jsonify(message="Account registered.", user=user.public_dict()), 201


@api.post("/api/auth/login")
@limiter.limit("5 per minute")
def login():
    payload, error = _json_body()
    if error:
        return error

    email = payload.get("email")
    password = payload.get("password")
    if not isinstance(email, str) or not email.strip() or not isinstance(password, str) or not password:
        return jsonify(error="Email and password are required."), 400

    user = db.session.execute(
        select(User).filter_by(email=email.strip().lower())
    ).scalar_one_or_none()

    # Use the same response for unknown accounts, wrong passwords, and lockouts.
    if user is None:
        _record_audit("login_failure")
        db.session.commit()
        return jsonify(error="Invalid email or password."), 401

    now = utc_now()
    if user.locked_until is not None:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=now.tzinfo)
        if locked_until > now:
            _record_audit("login_lockout", user)
            db.session.commit()
            return jsonify(error="Invalid email or password."), 401
        user.locked_until = None
        user.failed_login_attempts = 0

    if not user.check_password(password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            _record_audit("login_lockout", user)
        else:
            _record_audit("login_failure", user)
        db.session.commit()
        return jsonify(error="Invalid email or password."), 401

    user.failed_login_attempts = 0
    user.locked_until = None
    _record_audit("login_success", user)
    db.session.commit()
    token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "email": user.email},
    )
    return jsonify(access_token=token, token_type="Bearer"), 200


@api.get("/api/me")
@jwt_required()
def protected_profile():
    user = db.session.get(User, int(get_jwt_identity()))
    if user is None:
        return jsonify(error="Account not found."), 404
    return jsonify(user=user.public_dict()), 200


@api.get("/api/admin/users")
@roles_required("admin")
def list_users():
    users = db.session.execute(select(User).order_by(User.id)).scalars().all()
    return jsonify(users=[user.public_dict() for user in users]), 200


@api.get("/api/admin/audit-logs")
@roles_required("admin")
def list_audit_logs():
    logs = db.session.execute(
        select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(200)
    ).scalars().all()
    return jsonify(audit_logs=[entry.public_dict() for entry in logs]), 200

