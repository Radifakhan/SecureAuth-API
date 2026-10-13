"""SQLAlchemy models for accounts and security-relevant events."""

from datetime import datetime, timezone

from app import bcrypt, db


def utc_now():
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class User(db.Model):
    """A registered account; public registration always creates the user role."""

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="user")
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    def __init__(self, email, password, role="user"):
        self.email = email
        self.password = password
        self.role = role

    @property
    def password(self):
        """Passwords cannot be read back after hashing."""
        raise AttributeError("Password is write-only.")

    @password.setter
    def password(self, raw_password):
        self.password_hash = bcrypt.generate_password_hash(raw_password).decode("utf-8")

    def check_password(self, raw_password):
        return bcrypt.check_password_hash(self.password_hash, raw_password)

    def public_dict(self):
        return {"id": self.id, "email": self.email, "role": self.role}


class AuditLog(db.Model):
    """Append-only record of login outcomes and account lockouts."""

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    event_type = db.Column(db.String(40), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    user = db.relationship("User", backref=db.backref("audit_logs", lazy=True))

    def public_dict(self):
        timestamp = self.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.user.email if self.user else None,
            "event_type": self.event_type,
            "ip_address": self.ip_address,
            "timestamp": timestamp.isoformat(),
        }
