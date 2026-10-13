from app import db
from app.models import AuditLog, User


def test_register_hashes_password_and_defaults_to_user(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "person@example.com", "password": "StrongPassword9!"},
    )
    assert response.status_code == 201
    assert response.json["user"]["role"] == "user"
    with client.application.app_context():
        user = User.query.filter_by(email="person@example.com").one()
        assert user.password_hash != "StrongPassword9!"
        assert user.check_password("StrongPassword9!")


def test_registration_rejects_weak_password(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "person@example.com", "password": "weak"},
    )
    assert response.status_code == 400
    assert len(response.json["details"]) >= 4


def test_registration_supports_passwords_longer_than_bcrypt_input_limit(client):
    password = "A" * 90 + "b7!"
    response = client.post(
        "/api/auth/register",
        json={"email": "long-password@example.com", "password": password},
    )
    assert response.status_code == 201
    with client.application.app_context():
        user = User.query.filter_by(email="long-password@example.com").one()
        assert user.check_password(password)


def test_registration_rejects_duplicate_email(client, registered_user):
    response = client.post(
        "/api/auth/register",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    assert response.status_code == 409


def test_registration_rejects_malformed_body(client):
    response = client.post("/api/auth/register", data="{", content_type="application/json")
    assert response.status_code == 400


def test_login_returns_bearer_token_and_audits_success(client, registered_user):
    response = client.post("/api/auth/login", json=registered_user)
    assert response.status_code == 200
    assert response.json["token_type"] == "Bearer"
    with client.application.app_context():
        assert AuditLog.query.filter_by(event_type="login_success").count() == 1


def test_protected_endpoint_requires_token_and_returns_profile(client, registered_user):
    assert client.get("/api/me").status_code == 401
    token = client.post("/api/auth/login", json=registered_user).json["access_token"]
    response = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json["user"]["email"] == registered_user["email"]


def test_protected_endpoint_returns_not_found_for_deleted_account(client, registered_user, app):
    token = client.post("/api/auth/login", json=registered_user).json["access_token"]
    with app.app_context():
        user = User.query.filter_by(email=registered_user["email"]).one()
        db.session.delete(user)
        db.session.commit()
    response = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404


def test_five_failed_logins_lock_account_and_audit_events(client, registered_user):
    for _ in range(5):
        response = client.post(
            "/api/auth/login",
            json={"email": registered_user["email"], "password": "WrongPassword9!"},
        )
        assert response.status_code == 401

    with client.application.app_context():
        user = User.query.filter_by(email=registered_user["email"]).one()
        assert user.failed_login_attempts == 5
        assert user.locked_until is not None
        assert AuditLog.query.filter_by(event_type="login_failure").count() == 4
        assert AuditLog.query.filter_by(event_type="login_lockout").count() == 1

    # Even the correct password cannot bypass the active lockout.
    response = client.post("/api/auth/login", json=registered_user)
    assert response.status_code == 401


def test_user_cannot_access_admin_endpoints(client, registered_user):
    token = client.post("/api/auth/login", json=registered_user).json["access_token"]
    response = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_admin_can_list_users_and_audit_logs(client, registered_user, app):
    from app.models import User as Account

    with app.app_context():
        admin = Account(email="admin@example.com", password="AdminPassword9!", role="admin")
        db.session.add(admin)
        db.session.commit()
        admin_id = admin.id
    token = client.post(
        "/api/auth/login",
        json={"email": "admin@example.com", "password": "AdminPassword9!"},
    ).json["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    users = client.get("/api/admin/users", headers=headers)
    logs = client.get("/api/admin/audit-logs", headers=headers)
    assert users.status_code == 200
    assert {entry["role"] for entry in users.json["users"]} == {"admin", "user"}
    assert logs.status_code == 200
    assert logs.json["audit_logs"][0]["event_type"] == "login_success"
    assert admin_id > 0


def test_security_headers_are_on_html_and_api_responses(client):
    for response in (client.get("/"), client.get("/api/me")):
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_login_rate_limit_returns_429(tmp_path):
    from app import create_app

    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'limited.sqlite'}",
            "JWT_SECRET_KEY": "test-jwt-secret-with-at-least-32-bytes",
            "SECRET_KEY": "test-secret-with-at-least-32-bytes",
            "BCRYPT_LOG_ROUNDS": 4,
            "RATELIMIT_ENABLED": True,
            "RATELIMIT_STORAGE_URI": "memory://",
        }
    )
    client = app.test_client()
    statuses = [
        client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "Nope9!"}).status_code
        for _ in range(6)
    ]
    assert statuses[:5] == [401] * 5
    assert statuses[5] == 429
    with app.app_context():
        db.session.remove()
        db.drop_all()
