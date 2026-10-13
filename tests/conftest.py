import pytest

from app import create_app, db


@pytest.fixture
def app(tmp_path):
    database_path = tmp_path / "test.sqlite"
    test_app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
            "JWT_SECRET_KEY": "test-jwt-secret-with-at-least-32-bytes",
            "SECRET_KEY": "test-secret-with-at-least-32-bytes",
            "BCRYPT_LOG_ROUNDS": 4,
            "RATELIMIT_ENABLED": False,
        }
    )
    yield test_app
    with test_app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def registered_user(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "person@example.com", "password": "StrongPassword9!"},
    )
    assert response.status_code == 201
    return {"email": "person@example.com", "password": "StrongPassword9!"}
