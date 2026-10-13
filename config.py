"""Application settings, with environment-variable overrides for deployment."""

import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-this-secret-key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-only-change-this-jwt-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///secureauth.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = 60 * 60
    BCRYPT_LOG_ROUNDS = int(os.getenv("BCRYPT_LOG_ROUNDS", "12"))
    BCRYPT_HANDLE_LONG_PASSWORDS = True
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = []
    MAX_CONTENT_LENGTH = 16 * 1024
