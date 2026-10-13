"""Small input validators shared by HTTP routes and the admin CLI."""

import re


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_email(email):
    errors = []
    if not isinstance(email, str) or not email.strip():
        return ["Email is required."]
    if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        errors.append("Enter a valid email address (maximum 254 characters).")
    return errors


def validate_password(password):
    errors = []
    if not isinstance(password, str):
        return ["Password is required."]
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain an uppercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password must contain a digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain a symbol.")
    return errors

