# SecureAuth-API

A small, runnable authentication API built with Flask, Flask-SQLAlchemy, SQLite, bcrypt, and JWT access tokens. It includes a browser demo, administrator endpoints, security auditing, and pytest coverage.

## Features

- Register and log in with bcrypt password hashing and signed JWT bearer tokens.
- Enforce a password of at least 12 characters containing uppercase, lowercase, numeric, and symbol characters.
- Lock an account for 15 minutes after five consecutive incorrect-password attempts.
- Limit login requests to five per minute per client IP.
- Keep public registration at the `user` role; create administrators using a local/production CLI command.
- Restrict user listings and audit log listings to administrators.
- Record login successes, login failures, and lockouts with UTC timestamps and client IP addresses.
- Return JSON validation errors and appropriate HTTP statuses, including 400, 401, 403, 404, 409, and 429.
- Send `X-Content-Type-Options`, `X-Frame-Options`, and Content Security Policy headers on every response.
- Provide a simple HTML/JavaScript page for registration, login, and a protected request.

## Setup and run

Use Python 3.10 or newer. From the project directory:

```bash
pip install -r requirements.txt
python wsgi.py
```

Open <http://127.0.0.1:5000/> for the browser demo. The SQLite database is created automatically as `instance/secureauth.db`.

Before deployment, configure strong, unique secrets:

```text
SECRET_KEY=<random application secret>
JWT_SECRET_KEY=<different random JWT signing secret>
DATABASE_URL=sqlite:///secureauth.db
```

Create an administrator interactively:

```bash
flask --app wsgi create-admin
```

The CLI prompts for an email and password and validates the password policy. The command is the only supported way to assign the admin role; normal registration cannot choose a role.

## Tests

```bash
pytest -q
```

Tests use isolated SQLite files and a reduced bcrypt work factor to run quickly; normal app configuration uses bcrypt's default work factor of 12.

## Endpoint table

| Method | Path | Access | Purpose |
|---|---|---|---|
| `GET` | `/` | Public | Browser demonstration page |
| `POST` | `/api/auth/register` | Public | Create a user account |
| `POST` | `/api/auth/login` | Public; limited | Authenticate and receive a JWT |
| `GET` | `/api/me` | Valid JWT | Return the current account |
| `GET` | `/api/admin/users` | Admin JWT | List account IDs, emails, and roles |
| `GET` | `/api/admin/audit-logs` | Admin JWT | Return the latest 200 audit events |

### curl examples

Register (substitute a password meeting the policy):

```bash
curl -i http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"person@example.com","password":"StrongPassword9!"}'
```

Log in and copy the `access_token` from the JSON response:

```bash
curl -i http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"person@example.com","password":"StrongPassword9!"}'
```

Call the protected profile endpoint:

```bash
curl -i http://127.0.0.1:5000/api/me \
  -H "Authorization: Bearer <access_token>"
```

After creating an admin with the CLI and logging in as that admin, call:

```bash
curl -i http://127.0.0.1:5000/api/admin/users \
  -H "Authorization: Bearer <admin_access_token>"
curl -i http://127.0.0.1:5000/api/admin/audit-logs \
  -H "Authorization: Bearer <admin_access_token>"
```

## Security design notes

- **Password hashing:** Flask-Bcrypt stores only salted bcrypt hashes; plaintext passwords are write-only in the model and never appear in API responses.
- **Password policy:** Registration and the admin-creation command both apply the same minimum-length and character-class checks, preventing weaker administrator credentials.
- **JWT authentication:** Protected routes require a signed bearer token. Tokens carry the user's role; their lifetime is one hour by default. Keep `JWT_SECRET_KEY` private and rotate it to invalidate outstanding tokens.
- **Role-based access:** Public registration always selects the `user` role. Only the admin CLI creates an admin. The API checks role claims before exposing user and audit data.
- **Lockout:** Five consecutive password failures lock the account for 15 minutes. Correct credentials do not bypass an active lockout; a successful login clears failure state.
- **Rate limiting:** The login route allows at most five requests per minute per remote IP. Configure `RATELIMIT_STORAGE_URI` to use a shared production storage backend if running multiple workers; the in-memory default is suitable for local development only.
- **Audit trail:** Successes, failures, and lockouts are timestamped and associated with an IP address. Unknown-email failures are recorded without a user ID to avoid leaking whether an account exists.
- **Input and HTTP handling:** JSON shape and email/password fields are validated before database operations. Duplicate registration returns 409; invalid input, authentication failures, insufficient role, missing account, and rate-limit violations return 400, 401, 403, 404, and 429 respectively.
- **Browser protections:** A centralized response hook adds nosniff, frame denial, and a restrictive CSP to successful responses, API errors, and limiter responses.
- **Deployment:** Render receives generated secrets via `render.yaml`. SQLite is simple to run, but its local filesystem is not durable across many hosted deployment plans or instances; use a persistent disk or managed database for production. Never use development fallback secrets in production.
- **Proxy/IP handling:** The app uses `request.remote_addr` for rate-limit and audit attribution. Configure trusted-proxy handling deliberately if deployed behind a proxy; do not blindly trust client-supplied forwarding headers.

