# Secure Login System (Flask)

A small Flask authentication app built to apply what I found while testing a deliberately vulnerable app (DVWA). It implements registration, login and logout, with each common weakness addressed and tested.

> After exploiting SQL injection and XSS in DVWA, I built this app to see what it takes to prevent them, then attacked it myself and wrote automated tests to confirm the defenses hold.

## Features and Defenses

| Area | What the app does |
|---|---|
| Password storage | bcrypt with a per-password salt (never plain text, never MD5) |
| SQL injection | Parameterized queries only; user input is never concatenated into SQL |
| Input validation | Usernames limited to 3-30 letters, digits or underscores; passwords 8+ characters, 72 bytes max (bcrypt's limit) |
| CSRF | Flask-WTF token required on every POST; logout is a POST |
| Brute force | Rate limit of 10 login attempts per minute per IP, plus account lockout for 15 minutes after 5 failed attempts |
| User enumeration | Same "Invalid username or password." message for unknown users, wrong passwords and locked accounts; a dummy bcrypt check keeps timing similar |
| Session security | `HttpOnly` and `SameSite=Lax` cookies, 30-minute session lifetime, session cleared on login |
| Security headers | `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| Secrets | `SECRET_KEY` is read from an environment variable, never stored in the code |

## Before and After: DVWA vs This App

| Weakness found in DVWA (Low security) | In this app |
|---|---|
| SQL injection returned every user record | Payloads such as `admin' OR '1'='1` are treated as plain text and rejected |
| Passwords stored as unsalted MD5 hashes | bcrypt hashes (`$2b$...`), salted and deliberately slow |
| Reflected XSS from unencoded input | Usernames are validated, output is auto-escaped by the template engine, and a strict CSP is set |
| No limit on login attempts | Rate limiting and account lockout |
| No CSRF protection | Requests without a valid token get `400 Bad Request` |

## Tech Stack

Python, Flask, SQLite, bcrypt, Flask-WTF, Flask-Limiter, pytest

## Setup

```
git clone https://github.com/Sonam1133/secure-login-system.git
cd secure-login-system
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Generate and set a secret key (Windows Command Prompt):

```
for /f %i in ('python -c "import secrets; print(secrets.token_hex(32))"') do set SECRET_KEY=%i
```

On Linux or macOS: `export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")`

Run the app:

```
python app.py
```

Then open http://127.0.0.1:5000/register. The app refuses to start without `SECRET_KEY`.

## Testing

Automated tests (12) use a temporary database, so they never touch real data:

```
python -m pytest test_app.py
```

They cover registration and login, bcrypt hashing, SQL injection in both the username and password fields, identical error messages for unknown users and wrong passwords, script-tag usernames, short passwords, lockout after five failures, login required for the dashboard, CSRF rejection, security headers and rate limiting.

## Manual Verification

I also checked each defense by hand against the running app. Screenshots are in `evidence/`:

| Check | How it was tested | Result |
|---|---|---|
| SQL injection | Username `admin' OR '1'='1` on the login form | Rejected with the generic error message |
| Rate limiting | Submitted the login form repeatedly within a minute | `429 Too Many Requests` |
| CSRF | `curl -X POST /login` with no token | `400 Bad Request: The CSRF token is missing` |
| Security headers | `curl -I /login` | All four headers present |
| Cookie flags | Browser DevTools, Application tab | `HttpOnly` set, `SameSite=Lax` |
| Account lockout | 5 wrong passwords, then the correct one | Login refused; `locked_until` set in the database |

## Limitations

This is a learning project, not production-ready software.

- Runs on Flask's development server. A production deployment needs a WSGI server (for example gunicorn) behind HTTPS.
- `SESSION_COOKIE_SECURE` is `False` because it runs over local HTTP; it must be `True` under HTTPS.
- The rate limiter stores counts in memory, so they reset on restart and aren't shared across processes. Use Redis for a real deployment.
- Account lockout can be abused to deliberately lock someone else out. Real systems often add CAPTCHA, progressive delays or alerts.
- No password reset, email verification or two-factor authentication.
- Flask's default session cookie is signed but not encrypted, so nothing sensitive should be stored in it.

## Possible Next Steps

- TOTP two-factor authentication
- Password breach check (k-anonymity API)
- Audit logging of failed logins
- Docker packaging and a CI pipeline running tests and security scans

## Disclaimer

For educational use. Do not use the attack payloads described here against systems you do not own or have written permission to test.

## Author

**Sonam Bamotra**
GitHub: [Sonam1133](https://github.com/Sonam1133)