import os
import re
import sqlite3
import time
import bcrypt
from flask import Flask, request, session, redirect, render_template_string
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
 
app = Flask(__name__)
 
# Secret key comes from the environment, never from the source code
secret = os.environ.get("SECRET_KEY")
if not secret:
    raise RuntimeError("Set the SECRET_KEY environment variable before running.")
app.secret_key = secret
 
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # JavaScript cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",   # limits cross-site request sending
    SESSION_COOKIE_SECURE=False,     # set True when served over HTTPS
    PERMANENT_SESSION_LIFETIME=1800, # sessions expire after 30 minutes
)
 
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")
 
DB = "users.db"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
MAX_FAILS = 5
LOCK_SECONDS = 15 * 60
GENERIC_ERROR = "Invalid username or password."
# Used so unknown usernames take about as long to check as real ones
DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt())
 
 
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn
 
 
def init_db():
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            )"""
        )
 
 
FORM = """
<h2>{{ title }}</h2>
{% if error %}<p><strong>{{ error }}</strong></p>{% endif %}
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="username" placeholder="username" required>
  <input name="password" type="password" placeholder="password" required>
  <button type="submit">{{ title }}</button>
</form>
<p><a href="/register">Register</a> | <a href="/login">Login</a></p>
"""
 
DASHBOARD = """
<h2>Welcome, {{ user }}</h2>
<form method="post" action="/logout">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit">Logout</button>
</form>
"""
 
 
@app.after_request
def add_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp
 
 
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not USERNAME_RE.match(username):
            error = "Username must be 3-30 letters, digits or underscores."
        elif len(password) < 8 or len(password.encode()) > 72:
            error = "Password must be 8 characters or more (72 bytes max)."
        else:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, hashed),
                    )
                return redirect("/login")
            except sqlite3.IntegrityError:
                error = "That username is taken."
    return render_template_string(FORM, title="Register", error=error)
 
 
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        pw_bytes = password.encode()
        now = time.time()
 
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
 
            if len(pw_bytes) > 72:
                error = GENERIC_ERROR
            elif row is None:
                bcrypt.checkpw(pw_bytes, DUMMY_HASH)
                error = GENERIC_ERROR
            elif row["locked_until"] > now:
                error = GENERIC_ERROR  # locked: same message, reveals nothing
            elif bcrypt.checkpw(pw_bytes, row["password_hash"]):
                conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
                    (row["id"],),
                )
                session.clear()
                session.permanent = True
                session["user"] = row["username"]
                return redirect("/dashboard")
            else:
                fails = row["failed_attempts"] + 1
                locked_until = 0
                if fails >= MAX_FAILS:
                    locked_until = now + LOCK_SECONDS
                    fails = 0
                conn.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (fails, locked_until, row["id"]),
                )
                error = GENERIC_ERROR
    return render_template_string(FORM, title="Login", error=error)
 
 
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template_string(DASHBOARD, user=session["user"])
 
 
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")
 
 
if __name__ == "__main__":
    init_db()
    app.run(debug=False)
 