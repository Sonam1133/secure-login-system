import re
import sqlite3
import bcrypt
from flask import Flask, request, session, redirect, render_template_string

app = Flask(__name__)
app.secret_key = "change-this-on-day-2"  # Day 2: load from an environment variable

DB = "users.db"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")


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
                password_hash BLOB NOT NULL
            )"""
        )


FORM = """
<h2>{{ title }}</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">
  <input name="username" placeholder="username" required>
  <input name="password" type="password" placeholder="password" required>
  <button type="submit">{{ title }}</button>
</form>
<p><a href="/register">Register</a> | <a href="/login">Login</a></p>
"""


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not USERNAME_RE.match(username):
            error = "Username must be 3-30 letters, digits or underscores."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            try:
                with get_db() as conn:
                    # Parameterized query: user input is never part of the SQL text
                    conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, hashed),
                    )
                return redirect("/login")
            except sqlite3.IntegrityError:
                error = "That username is taken."
    return render_template_string(FORM, title="Register", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        if row and bcrypt.checkpw(password.encode(), row["password_hash"]):
            session.clear()
            session["user"] = row["username"]
            return redirect("/dashboard")
        # Same message for unknown user and wrong password, so attackers can't tell which
        error = "Invalid username or password."
    return render_template_string(FORM, title="Login", error=error)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template_string(
        "<h2>Welcome, {{ user }}</h2><a href='/logout'>Logout</a>",
        user=session["user"],
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    init_db()
    app.run(debug=False)