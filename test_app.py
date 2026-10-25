import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

import sqlite3
import pytest
import app as app_module

GOOD_PW = "Correct123"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "DB", str(tmp_path / "test.db"))
    app_module.init_db()
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    app_module.limiter.enabled = False
    app_module.limiter.reset()
    with app_module.app.test_client() as c:
        yield c
    app_module.limiter.reset()


def register(client, username="alice", password=GOOD_PW):
    return client.post("/register", data={"username": username, "password": password})


def login(client, username="alice", password=GOOD_PW):
    return client.post("/login", data={"username": username, "password": password})


def logged_in(client):
    with client.session_transaction() as s:
        return "user" in s


def test_register_and_login_succeeds(client):
    assert register(client).status_code == 302
    resp = login(client)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")
    assert logged_in(client)


def test_password_is_stored_as_bcrypt_hash(client):
    register(client)
    row = sqlite3.connect(app_module.DB).execute(
        "SELECT password_hash FROM users WHERE username='alice'"
    ).fetchone()
    assert row[0].startswith(b"$2b$")
    assert GOOD_PW.encode() not in row[0]


def test_sql_injection_in_username_is_rejected(client):
    register(client)
    resp = login(client, username="alice' OR '1'='1", password="anything123")
    assert b"Invalid username or password." in resp.data
    assert not logged_in(client)


def test_sql_injection_in_password_is_rejected(client):
    register(client)
    resp = login(client, password="' OR '1'='1")
    assert b"Invalid username or password." in resp.data
    assert not logged_in(client)


def test_unknown_user_and_wrong_password_give_same_message(client):
    register(client)
    wrong_pw = login(client, password="WrongPass999")
    no_user = login(client, username="nobody", password="WrongPass999")
    assert b"Invalid username or password." in wrong_pw.data
    assert b"Invalid username or password." in no_user.data


def test_script_tag_username_is_rejected(client):
    resp = register(client, username="<script>alert(1)</script>")
    assert resp.status_code == 200
    assert b"Username must be" in resp.data


def test_short_password_is_rejected(client):
    resp = register(client, password="short")
    assert b"at least" in resp.data or b"8 characters" in resp.data


def test_account_locks_after_five_failures(client):
    register(client)
    for _ in range(5):
        login(client, password="WrongPass999")
    resp = login(client)  # correct password, but account is locked
    assert b"Invalid username or password." in resp.data
    assert not logged_in(client)


def test_dashboard_requires_login(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_csrf_token_is_required(client):
    app_module.app.config["WTF_CSRF_ENABLED"] = True
    resp = client.post("/login", data={"username": "a", "password": "b"})
    assert resp.status_code == 400


def test_security_headers_present(client):
    resp = client.get("/login")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_login_is_rate_limited(client):
    app_module.limiter.enabled = True
    app_module.limiter.reset()
    codes = [login(client, username="nobody", password="WrongPass999").status_code
             for _ in range(12)]
    assert 429 in codes