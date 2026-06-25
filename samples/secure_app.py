import os
import re
import secrets
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, redirect, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_urlsafe(32)


def _db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def _validate_hostname(host: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host or ""))


def _safe_upload_path(filename: str) -> Path:
    base = (Path(__file__).resolve().parent / "uploads").resolve()
    base.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename or "").name
    resolved = (base / safe_name).resolve()
    if base not in resolved.parents and resolved != base:
        raise ValueError("invalid path")
    return resolved


def _is_safe_redirect_target(url: str) -> bool:
    parsed = urlparse(url or "")
    return parsed.scheme == "" and parsed.netloc == ""


@app.before_request
def _ensure_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    with _db() as conn:
        row = conn.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,)).fetchone()

    if not row:
        return "Login failed", 401
    if not check_password_hash(row["password_hash"], password):
        return "Login failed", 401
    return "Login successful"


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_hash = generate_password_hash(password)

    with _db() as conn:
        conn.execute("INSERT INTO users(username, password_hash) VALUES(?, ?)", (username, password_hash))
        conn.commit()

    return "Registered"


@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"<h1>Search results for: {escape(query)}</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    if not _validate_hostname(host):
        return "Invalid host", 400

    proc = subprocess.run(
        ["ping", "-n", "1", host],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout or proc.stderr


@app.route("/load_session", methods=["POST"])
def load_session():
    data = request.get_json(silent=True)
    if data is None:
        return "Invalid JSON", 400
    return {"ok": True, "received": data}


@app.route("/read_file")
def read_file():
    filename = request.args.get("file", "")
    try:
        path = _safe_upload_path(filename)
    except ValueError:
        return "Invalid file path", 400
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "Not found", 404


@app.route("/transfer", methods=["POST"])
def transfer_funds():
    token = request.headers.get("X-CSRF-Token", "")
    if not secrets.compare_digest(token, session.get("csrf_token", "")):
        return "CSRF token missing/invalid", 403

    amount = request.form.get("amount", "")
    to_account = request.form.get("to", "")
    return f"Transferred {escape(amount)} to {escape(to_account)}"


@app.route("/calculate")
def calculate():
    try:
        n = int(request.args.get("n", "0"))
    except ValueError:
        return "Invalid number", 400
    if n < 0 or n > 1_000_000:
        return "Out of range", 400
    return str(n * 999999999999999)


@app.route("/redirect_user")
def redirect_user():
    url = request.args.get("url", "/")
    if not _is_safe_redirect_target(url):
        return "Invalid redirect", 400
    return redirect(url)


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="127.0.0.1", port=5000)

