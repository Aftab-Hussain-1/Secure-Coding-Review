"""
Sample Vulnerable Flask Web Application
========================================
This file intentionally contains security vulnerabilities
for demonstration and educational purposes.
DO NOT deploy this code in production.
"""

import sqlite3
import os
import pickle
import subprocess
import hashlib
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# VULNERABILITY: Hardcoded secret key
app.secret_key = "supersecretkey123"

# VULNERABILITY: Hardcoded credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
ADMIN_USER = "admin"
ADMIN_PASS = "password"


# VULNERABILITY: SQL Injection
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("users.db")
    # Directly interpolating user input into SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    if user:
        return "Login successful"
    return "Login failed"


# VULNERABILITY: Cross-Site Scripting (XSS)
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Directly rendering user input without sanitization
    template = f"<h1>Search results for: {query}</h1>"
    return render_template_string(template)


# VULNERABILITY: Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # Passing user input directly to shell command
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output.decode()


# VULNERABILITY: Insecure Deserialization
@app.route("/load_session", methods=["POST"])
def load_session():
    data = request.data
    # Deserializing untrusted data with pickle
    session_data = pickle.loads(data)
    return str(session_data)


# VULNERABILITY: Path Traversal
@app.route("/read_file")
def read_file():
    filename = request.args.get("file", "")
    # No validation of file path - allows reading arbitrary files
    with open(f"/var/app/uploads/{filename}", "r") as f:
        return f.read()


# VULNERABILITY: Weak Hashing (MD5 for passwords)
def store_password(password: str) -> str:
    # MD5 is cryptographically broken for password storage
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY: Insecure Random
import random

def generate_token():
    # random is not cryptographically secure
    return str(random.randint(100000, 999999))


# VULNERABILITY: Debug mode enabled in production
@app.route("/debug")
def debug_info():
    # Exposing sensitive environment variables
    env_vars = dict(os.environ)
    return str(env_vars)


# VULNERABILITY: No HTTPS enforcement
@app.route("/transfer", methods=["POST"])
def transfer_funds():
    amount = request.form.get("amount")
    to_account = request.form.get("to")
    # No CSRF protection, no authentication check
    return f"Transferred {amount} to {to_account}"


# VULNERABILITY: Integer overflow potential
@app.route("/calculate")
def calculate():
    # No input validation on numeric input
    n = int(request.args.get("n", 0))
    result = n * 999999999999999
    return str(result)


# VULNERABILITY: Open Redirect
@app.route("/redirect_user")
def redirect_user():
    url = request.args.get("url", "/")
    # Redirecting to arbitrary URL without validation
    return redirect(url)


# VULNERABILITY: Broad Exception Handling + Info Disclosure
@app.route("/process")
def process():
    try:
        data = request.args.get("data")
        result = eval(data)   # VULNERABILITY: eval() on user input
        return str(result)
    except Exception as e:
        # Exposing stack trace to end user
        return f"Error: {str(e)}", 500


if __name__ == "__main__":
    # VULNERABILITY: Running in debug mode with all interfaces exposed
    app.run(debug=True, host="0.0.0.0", port=5000)
