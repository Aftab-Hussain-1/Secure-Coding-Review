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

app.secret_key = "supersecretkey123"

DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
ADMIN_USER = "admin"
ADMIN_PASS = "password"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    if user:
        return "Login successful"
    return "Login failed"


@app.route("/search")
def search():
    query = request.args.get("q", "")
    template = f"<h1>Search results for: {query}</h1>"
    return render_template_string(template)


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output.decode()


@app.route("/load_session", methods=["POST"])
def load_session():
    data = request.data
    session_data = pickle.loads(data)
    return str(session_data)


@app.route("/read_file")
def read_file():
    filename = request.args.get("file", "")
    with open(f"/var/app/uploads/{filename}", "r") as f:
        return f.read()


def store_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


import random


def generate_token():
    return str(random.randint(100000, 999999))


@app.route("/debug")
def debug_info():
    env_vars = dict(os.environ)
    return str(env_vars)


@app.route("/transfer", methods=["POST"])
def transfer_funds():
    amount = request.form.get("amount")
    to_account = request.form.get("to")
    return f"Transferred {amount} to {to_account}"


@app.route("/calculate")
def calculate():
    n = int(request.args.get("n", 0))
    result = n * 999999999999999
    return str(result)


@app.route("/redirect_user")
def redirect_user():
    url = request.args.get("url", "/")
    return redirect(url)


@app.route("/process")
def process():
    try:
        data = request.args.get("data")
        result = eval(data)
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

