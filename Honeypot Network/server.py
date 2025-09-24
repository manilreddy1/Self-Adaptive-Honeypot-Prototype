from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import sqlite3
import time
import random
import requests
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
limiter = Limiter(get_remote_address)
limiter.init_app(app)
CORS(app)

bcrypt = Bcrypt(app)

ABUSEIPDB_API_KEY = "a085d729af79c0bf597c323f08171fb237060eab6182c1003bd0f21bcad2833cf4916861e2eeb237"
LOGIN_ENDPOINT = "/login"
MAX_ATTEMPTS = 3

# Initialize database
def init_db():
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            username TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklisted_users (
            username TEXT PRIMARY KEY,
            timestamp REAL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_attempts (
            username TEXT PRIMARY KEY,
            attempts INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

# Log failed login attempts
def log_attempt(username, ip, user_agent):
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (ip, username, user_agent) VALUES (?, ?, ?)", (ip, username, user_agent))
    conn.commit()
    conn.close()

# Verify user credentials
def verify_credentials(username, password):
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user and bcrypt.check_password_hash(user[0], password)

# Blacklist user after multiple failures
def blacklist_user(username):
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO blacklisted_users (username, timestamp) VALUES (?, ?)", (username, time.time() + 600))
    conn.commit()
    conn.close()

# Update attack attempts
def update_attack_attempts(username):
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()
    cursor.execute("SELECT attempts FROM attack_attempts WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        cursor.execute("UPDATE attack_attempts SET attempts = attempts + 1 WHERE username = ?", (username,))
    else:
        cursor.execute("INSERT INTO attack_attempts (username, attempts) VALUES (?, 1)", (username,))
    conn.commit()
    conn.close()

# Fake delay to slow brute-force attempts
def fake_delay():
    time.sleep(random.uniform(0, 1))

@app.route("/")
def home():
    return render_template("index.html", login_url=LOGIN_ENDPOINT)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    fake_delay()
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")
    user_agent = request.headers.get("User-Agent", "Unknown")
    ip = request.remote_addr
    
    log_attempt(username, ip, user_agent)
    update_attack_attempts(username)
    
    if not username or not password:
        return jsonify({"message": "Please enter username and password."}), 400
    
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()
    cursor.execute("SELECT attempts FROM attack_attempts WHERE username = ?", (username,))
    attempts = cursor.fetchone()
    attempts = attempts[0] if attempts else 0
    conn.close()
    
    if attempts >= MAX_ATTEMPTS:
        blacklist_user(username)
        return jsonify({"message": "Intrusion Detected! Security System Resetting...", "reset": True}), 403
    
    if verify_credentials(username, password):
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"message": "Access Granted", "token": token})
    else:
        return jsonify({"message": "Unauthorized. This attempt has been logged."}), 403

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
