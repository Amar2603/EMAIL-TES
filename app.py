from flask import Flask, request, jsonify, send_from_directory, redirect, url_for
import os
import sqlite3
import re
import dns.resolver
import smtplib
import socket

app = Flask(__name__, template_folder='.')

DB_FILE = 'users.db'

# ================= DB =================
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            fullname TEXT,
            password TEXT,
            credits INTEGER DEFAULT 100
        )
    ''')
    conn.commit()
    conn.close()

# ================= STATIC =================
@app.route('/')
def home():
    return redirect('/login.html')

@app.route('/<path:filename>')
def serve_files(filename):
    return send_from_directory('.', filename)

# ================= EMAIL LOGIC =================

def valid_format(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email)

def get_mx(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return str(records[0].exchange).rstrip('.')
    except:
        return None

def smtp_check(mx, email, domain):
    try:
        server = smtplib.SMTP(mx, timeout=8)
        server.ehlo()

        server.mail('test@' + domain)
        code, msg = server.rcpt(email)

        server.quit()

        msg = str(msg).lower()

        if code in [250, 251]:
            return "Valid", code, msg

        if "not exist" in msg or "no such" in msg or "5.1.1" in msg:
            return "Bounce", code, msg

        return "Valid", code, msg  # fallback

    except:
        # 🔥 SMTP blocked → treat as valid
        return "Valid", None, "SMTP blocked"

# ================= VERIFY API =================
@app.route('/verify-email')
def verify_email():
    email = request.args.get('email', '').strip()

    if not email:
        return jsonify({"status": "Error", "message": "No email"})

    if not valid_format(email):
        return jsonify({"status": "Invalid", "message": "Bad format"})

    domain = email.split('@')[1]

    mx = get_mx(domain)

    if not mx:
        return jsonify({"status": "Invalid", "message": "No MX record"})

    status, code, msg = smtp_check(mx, email, domain)

    return jsonify({
        "status": status,
        "smtp_code": code,
        "message": msg
    })

# ================= SERVER =================
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
