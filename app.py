from flask import Flask, request, redirect, url_for, send_from_directory, jsonify, render_template
import os
import sys
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from werkzeug.utils import secure_filename
from verify.singleemail import validate_email 

app = Flask(__name__, template_folder='.')
DB_FILE = 'users.db'
PROFILE_UPLOAD_DIR = 'profile_uploads'
ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

# 🔥 THREAD POOL (IMPORTANT)
executor = ThreadPoolExecutor(max_workers=5)

print("=" * 50)
print("Flask Server Starting...")
print("Go to: http://localhost:5000/login.html")
print("=" * 50)

# ================= DB =================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(PROFILE_UPLOAD_DIR, exist_ok=True)
    conn = get_db_connection()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                fullname TEXT NOT NULL,
                password TEXT NOT NULL,
                profile_image TEXT,
                credits INTEGER NOT NULL DEFAULT 100
            )
        ''')

        columns = [row['name'] for row in conn.execute("PRAGMA table_info(users)").fetchall()]

        if 'profile_image' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN profile_image TEXT')

        if 'credits' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN credits INTEGER NOT NULL DEFAULT 100')

        conn.execute('UPDATE users SET credits = 100 WHERE credits IS NULL')
        conn.commit()
    finally:
        conn.close()

# ================= STATIC ROUTES =================
@app.route('/')
def home():
    return redirect(url_for('static_login'))

@app.route('/signup.html')
def static_signup():
    return send_from_directory('.', 'signup.html')

@app.route('/login.html')
def static_login():
    return send_from_directory('.', 'login.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

@app.route('/verify/<path:filename>')
def serve_verify_files(filename):
    return send_from_directory('verify', filename)

@app.route('/home/<path:filename>')
def serve_home_files(filename):
    return send_from_directory('home', filename)

@app.route('/billing/<path:filename>')
def serve_billing_files(filename):
    return send_from_directory('billing', filename)

@app.route('/shared/<path:filename>')
def serve_shared_files(filename):
    return send_from_directory('shared', filename)

@app.route('/profile_uploads/<path:filename>')
def serve_profile_upload(filename):
    return send_from_directory(PROFILE_UPLOAD_DIR, filename)

# ================= AUTH =================
@app.route('/signup', methods=['POST'])
def handle_signup():
    try:
        data = request.get_json()

        full_name = data.get('fullname', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()

        if not full_name or not email or not password:
            return jsonify({'success': False, 'message': 'All fields required'}), 400

        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password too short'}), 400

        conn = get_db_connection()
        try:
            existing = conn.execute('SELECT email FROM users WHERE email = ?', (email,)).fetchone()
            if existing:
                return jsonify({'success': False, 'message': 'Email exists'}), 400

            conn.execute(
                'INSERT INTO users (email, fullname, password, credits) VALUES (?, ?, ?, ?)',
                (email, full_name, password, 100)
            )
            conn.commit()
        finally:
            conn.close()

        return jsonify({'success': True})

    except Exception as e:
        print("Signup error:", e)
        return jsonify({'success': False}), 500

@app.route('/login', methods=['POST'])
def handle_login():
    try:
        data = request.get_json()

        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()

        conn = get_db_connection()
        try:
            user = conn.execute(
                'SELECT fullname, password, credits FROM users WHERE email = ?',
                (email,)
            ).fetchone()
        finally:
            conn.close()

        if not user or user['password'] != password:
            return jsonify({'success': False}), 400

        return jsonify({
            'success': True,
            'fullname': user['fullname'],
            'credits': int(user['credits'] or 0)
        })

    except Exception as e:
        print("Login error:", e)
        return jsonify({'success': False}), 500

# ================= EMAIL VERIFY (UPGRADED) =================
def safe_validate(email):
    try:
        status, code, message = validate_email(email)

        if status == "Unknown":
            status = "Risky"
            message = "SMTP blocked"

        return {
            "status": status,
            "smtp_code": code,
            "message": message
        }
    except Exception as e:
        return {
            "status": "Error",
            "smtp_code": None,
            "message": str(e)
        }

@app.route('/verify-email', methods=['GET'])
def verify_email_api():
    email = request.args.get('email', '').strip()

    if not email:
        return jsonify({'status': 'Error', 'message': 'No email'}), 400

    future = executor.submit(safe_validate, email)

    try:
        result = future.result(timeout=25)  # 🔥 timeout protection
        return jsonify(result)

    except Exception:
        return jsonify({
            "status": "Timeout",
            "message": "Server busy"
        }), 500

# ================= SERVER =================
if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
