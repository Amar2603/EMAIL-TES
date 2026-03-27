from flask import Flask, request, redirect, url_for, send_from_directory, jsonify, render_template
import os
import sys
import sqlite3
from werkzeug.utils import secure_filename

# 🔥 IMPORT YOUR VALIDATOR DIRECTLY (IMPORTANT)
from verify.singleemail import validate_email

app = Flask(__name__, template_folder='.')

DB_FILE = 'users.db'
PROFILE_UPLOAD_DIR = 'profile_uploads'
ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

print("=" * 50)
print("Flask Server Starting...")
print("=" * 50)

# ---------------- DATABASE ----------------

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
        conn.commit()
    finally:
        conn.close()

# ---------------- STATIC ROUTES ----------------

@app.route('/')
def home():
    return redirect(url_for('static_login'))

@app.route('/signup.html')
def static_signup():
    return send_from_directory('.', 'signup.html')

@app.route('/login.html')
def static_login():
    return send_from_directory('.', 'login.html')

@app.route('/verify/<path:filename>')
def serve_verify_files(filename):
    return send_from_directory('verify', filename)


# ---------------- AUTH ----------------

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    email = data.get('email').lower()
    fullname = data.get('fullname')
    password = data.get('password')

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (email, fullname, password, credits) VALUES (?, ?, ?, ?)",
            (email, fullname, password, 100)
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({'success': True})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email').lower()
    password = data.get('password')

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    if not user or user['password'] != password:
        return jsonify({'success': False})

    return jsonify({
        'success': True,
        'fullname': user['fullname'],
        'credits': user['credits']
    })

# ---------------- EMAIL VERIFY (🔥 FIXED) ----------------

@app.route('/verify-email', methods=['GET'])
def verify_email_api():
    email = request.args.get('email', '').strip()

    if not email:
        return jsonify({
            'status': 'Error',
            'smtp_code': None,
            'message': 'No email provided'
        }), 400

    try:
        status, code, message = validate_email(email)

        # 🔥 REMOVE UNKNOWN COMPLETELY
        if status == "Unknown":
            status = "Risky"
            message = "Converted from unknown"

        return jsonify({
            'status': status,
            'smtp_code': code,
            'message': message
        })

    except Exception as e:
        return jsonify({
            'status': 'Error',
            'smtp_code': None,
            'message': str(e)
        }), 500

# ---------------- TEST ----------------

@app.route('/test')
def test():
    return "Server working ✅"

# ---------------- RUN ----------------

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
