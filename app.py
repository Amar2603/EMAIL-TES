from flask import Flask, request, redirect, url_for, send_from_directory, jsonify, render_template
import os
import sys
import sqlite3
from werkzeug.utils import secure_filename
from verify.singleemail import validate_email

app = Flask(__name__, template_folder='.')
DB_FILE = 'users.db'
PROFILE_UPLOAD_DIR = 'profile_uploads'
ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

# Print startup message
print("=" * 50)
print("Flask Server Starting...")
print("Go to: http://localhost:5000/login.html")
print("=" * 50)
sys.stdout.flush()

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(PROFILE_UPLOAD_DIR, exist_ok=True)
    conn = get_db_connection()
    try:
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                fullname TEXT NOT NULL,
                password TEXT NOT NULL,
                profile_image TEXT,
                credits INTEGER NOT NULL DEFAULT 100
            )
            '''
        )
        # Backward-compatible migration for older DBs.
        columns = [row['name'] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if 'profile_image' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN profile_image TEXT')
        if 'credits' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN credits INTEGER NOT NULL DEFAULT 100')
        conn.execute('UPDATE users SET credits = 100 WHERE credits IS NULL')
        conn.commit()
    finally:
        conn.close()

@app.route('/')
def home():
    return redirect(url_for('static_login'))

@app.route('/signup.html')
def static_signup():
    return send_from_directory('.', 'signup.html')

@app.route('/login.html')
def static_login():
    return send_from_directory('.', 'login.html')

@app.route('/style.css')
def static_css():
    return send_from_directory('.', 'style.css')

@app.route('/global.css')
def static_global_css():
    return send_from_directory('.', 'global.css')

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

@app.route('/signup', methods=['POST'])
def handle_signup():
    """Handle signup form submission"""
    print(f"Received signup request: {request.method}")
    sys.stdout.flush()
    
    try:
        data = request.get_json()
        print(f"Data received: {data}")
        sys.stdout.flush()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
        
        full_name = data.get('fullname', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        
        # Validation
        if not full_name or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        conn = get_db_connection()
        try:
            existing = conn.execute(
                'SELECT email FROM users WHERE email = ?',
                (email,)
            ).fetchone()
            if existing:
                return jsonify({'success': False, 'message': 'Email already registered'}), 400
            
            conn.execute(
                'INSERT INTO users (email, fullname, password, credits) VALUES (?, ?, ?, ?)',
                (email, full_name, password, 100)
            )
            conn.commit()
        finally:
            conn.close()
        
        print(f"User registered: {email}")
        sys.stdout.flush()
        
        return jsonify({'success': True, 'message': 'Account created successfully!'})
    
    except Exception as e:
        print(f"Error in signup: {str(e)}")
        sys.stdout.flush()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def handle_login():
    """Handle login form submission"""
    print(f"Received login request: {request.method}")
    sys.stdout.flush()
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        
        # Validation
        if not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        conn = get_db_connection()
        try:
            user = conn.execute(
                'SELECT fullname, password, credits FROM users WHERE email = ?',
                (email,)
            ).fetchone()
        finally:
            conn.close()
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 400
        
        if user['password'] != password:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 400
        
        print(f"User logged in: {email}")
        sys.stdout.flush()
        
        # Login successful
        return jsonify({
            'success': True,
            'message': 'Login successful!',
            'fullname': user['fullname'],
            'credits': int(user['credits'] or 0)
        })
    
    except Exception as e:
        print(f"Error in login: {str(e)}")
        sys.stdout.flush()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/profile', methods=['GET'])
def get_profile():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    conn = get_db_connection()
    try:
        user = conn.execute(
            'SELECT fullname, profile_image, credits FROM users WHERE email = ?',
            (email,)
        ).fetchone()
    finally:
        conn.close()

    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    image_url = None
    if user['profile_image']:
        image_url = '/profile_uploads/' + user['profile_image']

    return jsonify({
        'success': True,
        'fullname': user['fullname'],
        'profile_image_url': image_url,
        'credits': int(user['credits'] or 0)
    })

@app.route('/credits', methods=['GET'])
def get_credits():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    conn = get_db_connection()
    try:
        user = conn.execute(
            'SELECT credits FROM users WHERE email = ?',
            (email,)
        ).fetchone()
    finally:
        conn.close()

    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    return jsonify({
        'success': True,
        'credits': int(user['credits'] or 0)
    })

@app.route('/credits/spend', methods=['POST'])
def spend_credits():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    amount_raw = data.get('amount', 0)

    try:
        amount = int(amount_raw)
    except (TypeError, ValueError):
        amount = 0

    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400
    if amount <= 0:
        return jsonify({'success': False, 'message': 'Amount must be greater than 0'}), 400

    conn = get_db_connection()
    try:
        user = conn.execute('SELECT credits FROM users WHERE email = ?', (email,)).fetchone()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        current_credits = int(user['credits'] or 0)
        if current_credits < amount:
            return jsonify({
                'success': False,
                'message': 'Insufficient credits. Please buy credits to continue.',
                'credits': current_credits
            }), 400

        updated_credits = current_credits - amount
        conn.execute('UPDATE users SET credits = ? WHERE email = ?', (updated_credits, email))
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        'success': True,
        'credits': updated_credits
    })

@app.route('/credits/add', methods=['POST'])
def add_credits():
    return jsonify({
        'success': False,
        'message': 'Payment required. Credits can only be added after successful payment confirmation.'
    }), 403

@app.route('/upload-profile', methods=['POST'])
def upload_profile():
    email = request.form.get('email', '').strip().lower()
    image_file = request.files.get('profile')

    if not email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400
    if image_file is None or image_file.filename == '':
        return jsonify({'success': False, 'message': 'Profile image is required'}), 400

    ext = os.path.splitext(image_file.filename)[1].lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return jsonify({'success': False, 'message': 'Unsupported image format'}), 400

    conn = get_db_connection()
    try:
        user = conn.execute('SELECT email FROM users WHERE email = ?', (email,)).fetchone()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        safe_base = secure_filename(email.replace('@', '_at_').replace('.', '_'))
        filename = f'{safe_base}{ext}'
        file_path = os.path.join(PROFILE_UPLOAD_DIR, filename)
        image_file.save(file_path)

        conn.execute(
            'UPDATE users SET profile_image = ? WHERE email = ?',
            (filename, email)
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        'success': True,
        'message': 'Profile image updated successfully',
        'profile_image_url': '/profile_uploads/' + filename
    })

@app.route('/dashboard.html')
def dashboard():
    """Dashboard page after successful login"""
    return send_from_directory('.', 'dashboard.html')

@app.route('/home.html')
def home_page():
    """Home page with E-fy email verification service"""
    # Get username from query parameter (passed from login)
    username = request.args.get('username', 'User')
    return render_template('home.html', username=username)

@app.route('/emaildashboard/<path:filename>')
def serve_emaildashboard(filename):
    print(f"Serving file: {filename}")
    sys.stdout.flush()
    return send_from_directory('emaildashboard', filename)

@app.route('/test')
def test_route():
    return 'Server is working!'

    
    # Get the path to singleemail.py

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    try:
        if request.method == 'GET':
            email = request.args.get('email', '').strip()
        else:
            data = request.get_json()
            email = data.get('email', '').strip()

        if not email:
            return jsonify({
                'status': 'Error',
                'smtp_code': 'N/A',
                'message': 'No email provided'
            }), 400

        try:
            status, code, message = validate_email(email)

        except Exception as inner_error:
            print("SMTP ERROR:", inner_error)

            # 🔥 FALLBACK (IMPORTANT)
            return jsonify({
                'status': 'Valid',
                'smtp_code': None,
                'message': 'SMTP blocked / fallback'
            })

        # 🔥 HANDLE UNKNOWN
        if status == "Unknown":
            status = "Valid"
            message = "SMTP blocked (treated as valid)"

        return jsonify({
            'status': status,
            'smtp_code': code,
            'message': message
        })

    except Exception as e:
        print("API ERROR:", e)

        return jsonify({
            'status': 'Error',
            'smtp_code': 'N/A',
            'message': 'Internal server error'
        }), 500



if __name__ == '__main__':
    init_db()
    # Bind to all interfaces and enable debug
    app.run(host='0.0.0.0', port=5000, debug=True)
