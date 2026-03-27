from flask import Flask, request, jsonify
import re
import smtplib
import dns.resolver
import socket
import random
import string
from time import sleep
import os

app = Flask(__name__)

# ---------------- CONFIG ----------------
SMTP_RETRIES = 3
NUM_FAKE_CHECKS = 3

# ---------------- VALIDATION ----------------

def validate_email_format(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def validate_domain(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        return {'type': 'MX', 'record': str(records[0].exchange).rstrip('.')}
    except:
        try:
            records = dns.resolver.resolve(domain, 'A', lifetime=5)
            return {'type': 'A', 'record': str(records[0])}
        except:
            return None


def smtp_check(mx_record, email, domain):
    try:
        server = smtplib.SMTP(mx_record, timeout=10)
        server.helo()
        server.mail('test@example.com')
        code, message = server.rcpt(email)
        server.quit()

        msg = str(message).lower()

        if code == 250:
            return 'Valid', code, msg

        if code == 550 or "does not exist" in msg or "no such user" in msg:
            return 'Bounce', code, msg

        return 'Valid', code, "Server protected"

    except Exception as e:
        return 'Risky', None, "SMTP blocked / no response"


def validate_email(email):

    if not validate_email_format(email):
        return 'Invalid Format', None, 'Invalid email format'

    domain = email.split('@')[1]

    domain_info = validate_domain(domain)
    if not domain_info:
        return 'Invalid Domain', None, 'Domain not found'

    # SMTP try
    if domain_info['type'] == 'MX':
        for _ in range(SMTP_RETRIES):
            status, code, message = smtp_check(domain_info['record'], email, domain)

            if status == 'Valid':
                return status, code, message

            if status == 'Bounce':
                return status, code, message

    # fallback
    SAFE_PROVIDERS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

    if domain in SAFE_PROVIDERS:
        return 'Valid', None, 'Valid (provider protected)'

    return 'Risky', None, 'Mailbox cannot be verified'


# ---------------- ROUTES ----------------

@app.route('/verify-email')
def verify_email():
    email = request.args.get('email')

    if not email:
        return jsonify({'status': 'Error', 'message': 'No email provided'}), 400

    status, code, message = validate_email(email)

    return jsonify({
        'status': status,
        'smtp_code': code,
        'message': message
    })


@app.route('/verify-list')
def verify_list():
    emails_param = request.args.get('emails', '')
    emails = [e.strip() for e in emails_param.split(',') if e.strip()]

    results = []

    for email in emails:
        status, code, message = validate_email(email)
        results.append({
            'email': email,
            'status': status,
            'message': message
        })

    return jsonify({
        'total': len(results),
        'results': results
    })


# ---------------- RUN ----------------

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
