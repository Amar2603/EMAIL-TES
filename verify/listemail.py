import re
import smtplib
import dns.resolver
import random
import string
import json
from time import sleep
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import os

# Config
NUM_FAKE_CHECKS = 5
SMTP_RETRIES = 3
ENABLE_CATCH_ALL_CHECK = True

# List of common disposable email domains for additional check
DISPOSABLE_DOMAINS = {
    '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'temp-mail.org',
    'throwaway.email', 'yopmail.com', 'maildrop.cc', 'tempail.com', 'dispostable.com'
}


def validate_email_format(email):
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def generate_random_email(domain):
    local_part = ''.join(random.choices(string.ascii_lowercase + string.digits + '._-', k=random.randint(8, 12)))
    return f"{local_part}@{domain}"


def validate_domain(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX', lifetime=10)
        if not records:
            return None
        mx_records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in records])
        return mx_records[0][1] if mx_records else None
    except Exception:
        return None


def categorize_smtp_response(code, message):
    if code is None:
        return 'Unknown'
    if isinstance(message, bytes):
        message = message.decode('utf-8', errors='ignore')
    message = str(message)
    if code in (250, 251, 252):
        return 'Valid'
    elif code in (550, 551, 552, 553, 554, 555) or '5.1.1' in message or '5.1.10' in message or 'user unknown' in message.lower():
        return 'Bounce'
    elif code in (421, 450, 451, 452, 454) or 400 <= code <= 499:
        return 'Unknown'
    elif 500 <= code <= 504:
        return 'Unknown'
    return 'Unknown'


def smtp_check(mx_record, email, domain):
    try:
        server = smtplib.SMTP(mx_record, timeout=15)
        server.starttls()
        server.helo()
        server.mail('test@example.com')
        code_real, msg_real = server.rcpt(email)
        decoded_msg_real = msg_real.decode() if isinstance(msg_real, bytes) else str(msg_real)

        if ENABLE_CATCH_ALL_CHECK and code_real == 250:
            is_catch_all = True
            fake_checks = 0
            while fake_checks < NUM_FAKE_CHECKS and is_catch_all:
                fake_email = generate_random_email(domain)
                try:
                    code_fake, _ = server.rcpt(fake_email)
                    if code_fake != 250:
                        is_catch_all = False
                except Exception:
                    is_catch_all = False
                fake_checks += 1
            server.quit()
            return ('Catch-All' if is_catch_all else 'Valid'), code_real, decoded_msg_real

        result = categorize_smtp_response(code_real, decoded_msg_real)
        server.quit()
        return result, code_real, decoded_msg_real
    except smtplib.SMTPConnectError:
        return 'Unknown', None, 'SMTP connection failed'
    except smtplib.SMTPAuthenticationError:
        return 'Unknown', None, 'SMTP authentication failed'
    except smtplib.SMTPException as e:
        return 'Unknown', None, f'SMTP error: {str(e)}'
    except Exception as e:
        return 'Unknown', None, str(e)


def validate_email(email):
    if not validate_email_format(email):
        return 'Invalid Format', None, 'Invalid email format'

    domain = email.split('@')[1].lower()
    if domain in DISPOSABLE_DOMAINS:
        return 'Bounce', None, 'Disposable email domain'

    mx_record = validate_domain(domain)
    if not mx_record:
        return 'Invalid Domain', None, 'Invalid domain or no MX record'

    for attempt in range(SMTP_RETRIES):
        status, code, message = smtp_check(mx_record, email, domain)
        if status not in ('Unknown', 'Invalid Format', 'Invalid Domain'):
            return status, code, message
        sleep(2 ** attempt)

    return 'Unknown', None, 'SMTP failed after retries'


class RequestHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)

        if path == '/verify-list':
            emails_param = query.get('emails', [''])[0]
            emails = [e.strip() for e in emails_param.split(',') if e.strip()]

            if not emails:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'No emails provided'}).encode())
                return

            results = []
            valid_count = 0
            invalid_count = 0
            risky_count = 0

            for email in emails:
                status, code, message = validate_email(email)
                if status == 'Valid':
                    valid_count += 1
                elif status in ('Bounce', 'Invalid Domain', 'Invalid Format'):
                    invalid_count += 1
                else:
                    risky_count += 1

                results.append({
                    'email': email,
                    'status': status,
                    'message': message
                })

            total = len(results)
            summary = {
                'valid': valid_count,
                'invalid': invalid_count,
                'risky': risky_count,
                'valid_percent': round((valid_count / total) * 100) if total else 0,
                'invalid_percent': round((invalid_count / total) * 100) if total else 0,
                'risky_percent': round((risky_count / total) * 100) if total else 0
            }

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                'results': results,
                'total': total,
                'summary': summary
            }).encode())
            return

        self.send_response(404)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({'error': 'Not found'}).encode())

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


def run_server():
    port = int(os.environ.get("PORT", 8002))
    server = HTTPServer(('0.0.0.0', port), RequestHandler)
    print('=' * 60)
    print('E-fy List Email Verification Server')
    print(f'Running at: http://localhost:{port}')
    print('=' * 60)
    print('Use port 8002 for bulk email verification')
    print('=' * 60)
    server.serve_forever()


if __name__ == '__main__':
    run_server()
