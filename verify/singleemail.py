import re
import smtplib
import dns.resolver
import socket
import random
import string
import json
import time
from time import sleep
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import os
import socks

# ================= CONFIG =================
NUM_FAKE_CHECKS = 5
SMTP_RETRIES = 3
ENABLE_CATCH_ALL_CHECK = True

MAIL_FROM_CANDIDATES = (
    'postmaster@{domain}',
    'noreply@{domain}',
    'verify@{domain}',
    'test@example.com',
    '<>',
)

# ================= PROXIES =================
RAW_PROXIES = [
    ("86.53.183.16", 1080),
    ("47.77.193.180", 1080),
    ("103.17.246.60", 1080),
    ("64.227.76.27", 1080),
    ("194.67.99.223", 1080),
]

WORKING_PROXIES = []
BAD_PROXIES = set()

def test_proxy(host, port, timeout=5):
    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, host, port)
        s.settimeout(timeout)
        s.connect(("8.8.8.8", 53))
        s.close()
        return True
    except:
        return False

def load_working_proxies():
    print("[INFO] Testing proxies...")
    for host, port in RAW_PROXIES:
        if test_proxy(host, port):
            print(f"[OK] {host}:{port}")
            WORKING_PROXIES.append((host, port))
        else:
            print(f"[BAD] {host}:{port}")

def enable_proxy():
    if not WORKING_PROXIES:
        return False

    host, port = random.choice(WORKING_PROXIES)
    socks.set_default_proxy(socks.SOCKS5, host, port)
    socket.socket = socks.socksocket
    print(f"[PROXY] {host}:{port}")
    return True

def disable_proxy():
    socket.socket = socket._socketobject if hasattr(socket, "_socketobject") else socket.socket

# ================= CORE =================
def validate_email_format(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email)

def generate_random_email(domain):
    return ''.join(random.choices(string.ascii_lowercase, k=8)) + '@' + domain

def smtp_accepts_recipient(code):
    return code in (250, 251, 252)

def establish_mail_from(server, domain):
    for sender in MAIL_FROM_CANDIDATES:
        try:
            server.mail(sender.format(domain=domain))
            return True
        except:
            continue
    return False

def detect_catch_all(server, domain):
    count = 0
    for _ in range(NUM_FAKE_CHECKS):
        fake = generate_random_email(domain)
        code, _ = server.rcpt(fake)
        if smtp_accepts_recipient(code):
            count += 1
    return count >= 4

def categorize(code, msg):
    msg = str(msg).lower()

    if code in (250, 251, 252):
        return "Valid"

    if "not exist" in msg or "no such" in msg or "user unknown" in msg:
        return "Bounce"

    return "Unknown"

def validate_domain(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return str(records[0].exchange).rstrip('.')
    except:
        return None

# ================= SMTP CHECK =================
def smtp_check(mx, email, domain):
    for attempt in range(SMTP_RETRIES):
        use_proxy = enable_proxy()
        server = None

        try:
            server = smtplib.SMTP(mx, timeout=20)
            server.ehlo()

            if not establish_mail_from(server, domain):
                continue

            code, msg = server.rcpt(email)
            msg = msg.decode() if isinstance(msg, bytes) else str(msg)

            if ENABLE_CATCH_ALL_CHECK and smtp_accepts_recipient(code):
                if detect_catch_all(server, domain):
                    return "Catch-All", code, msg

            return categorize(code, msg), code, msg

        except Exception as e:
            print("[ERROR]", e)
            sleep(1)

        finally:
            disable_proxy()
            if server:
                try:
                    server.quit()
                except:
                    pass

    return "Unknown", None, "Failed after retries"

# ================= MAIN VALIDATOR =================
def validate_email(email):
    if not validate_email_format(email):
        return "Invalid", None, "Bad format"

    domain = email.split('@')[1]
    mx = validate_domain(domain)

    if not mx:
        return "Invalid Domain", None, "No MX"

    return smtp_check(mx, email, domain)

# ================= API =================
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/verify-email":
            email = query.get("email", [""])[0]

            status, code, msg = validate_email(email)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            self.wfile.write(json.dumps({
                "email": email,
                "status": status,
                "code": code,
                "message": msg
            }).encode())

        elif path == "/verify-list":
            emails = query.get("emails", [""])[0].split(",")

            results = []

            for e in emails:
                e = e.strip()
                if not e:
                    continue

                status, code, msg = validate_email(e)

                results.append({
                    "email": e,
                    "status": status
                })

                sleep(random.uniform(1.5, 3))  # anti-block

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            self.wfile.write(json.dumps({
                "results": results,
                "total": len(results)
            }).encode())

        else:
            self.send_response(404)
            self.end_headers()

# ================= SERVER =================
def run():
    port = int(os.environ.get("PORT", 8001))
    server = HTTPServer(("0.0.0.0", port), Handler)

    print("="*50)
    print("EMAIL VERIFIER SERVER RUNNING")
    print(f"http://localhost:{port}")
    print("="*50)

    server.serve_forever()

# ================= START =================
if __name__ == "__main__":
    load_working_proxies()
    run()
