import re
import smtplib
import dns.resolver
import socket
import random
import string
import time
from time import sleep
import socks

# ================= CONFIG =================
SMTP_RETRIES = 2
NUM_FAKE_CHECKS = 3
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
]

WORKING_PROXIES = []

# ================= PROXY =================
def enable_proxy():
    if not RAW_PROXIES:
        return False

    host, port = random.choice(RAW_PROXIES)
    try:
        socks.set_default_proxy(socks.SOCKS5, host, port)
        socket.socket = socks.socksocket
        return True
    except:
        return False

def disable_proxy():
    socket.socket = socket.socket

# ================= CORE =================
def validate_email_format(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email)

def smtp_accepts(code):
    return code in (250, 251, 252)

def categorize(code, msg):
    msg = str(msg).lower()

    if code in (250, 251, 252):
        return "Valid"

    if "no such" in msg or "not exist" in msg or "user unknown" in msg:
        return "Bounce"

    return "Unknown"

def get_mx(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return str(records[0].exchange).rstrip('.')
    except:
        return None

# ================= SMTP =================
def smtp_check(mx, email, domain):
    for _ in range(SMTP_RETRIES):
        server = None
        enable_proxy()

        try:
            server = smtplib.SMTP(mx, timeout=8)
            server.ehlo()

            server.mail("test@" + domain)
            code, msg = server.rcpt(email)

            msg = msg.decode() if isinstance(msg, bytes) else str(msg)

            status = categorize(code, msg)

            # 🔥 Catch-all detection
            if ENABLE_CATCH_ALL_CHECK and smtp_accepts(code):
                fake = "random123@" + domain
                fake_code, _ = server.rcpt(fake)
                if smtp_accepts(fake_code):
                    return "Catch-All", code, msg

            return status, code, msg

        except Exception as e:
            sleep(1)

        finally:
            disable_proxy()
            if server:
                try:
                    server.quit()
                except:
                    pass

    # 🔥 FINAL FALLBACK (IMPORTANT)
    return "Valid", None, "SMTP blocked"

# ================= MAIN =================
def validate_email(email):
    if not validate_email_format(email):
        return "Invalid", None, "Bad format"

    domain = email.split("@")[1]

    mx = get_mx(domain)
    if not mx:
        return "Invalid", None, "No MX record"

    status, code, msg = smtp_check(mx, email, domain)

    # 🔥 NEVER RETURN UNKNOWN
    if status == "Unknown":
        return "Valid", code, "SMTP blocked"

    return status, code, msg
