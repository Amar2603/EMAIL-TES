import re
import smtplib
import dns.resolver
import socket
import random
import string
import json
from time import sleep
from flask import Flask, request, jsonify
import os

# Config
NUM_FAKE_CHECKS = 5
SMTP_RETRIES = 5
ENABLE_CATCH_ALL_CHECK = True
MAIL_FROM_CANDIDATES = (
    'postmaster@{domain}',
    'noreply@{domain}',
    'verify@{domain}',
    'test@example.com',
    '<>',
)

def validate_email_format(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def generate_random_email(domain):
    local_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"{local_part}@{domain}"

def smtp_accepts_recipient(code, message):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return False

    if isinstance(message, bytes):
        message = message.decode('utf-8', errors='ignore')
    message = str(message).lower()
    return code in (250, 251, 252) or '2.1.5' in message or 'recipient ok' in message

def smtp_accepts_sender(code, message):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return False

    if isinstance(message, bytes):
        message = message.decode('utf-8', errors='ignore')
    message = str(message).lower()
    return code in (250, 251, 252) or 'sender ok' in message or 'ok' == message.strip()

def establish_mail_from(server, domain):
    last_code = None
    last_message = 'MAIL FROM command was not accepted'

    for template in MAIL_FROM_CANDIDATES:
        sender = template.format(domain=domain)
        try:
            server.rset()
        except Exception:
            pass

        try:
            code, message = server.mail(sender)
            last_code, last_message = code, message
            if smtp_accepts_sender(code, message):
                return True, code, message
        except smtplib.SMTPException as e:
            last_message = str(e)
        except Exception as e:
            last_message = str(e)

    return False, last_code, last_message

def detect_catch_all(server, domain):
    accepted = 0

    for _ in range(NUM_FAKE_CHECKS):
        ready, _, _ = establish_mail_from(server, domain)
        if not ready:
            continue
        fake_email = generate_random_email(domain)
        code_fake, msg_fake = server.rcpt(fake_email)
        if smtp_accepts_recipient(code_fake, msg_fake):
            accepted += 1

    return accepted >= max(4, NUM_FAKE_CHECKS)

def validate_domain(domain):
    """Validate domain with multiple fallback methods and return record info."""
    errors = []
    
    # Try MX record first
    try:
        records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_record = str(records[0].exchange).rstrip('.')
        return {'type': 'MX', 'record': mx_record, 'errors': errors}
    except dns.resolver.NXDOMAIN:
        errors.append('MX: Domain does not exist (NXDOMAIN)')
    except dns.resolver.NoAnswer:
        errors.append('MX: No MX record found')
    except dns.resolver.Timeout:
        errors.append('MX: DNS query timeout')
    except Exception as e:
        errors.append(f'MX: {str(e)}')
    
    # Fallback: Try A record
    try:
        records = dns.resolver.resolve(domain, 'A', lifetime=5)
        a_record = str(records[0])
        return {'type': 'A', 'record': a_record, 'errors': errors}
    except dns.resolver.NXDOMAIN:
        errors.append('A: Domain does not exist (NXDOMAIN)')
    except dns.resolver.NoAnswer:
        errors.append('A: No A record found')
    except dns.resolver.Timeout:
        errors.append('A: DNS query timeout')
    except Exception as e:
        errors.append(f'A: {str(e)}')
    
    # Fallback: Try AAAA record (IPv6)
    try:
        records = dns.resolver.resolve(domain, 'AAAA', lifetime=5)
        aaaa_record = str(records[0])
        return {'type': 'AAAA', 'record': aaaa_record, 'errors': errors}
    except dns.resolver.NXDOMAIN:
        errors.append('AAAA: Domain does not exist (NXDOMAIN)')
    except dns.resolver.NoAnswer:
        errors.append('AAAA: No AAAA record found')
    except dns.resolver.Timeout:
        errors.append('AAAA: DNS query timeout')
    except Exception as e:
        errors.append(f'AAAA: {str(e)}')
    
    # Fallback: Try socket.gethostbyname (direct hostname resolution)
    try:
        ip_address = socket.gethostbyname(domain)
        return {'type': 'SOCKET', 'record': ip_address, 'errors': errors}
    except socket.gaierror as e:
        errors.append(f'SOCKET: {str(e)}')
    except Exception as e:
        errors.append(f'SOCKET: {str(e)}')
    
    # Fallback: Try NS record (to check if domain exists at all)
    try:
        records = dns.resolver.resolve(domain, 'NS', lifetime=5)
        ns_record = str(records[0])
        if ns_record:
            return {'type': 'NS', 'record': ns_record, 'errors': errors}
    except dns.resolver.NXDOMAIN:
        errors.append('NS: Domain does not exist (NXDOMAIN)')
    except dns.resolver.NoAnswer:
        errors.append('NS: No NS record found')
    except dns.resolver.Timeout:
        errors.append('NS: DNS query timeout')
    except Exception as e:
        errors.append(f'NS: {str(e)}')
    
    return None

def categorize_smtp_response(code, message):
    """Categorize SMTP response codes into Valid/Invalid/Bounce/Unknown"""
    if code is None:
        return 'Unknown'
    
    # Convert code to int if it's a string
    try:
        code = int(code)
    except (ValueError, TypeError):
        return 'Unknown'
    
    # Decode message if bytes
    if isinstance(message, bytes):
        message = message.decode('utf-8', errors='ignore')
    message = str(message).lower()
    
    # Valid responses
    if code in (250, 251, 252):
        return 'Valid'

    hard_bounce_keywords = [
        'user unknown', 'user not found', 'mailbox not found', 'no such user', 'no such address',
        'does not exist', 'not exist', 'address not found', 'recipient not found',
        'invalid mailbox', 'unknown recipient', 'invalid recipient', 'recipient unknown',
        '5.1.1', '5.1.0', '5.1.3', '5.1.6', '5.1.7', '5.1.10',
        'domain not found', 'domain invalid', 'invalid domain',
        'alias not found', 'mailing list not found', 'bad address'
    ]

    soft_failure_keywords = [
        'mailbox full', 'quota exceeded', 'mailbox quota', 'storage quota',
        'message rejected', 'access denied', 'relay denied', 'relay access denied',
        'sender rejected', 'rcpt rejected', 'recipient rejected',
        'spam detected', 'spam rejected', 'blocked', 'blocked by',
        'suspicious', 'policy violation', 'policy reject',
        'too large', 'message too big', 'size limit',
        'routing error', 'dns failure', 'dns error', 'host not found', 'no route to host',
        'system error', 'temporary error', 'rate limit', 'too many',
        'account disabled', 'account expired', 'account inactive',
        'verify failed', 'validation failed', 'authentication required',
        'not authorized', 'permission denied', 'unauthorized',
        'known spammer', 'blacklisted', 'blocklist', 'denylist',
        'mail is denied', 'message denied', 'content rejected',
        'greylist', 'greylisted', 'try again', 'please try', 'please wait',
        '421 ', '450 ', '451 ', '452 ', '4.2.', '4.3.', '4.4.', '4.7.'
    ]

    if any(x in message for x in soft_failure_keywords):
        return 'Unknown'

    if any(x in message for x in hard_bounce_keywords):
        return 'Bounce'

    # Treat only explicit hard failures as Bounce. Other 5xx errors are often policy blocks.
    if code in (550, 551, 553) and any(x in message for x in ('unknown', 'not found', 'does not exist', 'invalid', 'no such')):
        return 'Bounce'

    # Unknown - Server busy or temporary issues (greylisting)
    if code in (421, 450, 451, 452, 471, 472, 473, 474):
        greylist_patterns = ['try again', 'please try', 'greylist', 'greylisted', 
                             'defer', 'deferred', 'rate limit', 'too many', 'please wait']
        if any(x in message for x in greylist_patterns):
            return 'Unknown'
        return 'Unknown'
    
    if code >= 400 and code < 500:
        return 'Unknown'
    
    # Other server errors are ambiguous unless they clearly identify a bad mailbox.
    if code >= 500:
        if any(x in message for x in ['does not exist', 'no such user', '5.1.1']):
         return 'Bounce'
        return 'Unknown'
    
    # If we can't determine, return Unknown
    return 'Unknown'

def smtp_check(mx_record, email, domain):
    server = None
    try:
        server = smtplib.SMTP(mx_record, timeout=30)
        try:
            server.ehlo()
        except Exception:
            server.helo()

        mail_ready, mail_code, mail_msg = establish_mail_from(server, domain)
        if not mail_ready:
            decoded_mail_msg = mail_msg.decode('utf-8', errors='ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
            return 'Unknown', mail_code, f'MAIL FROM rejected: {decoded_mail_msg}'

        code_real, msg_real = server.rcpt(email)
        decoded_msg_real = msg_real.decode() if isinstance(msg_real, bytes) else str(msg_real)

        if code_real == 503 and 'need mail command' in decoded_msg_real.lower():
            mail_ready, mail_code, mail_msg = establish_mail_from(server, domain)
            if mail_ready:
                code_real, msg_real = server.rcpt(email)
                decoded_msg_real = msg_real.decode() if isinstance(msg_real, bytes) else str(msg_real)
            else:
                decoded_mail_msg = mail_msg.decode('utf-8', errors='ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
                return 'Unknown', mail_code, f'MAIL FROM rejected: {decoded_mail_msg}'

        # Catch-All Detection
        if ENABLE_CATCH_ALL_CHECK and smtp_accepts_recipient(code_real, decoded_msg_real):
            if detect_catch_all(server, domain):
                return 'Catch-All', code_real, f'{decoded_msg_real} | catch-all probe accepted'
            return 'Valid', code_real, decoded_msg_real

        result = categorize_smtp_response(code_real, decoded_msg_real)
        return result, code_real, decoded_msg_real

    except smtplib.SMTPServerDisconnected:
        return 'Unknown', None, 'Server disconnected - possibly blocking connections'
    except smtplib.SMTPConnectError:
        return 'Unknown', None, 'Connection error - server may be blocking'
    except smtplib.SMTPException as e:
        error_msg = str(e).lower()
        if 'timeout' in error_msg:
            return 'Unknown', None, 'Temporary server error - connection timeout'
        return 'Unknown', None, f'Temporary server error - {str(e)}'
    except TimeoutError:
        return 'Unknown', None, 'Connection timed out'
    except socket.timeout:
        return 'Unknown', None, 'Connection timed out'
    except Exception as e:
        error_msg = str(e).lower()
        if 'timeout' in error_msg:
            return 'Unknown', None, 'Connection timed out'
        elif 'connection' in error_msg:
            return 'Unknown', None, 'Connection failed - server may be blocking'
        else:
            return 'Unknown', None, str(e)
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass

def validate_email(email):
    # ---------------- FORMAT ----------------
    if not validate_email_format(email):
        return 'Invalid Format', None, 'Invalid email format'

    domain = email.split('@')[1]

    # ---------------- DNS CHECK ----------------
    domain_info = validate_domain(domain)
    if not domain_info:
        return 'Invalid Domain', None, 'Domain does not exist'

    mx_record = domain_info['record']

    # ---------------- SMART PROVIDER DETECTION ----------------
    popular_domains = [
        'gmail.com', 'yahoo.com', 'outlook.com',
        'hotmail.com', 'live.com', 'icloud.com'
    ]

    # ---------------- SMTP CHECK ----------------
    last_message = None

    try:
        for _ in range(3):
            status, code, message = smtp_check(mx_record, email, domain)

            if status in ('Valid', 'Catch-All'):
                return 'Valid', code, message

            if status == 'Bounce':
                return 'Bounce', code, message

            last_message = message
            sleep(1)

    except Exception as e:
        last_message = str(e)

    # ---------------- PRO FALLBACK ----------------

    if domain in popular_domains:
        return 'Valid', None, 'Trusted provider (SMTP blocked)'

    if domain_info:
        return 'Risky', None, last_message or 'SMTP blocked or no response'

    return 'Unknown', None, 'Could not verify'


app = Flask(__name__)

# ---------------- SINGLE EMAIL ----------------
@app.route('/verify-email', methods=['GET'])
def verify_email_api():
    email = request.args.get('email', '').strip()

    if not email:
        return jsonify({
            'status': 'Error',
            'smtp_code': None,
            'message': 'No email provided'
        }), 400

    status, code, message = validate_email(email)

    return jsonify({
        'status': status,
        'smtp_code': code,
        'message': message
    })


# ---------------- LIST EMAIL ----------------
@app.route('/verify-list', methods=['GET'])
def verify_list_api():
    emails_param = request.args.get('emails', '')
    emails = [e.strip() for e in emails_param.split(',') if e.strip()]

    if not emails:
        return jsonify({'error': 'No emails provided'}), 400

    results = []

    for email in emails:
        status, code, message = validate_email(email)
        results.append({
            'email': email,
            'status': status,
            'message': message
        })

    return jsonify({
        'results': results,
        'total': len(results)
    })


# ---------------- ROOT TEST ----------------
@app.route('/')
def home():
    return "Flask Email Validator Running 🚀"


# ---------------- RUN ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8001))
    print("="*60)
    print("Flask Email Verification Server Running 🚀")
    print("="*60)
    app.run(host='0.0.0.0', port=port)
