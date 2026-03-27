import re
import smtplib
import dns.resolver
import socket
import random
import string
import json
from time import sleep
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

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
    if not validate_email_format(email):
        return 'Invalid Format', None, 'Invalid email format'

    domain = email.split('@')[1]
    domain_info = validate_domain(domain)
    
    if not domain_info:
        return 'Invalid Domain', None, 'Invalid domain or no DNS record found'

    # Get the record for SMTP connection
    mx_record = domain_info['record']
    
    # If we only have domain_info['record a basic DNS record (not MX), we need special handling
    if domain_info['type'] != 'MX':
        # Try SMTP anyway with the IP or domain
        try:
            for _ in range(SMTP_RETRIES):
                status, code, message = smtp_check(mx_record, email, domain)
                # Return the actual SMTP result (Valid, Bounce, or Unknown)
                if status in ('Valid', 'Catch-All'):
                    return status, code, message
                elif status == 'Bounce':
                    return status, code, message
                # Only retry on connection errors, not on Unknown
                sleep(1)
        except Exception as e:
            pass
        
        # If SMTP fails, return syntax valid with domain info
        return 'Valid', None, f'Email format valid, domain resolved via {domain_info["type"]}'

    # Try SMTP validation with MX record
    last_unknown_message = None
    for _ in range(SMTP_RETRIES):
        status, code, message = smtp_check(mx_record, email, domain)
        if status in ('Valid', 'Catch-All'):
            return status, code, message
        elif status == 'Bounce':
            return status, code, message
        elif status == 'Unknown':
            last_unknown_message = message
            sleep(1)
            continue
        sleep(1)

    # Many providers block mailbox-level SMTP probing. If the domain has MX but
    # never gives a hard bounce, treat it as valid at the domain level.

    if last_unknown_message:
        # Detect bounce from message
        msg = last_unknown_message.lower()

        if "does not exist" in msg or "no such user" in msg or "5.1.1" in msg:
            return 'Bounce', None, last_unknown_message
    
        return 'Unknown', None, last_unknown_message

    return 'Unknown', None, 'Mailbox could not be confirmed'


# HTTP Request Handler
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
        
        # API: Verify single email
        if path == '/verify-email':
            email = query.get('email', [''])[0]
            if not email:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'Error', 'message': 'No email provided'}).encode())
                return
            
            status, code, message = validate_email(email)
            result = {
                'status': status,
                'smtp_code': code,
                'message': message
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        
        # API: Verify list of emails
        elif path == '/verify-list':
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
            for email in emails:
                status, code, message = validate_email(email)
                results.append({
                    'email': email,
                    'status': status,
                    'message': message
                })
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'results': results, 'total': len(results)}).encode())
        
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Not found'}).encode())
    
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

def run_server():
    port = 8001
    server = HTTPServer(('localhost', port), RequestHandler)
    print('='*60)
    print('E-fy Single Email Verification Server')
    print(f'Running at: http://localhost:{port}')
    print('='*60)
    print('Open your browser and go to: http://localhost:8001')
    print('='*60)
    server.serve_forever()

if __name__ == '__main__':
    run_server()
