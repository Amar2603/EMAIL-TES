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
NUM_FAKE_CHECKS = 3
SMTP_RETRIES = 5
ENABLE_CATCH_ALL_CHECK = False

def validate_email_format(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def generate_random_email(domain):
    local_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"{local_part}@{domain}"

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
    if code in (250, 251):
        return 'Valid'
    
    # Bounce/Invalid - Mailbox doesn't exist or rejected
    if code in (550, 551, 552, 553, 554, 555):
        return 'Bounce'
    if code >= 550:
        return 'Bounce'
    if any(x in message for x in ['5.1.0', '5.1.1', '5.1.2', '5.1.3', '5.1.4', '5.1.5', '5.1.6', '5.1.7', '5.1.8', '5.1.9',
                                   '5.2.0', '5.2.1', '5.2.2', '5.2.3', '5.2.4', '5.3.0', '5.4.0', '5.5.0', '5.6.0', '5.7.0',
                                   'user unknown', 'user not found', 'mailbox not found', 'no such user', 'does not exist',
                                   'invalid mailbox', 'mailbox unavailable', 'mailbox disabled', 'mailbox full',
                                   'quota exceeded', 'message rejected', 'access denied', 'relay denied']):
        return 'Bounce'
    
    # Bounce patterns - Enhanced detection
    bounce_keywords = [
        'user unknown', 'user not found', 'mailbox not found', 'no such user', 'no such address',
        'does not exist', 'not exist', 'address not found', 'recipient not found',
        'invalid mailbox', 'mailbox unavailable', 'mailbox disabled', 'mailbox disabled, not enabled',
        'mailbox full', 'quota exceeded', 'mailbox quota', 'storage quota',
        'message rejected', 'access denied', 'relay denied', 'relay access denied',
        'sender rejected', 'rcpt rejected', 'recipient rejected',
        'spam detected', 'spam rejected', 'blocked', 'blocked by',
        'suspicious', 'policy violation', 'policy reject',
        'domain not found', 'domain invalid', 'invalid domain',
        'alias not found', 'mailing list not found',
        'too large', 'message too big', 'size limit',
        'bad destination', 'bad address', 'routing error',
        'dns failure', 'dns error', 'host not found', 'no route to host',
        'system error', 'temporary error', 'permanent error',
        'exceeded', 'limit exceeded', 'rate limit',
        'account disabled', 'account expired', 'account inactive',
        'verify failed', 'validation failed', 'authentication required',
        'not authorized', 'permission denied', 'unauthorized',
        'disposable', 'throwaway', 'temporary address', 'fake email',
        'known spammer', 'blacklisted', 'blocklist', 'denylist',
        'handle unknown', 'invalid recipient', 'unknown recipient',
        'mail is denied', 'message denied', 'content rejected',
        'sorry', 'unable to deliver', 'cannot deliver', 'delivery failed',
        '550 5', '550-5', '5.0.0'
    ]
    
    if any(x in message for x in bounce_keywords):
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
    
    # Other server errors
    if code >= 500 and code < 550:
        return 'Unknown'
    
    # If we can't determine, return Unknown
    return 'Unknown'

def smtp_check(mx_record, email, domain):
    try:
        server = smtplib.SMTP(mx_record, timeout=30)
        server.helo()
        server.mail('test@example.com')
        code_real, msg_real = server.rcpt(email)
        decoded_msg_real = msg_real.decode() if isinstance(msg_real, bytes) else str(msg_real)

        # Catch-All Detection
        if ENABLE_CATCH_ALL_CHECK and code_real == 250:
            is_catch_all = True
            for _ in range(NUM_FAKE_CHECKS):
                fake_email = generate_random_email(domain)
                code_fake, _ = server.rcpt(fake_email)
                if code_fake != 250:
                    is_catch_all = False
                    break
            server.quit()
            return ('Catch-All' if is_catch_all else 'Valid'), code_real, decoded_msg_real

        result = categorize_smtp_response(code_real, decoded_msg_real)
        server.quit()
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
                if status == 'Valid':
                    return status, code, message
                elif status == 'Bounce':
                    return status, code, message
                # Only retry on connection errors, not on Unknown
                sleep(1)
        except Exception as e:
            pass
        
        # If SMTP fails, return syntax valid with domain info
        return 'Valid (Syntax)', None, f'Email format valid, domain resolved via {domain_info["type"]}'

    # Try SMTP validation with MX record
    for _ in range(SMTP_RETRIES):
        status, code, message = smtp_check(mx_record, email, domain)
        # Return actual SMTP results - don't fall back to Valid (Syntax)
        if status == 'Valid':
            return status, code, message
        elif status == 'Bounce':
            return status, code, message
        # If Unknown, return Unknown instead of falling back
        elif status == 'Unknown':
            return status, code, message
        sleep(1)

    # If SMTP fails completely, return Unknown
    return 'Unknown', None, 'SMTP validation failed - server not responding'


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
