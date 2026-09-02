import email
import hashlib
import os
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser


class SafeHTMLTextExtractor(HTMLParser):
    """Safely extract text from HTML without executing scripts."""
    def __init__(self):
        super().__init__()
        self.result = []
        self.skip_tags = {'script', 'style', 'noscript'}

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.skip_tags:
            self.skip_tags.add(tag.lower())

    def handle_endtag(self, tag):
        if tag.lower() in self.skip_tags:
            self.skip_tags.discard(tag.lower())

    def handle_data(self, data):
        if not self.skip_tags:
            self.result.append(data)

    def get_text(self):
        return ' '.join(self.result).strip()


def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file for evidence integrity."""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def parse_eml_file(file_path):
    """Parse an .eml file and extract email information."""
    result = {
        'basic_info': {},
        'headers': {},
        'body': {'plain': '', 'html': '', 'text': ''},
        'attachments': [],
    }

    with open(file_path, 'rb') as f:
        msg = policy.default.parser().parse(f)

    # Basic email fields
    result['basic_info'] = {
        'from': msg.get('From', ''),
        'to': msg.get('To', ''),
        'cc': msg.get('Cc', ''),
        'bcc': msg.get('Bcc', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'reply_to': msg.get('Reply-To', ''),
        'return_path': msg.get('Return-Path', ''),
        'message_id': msg.get('Message-ID', ''),
        'mime_type': msg.get_content_type(),
        'x_mailer': msg.get('X-Mailer', ''),
        'x_originating_ip': msg.get('X-Originating-IP', ''),
    }

    # Extract all headers
    for header_key, header_value in msg.items():
        result['headers'][header_key] = header_value

    # Extract body content
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))

            # Skip attachments
            if 'attachment' in content_disposition:
                filename = part.get_filename()
                if filename:
                    result['attachments'].append({
                        'filename': filename,
                        'content_type': content_type,
                        'size': len(part.get_payload(decode=True) or b''),
                    })
                continue

            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        result['body']['plain'] += payload.decode(charset, errors='replace')
                    except (LookupError, UnicodeDecodeError):
                        result['body']['plain'] += payload.decode('utf-8', errors='replace')

            elif content_type == 'text/html':
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        html_content = payload.decode(charset, errors='replace')
                    except (LookupError, UnicodeDecodeError):
                        html_content = payload.decode('utf-8', errors='replace')
                    result['body']['html'] += html_content
                    # Extract safe text from HTML
                    extractor = SafeHTMLTextExtractor()
                    try:
                        extractor.feed(html_content)
                        result['body']['text'] += extractor.get_text()
                    except Exception:
                        pass
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            try:
                content = payload.decode(charset, errors='replace')
            except (LookupError, UnicodeDecodeError):
                content = payload.decode('utf-8', errors='replace')

            if content_type == 'text/plain':
                result['body']['plain'] = content
                result['body']['text'] = content
            elif content_type == 'text/html':
                result['body']['html'] = content
                extractor = SafeHTMLTextExtractor()
                try:
                    extractor.feed(content)
                    result['body']['text'] = extractor.get_text()
                except Exception:
                    result['body']['text'] = content

    # Create a full text representation for analysis
    full_text = result['body']['plain'] or result['body']['text']
    result['body']['full_text'] = full_text

    return result


def extract_email_domain(email_address):
    """Extract domain from email address."""
    if not email_address:
        return ''
    match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
    return match.group(1).lower() if match else ''


def extract_ips_from_headers(headers):
    """Extract IP addresses from email headers."""
    ips = set()
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    for key, value in headers.items():
        if isinstance(value, str):
            found = ip_pattern.findall(value)
            ips.update(found)

    return list(ips)


def extract_received_headers(headers):
    """Extract Received headers in order."""
    received = []
    for key, value in headers.items():
        if key.lower() == 'received':
            received.append(value)
    return received
