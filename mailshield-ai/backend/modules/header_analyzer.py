import re
from .email_parser import extract_email_domain


def analyze_headers(parsed_email):
    """Analyze email headers for suspicious indicators."""
    headers = parsed_email.get('headers', {})
    basic = parsed_email.get('basic_info', {})
    analysis = {
        'findings': [],
        'risk_score': 0,
        'header_checks': [],
    }

    # Check Reply-To mismatch
    from_addr = basic.get('from', '')
    reply_to = basic.get('reply_to', '')
    return_path = basic.get('return_path', '')

    from_domain = extract_email_domain(from_addr)
    reply_to_domain = extract_email_domain(reply_to)
    return_path_domain = extract_email_domain(return_path)

    if reply_to and reply_to_domain and from_domain and reply_to_domain != from_domain:
        finding = {
            'type': 'REPLY_TO_MISMATCH',
            'severity': 'HIGH',
            'description': f'Reply-To domain ({reply_to_domain}) differs from sender domain ({from_domain})',
            'details': f'From: {from_addr} | Reply-To: {reply_to}',
        }
        analysis['findings'].append(finding)
        analysis['risk_score'] += 10

    if return_path and return_path_domain and from_domain and return_path_domain != from_domain:
        finding = {
            'type': 'RETURN_PATH_MISMATCH',
            'severity': 'MEDIUM',
            'description': f'Return-Path domain ({return_path_domain}) differs from sender domain ({from_domain})',
            'details': f'From: {from_addr} | Return-Path: {return_path}',
        }
        analysis['findings'].append(finding)
        analysis['risk_score'] += 5

    # Check for missing headers
    critical_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID']
    missing = [h for h in critical_headers if h.lower() not in {k.lower() for k in headers.keys()}]
    if missing:
        finding = {
            'type': 'MISSING_HEADERS',
            'severity': 'MEDIUM',
            'description': f'Missing critical email headers: {", ".join(missing)}',
            'details': 'Missing headers may indicate email tampering or non-standard email client.',
        }
        analysis['findings'].append(finding)
        analysis['risk_score'] += 5

    # Check Message-ID domain
    message_id = basic.get('message_id', '')
    if message_id:
        mid_match = re.search(r'@([a-zA-Z0-9.-]+)', message_id)
        if mid_match:
            mid_domain = mid_match.group(1)
            if from_domain and mid_domain != from_domain:
                finding = {
                    'type': 'MESSAGE_ID_MISMATCH',
                    'severity': 'LOW',
                    'description': f'Message-ID domain ({mid_domain}) differs from sender domain ({from_domain})',
                    'details': f'Message-ID: {message_id}',
                }
                analysis['findings'].append(finding)
                analysis['risk_score'] += 3

    # Check for suspicious X-Originating-IP
    x_origin_ip = basic.get('x_originating_ip', '')
    if x_origin_ip:
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', x_origin_ip)
        if ip_match:
            analysis['header_checks'].append({
                'header': 'X-Originating-IP',
                'value': x_origin_ip,
                'note': 'Originating IP address found in headers',
            })

    # Analyze Received headers for chain anomalies
    received_headers = headers.get_all('Received', []) if hasattr(headers, 'get_all') else [
        v for k, v in headers.items() if k.lower() == 'received'
    ]

    if len(received_headers) == 0:
        finding = {
            'type': 'NO_RECEIVED_HEADERS',
            'severity': 'MEDIUM',
            'description': 'No Received headers found in email',
            'details': 'Received headers are essential for tracing email path.',
        }
        analysis['findings'].append(finding)
        analysis['risk_score'] += 5

    # Check for X-Mailer anomalies
    x_mailer = basic.get('x_mailer', '')
    suspicious_mailers = ['phpmailer', 'mass mailer', 'bulk mail', 'mailer pro']
    if x_mailer:
        for sm in suspicious_mailers:
            if sm.lower() in x_mailer.lower():
                finding = {
                    'type': 'SUSPICIOUS_MAILER',
                    'severity': 'MEDIUM',
                    'description': f'Suspicious X-Mailer detected: {x_mailer}',
                    'details': 'Known bulk mailing or suspicious mailer software.',
                }
                analysis['findings'].append(finding)
                analysis['risk_score'] += 5
                break

    return analysis


def get_header_summary(parsed_email):
    """Get a summary of key headers for display."""
    basic = parsed_email.get('basic_info', {})
    return {
        'from': basic.get('from', 'N/A'),
        'to': basic.get('to', 'N/A'),
        'cc': basic.get('cc', 'N/A'),
        'subject': basic.get('subject', 'N/A'),
        'date': basic.get('date', 'N/A'),
        'reply_to': basic.get('reply_to', 'N/A'),
        'return_path': basic.get('return_path', 'N/A'),
        'message_id': basic.get('message_id', 'N/A'),
        'x_mailer': basic.get('x_mailer', 'N/A'),
    }
