import re
import socket
import struct


# Reserved IP ranges for private/internal addresses
PRIVATE_IP_RANGES = [
    (re.compile(r'^10\.'), 'Private (10.x.x.x)'),
    (re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'), 'Private (172.16-31.x.x)'),
    (re.compile(r'^192\.168\.'), 'Private (192.168.x.x)'),
    (re.compile(r'^127\.'), 'Loopback (127.x.x.x)'),
    (re.compile(r'^0\.'), 'Current Network'),
    (re.compile(r'^169\.254\.'), 'Link-Local (169.254.x.x)'),
    (re.compile(r'^224\.'), 'Multicast'),
    (re.compile(r'^255\.'), 'Broadcast'),
]

# Known suspicious IPs or ranges (placeholder for real threat intel)
SUSPICIOUS_IP_PATTERNS = [
    re.compile(r'^41\.168\.'),  # Known spam source ranges
    re.compile(r'^197\.210\.'),  # Common in phishing campaigns
]


def is_valid_ip(ip_str):
    """Validate an IPv4 address."""
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, AttributeError):
        return False


def get_ip_type(ip_address):
    """Classify IP address type."""
    for pattern, label in PRIVATE_IP_RANGES:
        if pattern.match(ip_address):
            return label
    return 'Public'


def extract_ips_from_text(text):
    """Extract all IPv4 addresses from text."""
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = ip_pattern.findall(text)
    return [ip for ip in ips if is_valid_ip(ip)]


def analyze_ip(ip_address, geo_data=None):
    """Analyze a single IP address for risk indicators."""
    result = {
        'ip_address': ip_address,
        'is_valid': is_valid_ip(ip_address),
        'ip_type': get_ip_type(ip_address),
        'country': 'Unknown',
        'city': 'Unknown',
        'isp': 'Unknown',
        'asn': 'Unknown',
        'latitude': None,
        'longitude': None,
        'risk_score': 0,
        'risk_level': 'LOW',
        'flags': [],
    }

    if not result['is_valid']:
        result['risk_score'] = 30
        result['risk_level'] = 'HIGH'
        result['flags'].append('INVALID_IP')
        return result

    # Check if IP is private (less risky but notable)
    if result['ip_type'] != 'Public':
        result['flags'].append('PRIVATE_IP')
        result['risk_score'] += 2
        result['risk_level'] = 'LOW'
        return result

    # Apply geo data if available
    if geo_data:
        result['country'] = geo_data.get('country', 'Unknown')
        result['city'] = geo_data.get('city', 'Unknown')
        result['isp'] = geo_data.get('isp', 'Unknown')
        result['asn'] = geo_data.get('asn', 'Unknown')
        result['latitude'] = geo_data.get('latitude')
        result['longitude'] = geo_data.get('longitude')

    # Check known suspicious patterns
    for pattern in SUSPICIOUS_IP_PATTERNS:
        if pattern.match(ip_address):
            result['flags'].append('KNOWN_SUSPICIOUS_RANGE')
            result['risk_score'] += 15
            break

    # Risk scoring
    result['risk_level'] = _score_to_level(result['risk_score'])

    return result


def analyze_ips(parsed_email):
    """Analyze all IPs found in the email headers."""
    headers = parsed_email.get('headers', {})
    basic = parsed_email.get('basic_info', {})

    # Collect IPs from headers
    all_ips = set()

    for key, value in headers.items():
        if isinstance(value, str):
            found = extract_ips_from_text(value)
            all_ips.update(found)

    # Also check X-Originating-IP
    x_orig_ip = basic.get('x_originating_ip', '')
    if x_orig_ip:
        found = extract_ips_from_text(x_orig_ip)
        all_ips.update(found)

    results = []
    for ip in sorted(all_ips):
        analysis = analyze_ip(ip)
        results.append(analysis)

    return {
        'ips': results,
        'total_ips': len(results),
        'public_ips': sum(1 for r in results if r['ip_type'] == 'Public'),
        'private_ips': sum(1 for r in results if r['ip_type'] != 'Public'),
    }


def reverse_dns_lookup(ip_address):
    """Perform reverse DNS lookup on an IP (non-blocking placeholder)."""
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _score_to_level(score):
    """Convert numeric score to risk level string."""
    if score >= 50:
        return 'CRITICAL'
    elif score >= 30:
        return 'HIGH'
    elif score >= 15:
        return 'MEDIUM'
    else:
        return 'LOW'
