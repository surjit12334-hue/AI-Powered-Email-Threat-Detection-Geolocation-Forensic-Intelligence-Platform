import re
from urllib.parse import urlparse
from config import SUSPICIOUS_TLDS


# Known suspicious domain patterns
SUSPICIOUS_DOMAIN_PATTERNS = [
    (re.compile(r'\d{5,}'), 'NUMERIC_HEAVY'),
    (re.compile(r'^(?:[a-z]\.){3,}', re.IGNORECASE), 'EXCESSIVE_SINGLE_CHAR_SUBDOMAINS'),
    (re.compile(r'(?:login|verify|secure|account|update|confirm|banking)', re.IGNORECASE), 'PHISHING_KEYWORD'),
]


def extract_domain_from_email(email_address):
    """Extract domain from an email address."""
    if not email_address:
        return ''
    match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
    return match.group(1).lower() if match else ''


def analyze_domain(domain, sender_domain=None):
    """Analyze a domain for suspicious characteristics."""
    result = {
        'domain': domain,
        'tld': '',
        'risk_score': 0,
        'risk_level': 'LOW',
        'flags': [],
        'details': {},
    }

    if not domain:
        result['risk_level'] = 'UNKNOWN'
        return result

    # Extract TLD
    parts = domain.split('.')
    if len(parts) >= 2:
        result['tld'] = '.' + parts[-1]

    # Check suspicious TLDs
    if result['tld'].lower() in SUSPICIOUS_TLDS:
        result['flags'].append('SUSPICIOUS_TLD')
        result['risk_score'] += 15

    # Check domain length
    if len(domain) > 50:
        result['flags'].append('LONG_DOMAIN')
        result['risk_score'] += 10

    # Check for excessive dashes
    if domain.count('-') > 3:
        result['flags'].append('DASH_HEAVY')
        result['risk_score'] += 10
    elif domain.count('-') > 2:
        result['flags'].append('MULTIPLE_DASHES')
        result['risk_score'] += 5

    # Check suspicious patterns
    for pattern, flag in SUSPICIOUS_DOMAIN_PATTERNS:
        if pattern.search(domain):
            result['flags'].append(flag)
            result['risk_score'] += 10

    # Check for punycode
    if 'xn--' in domain:
        result['flags'].append('PUNYCODE')
        result['risk_score'] += 20

    # Check for brand impersonation
    known_brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon',
                    'facebook', 'netflix', 'chase', 'wellsfargo', 'dropbox',
                    'linkedin', 'twitter', 'instagram', 'yahoo', 'aol']
    for brand in known_brands:
        if brand in domain and not domain.endswith(f'{brand}.com'):
            result['flags'].append(f'BRAND_IMPERSONATION:{brand.upper()}')
            result['risk_score'] += 20
            break

    # Check for IP in domain (not already handled)
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    if ip_pattern.match(domain):
        result['flags'].append('IP_AS_DOMAIN')
        result['risk_score'] += 25

    # Check if domain matches sender domain
    if sender_domain and domain != sender_domain:
        result['flags'].append('DOMAIN_MISMATCH_WITH_SENDER')
        result['risk_score'] += 5

    # Check for numeric-only second level domain
    sld = parts[-2] if len(parts) >= 2 else ''
    if sld and sld.isdigit():
        result['flags'].append('NUMERIC_SLD')
        result['risk_score'] += 10

    result['risk_level'] = _score_to_level(result['risk_score'])
    return result


def analyze_domains(parsed_email, url_analysis_results):
    """Analyze all domains found in the email."""
    basic = parsed_email.get('basic_info', {})
    sender_domain = extract_domain_from_email(basic.get('from', ''))

    domains = {}

    # Add sender domain
    if sender_domain:
        domains[sender_domain] = 'sender'

    # Add domains from URL analysis
    for url_result in url_analysis_results.get('urls', []):
        domain = url_result.get('domain', '')
        if domain and domain not in domains:
            domains[domain] = 'url'

    results = []
    for domain, source in domains.items():
        analysis = analyze_domain(domain, sender_domain)
        analysis['source'] = source
        results.append(analysis)

    return {
        'domains': results,
        'total_domains': len(results),
        'sender_domain': sender_domain,
    }


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
