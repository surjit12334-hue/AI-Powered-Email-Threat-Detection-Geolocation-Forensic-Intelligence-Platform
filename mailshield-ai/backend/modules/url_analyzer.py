import re
from urllib.parse import urlparse
from config import SUSPICIOUS_TLDS, SUSPICIOUS_URL_KEYWORDS, PHISHING_KEYWORDS


def extract_urls(text):
    """Extract all URLs from text content."""
    url_pattern = re.compile(
        r'https?://(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*(?:/[^\s<>\"\']*)?',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)
    return list(set(urls))


def analyze_url(url):
    """Analyze a single URL for suspicious characteristics."""
    result = {
        'url': url,
        'domain': '',
        'tld': '',
        'risk_score': 0,
        'risk_level': 'LOW',
        'flags': [],
        'details': {},
    }

    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ''
        result['domain'] = domain
        path = parsed.path or ''

        # Extract TLD
        parts = domain.split('.')
        if len(parts) >= 2:
            result['tld'] = '.' + parts[-1]

        # Check for IP address instead of domain
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        if ip_pattern.match(domain):
            result['flags'].append('IP_ADDRESS_INSTEAD_OF_DOMAIN')
            result['risk_score'] += 25

        # Check URL length
        if len(url) > 200:
            result['flags'].append('EXCESSIVELY_LONG_URL')
            result['risk_score'] += 10
        elif len(url) > 100:
            result['flags'].append('LONG_URL')
            result['risk_score'] += 5

        # Check for suspicious TLD
        if result['tld'].lower() in SUSPICIOUS_TLDS:
            result['flags'].append('SUSPICIOUS_TLD')
            result['risk_score'] += 15

        # Check for suspicious keywords in URL
        url_lower = url.lower()
        for keyword in SUSPICIOUS_URL_KEYWORDS:
            if keyword in url_lower:
                result['flags'].append(f'SUSPICIOUS_KEYWORD:{keyword.upper()}')
                result['risk_score'] += 10
                break

        # Check for excessive subdomains
        subdomain_count = len(parts) - 2
        if subdomain_count > 3:
            result['flags'].append('EXCESSIVE_SUBDOMAINS')
            result['risk_score'] += 15
        elif subdomain_count > 2:
            result['flags'].append('MULTIPLE_SUBDOMAINS')
            result['risk_score'] += 5

        # Check for @ sign (URL obfuscation)
        if '@' in url:
            result['flags'].append('AT_SIGN_OBFUSCATION')
            result['risk_score'] += 20

        # Check for double slashes in path
        if '//' in path and not url.startswith('http://'):
            result['flags'].append('DOUBLE_SLASH_IN_PATH')
            result['risk_score'] += 10

        # Check for URL encoding abuse
        percent_count = url.count('%')
        if percent_count > 5:
            result['flags'].append('URL_ENCODING_ABUSE')
            result['risk_score'] += 15

        # Check for punycode (IDN homograph attacks)
        if 'xn--' in domain:
            result['flags'].append('PUNYCODE_DOMAIN')
            result['risk_score'] += 20

        # Check for dash-heavy domains (often used in phishing)
        if domain.count('-') > 3:
            result['flags'].append('DASH_HEAVY_DOMAIN')
            result['risk_score'] += 10

        # Check for port numbers (unusual ports)
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            result['flags'].append('UNUSUAL_PORT')
            result['risk_score'] += 10

        # Check for data: or javascript: schemes
        if parsed.scheme in ['data', 'javascript', 'vbscript']:
            result['flags'].append('DANGEROUS_SCHEME')
            result['risk_score'] += 30

        # Domain similarity check with known brands
        known_brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon',
                        'facebook', 'netflix', 'chase', 'wellsfargo', 'dropbox']
        for brand in known_brands:
            if brand in domain and not domain.endswith(f'{brand}.com'):
                result['flags'].append(f'BRAND_IMPERSONATION:{brand.upper()}')
                result['risk_score'] += 20
                break

        # Calculate risk level
        result['risk_level'] = _score_to_level(result['risk_score'])

    except Exception as e:
        result['flags'].append(f'PARSE_ERROR:{str(e)}')
        result['risk_score'] += 5
        result['risk_level'] = 'UNKNOWN'

    return result


def analyze_urls(parsed_email):
    """Analyze all URLs found in an email."""
    body = parsed_email.get('body', {})
    text = body.get('full_text', '')
    html = body.get('html', '')

    # Extract URLs from both plain text and HTML
    urls_from_text = extract_urls(text)
    urls_from_html = extract_urls(html)
    all_urls = list(set(urls_from_text + urls_from_html))

    results = []
    total_risk = 0
    suspicious_count = 0

    for url in all_urls:
        analysis = analyze_url(url)
        results.append(analysis)
        total_risk += analysis['risk_score']
        if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
            suspicious_count += 1

    avg_risk = total_risk / len(results) if results else 0

    return {
        'urls': results,
        'total_urls': len(results),
        'suspicious_urls': suspicious_count,
        'average_risk_score': round(avg_risk, 2),
        'overall_risk_level': _score_to_level(avg_risk),
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
