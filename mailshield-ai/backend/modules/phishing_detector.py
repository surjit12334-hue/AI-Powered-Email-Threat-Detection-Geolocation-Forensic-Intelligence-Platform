import re
from config import PHISHING_KEYWORDS


def extract_features(parsed_email, url_analysis, ip_analysis, auth_analysis, domain_analysis):
    """Extract features for phishing detection from email analysis results."""
    basic = parsed_email.get('basic_info', {})
    body = parsed_email.get('body', {})
    full_text = body.get('full_text', '').lower()
    subject = basic.get('subject', '').lower()

    features = {
        'subject_length': len(basic.get('subject', '')),
        'body_length': len(full_text),
        'url_count': url_analysis.get('total_urls', 0),
        'suspicious_url_count': url_analysis.get('suspicious_urls', 0),
        'ip_count': ip_analysis.get('total_ips', 0),
        'domain_count': domain_analysis.get('total_domains', 0),
        'spf_fail': 1 if auth_analysis.get('spf', {}).get('status') == 'FAIL' else 0,
        'dkim_fail': 1 if auth_analysis.get('dkim', {}).get('status') == 'FAIL' else 0,
        'dmarc_fail': 1 if auth_analysis.get('dmarc', {}).get('status') == 'FAIL' else 0,
        'has_reply_to_mismatch': 0,
        'has_html': 1 if body.get('html') else 0,
        'attachment_count': len(parsed_email.get('attachments', [])),
        'urgency_score': 0,
        'phishing_keyword_count': 0,
        'caps_ratio': 0,
        'exclamation_count': 0,
        'dollar_sign_count': 0,
    }

    # Check for Reply-To mismatch
    headers = parsed_email.get('headers', {})
    from_domain = ''
    reply_to_domain = ''
    from_match = re.search(r'@([a-zA-Z0-9.-]+)', basic.get('from', ''))
    reply_match = re.search(r'@([a-zA-Z0-9.-]+)', basic.get('reply_to', ''))
    if from_match:
        from_domain = from_match.group(1).lower()
    if reply_match:
        reply_to_domain = reply_match.group(1).lower()
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        features['has_reply_to_mismatch'] = 1

    # Count phishing keywords
    combined_text = subject + ' ' + full_text
    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in combined_text:
            features['phishing_keyword_count'] += 1

    # Urgency indicators
    urgency_patterns = [
        r'urgent', r'immediate', r'act now', r'right away',
        r'within \d+ hours', r'expires? (?:today|soon|tomorrow)',
        r'last chance', r'do not ignore', r'critical',
    ]
    for pattern in urgency_patterns:
        if re.search(pattern, combined_text):
            features['urgency_score'] += 1

    # Caps ratio (shouting indicator)
    alpha_chars = re.findall(r'[a-zA-Z]', combined_text)
    if alpha_chars:
        caps_count = sum(1 for c in alpha_chars if c.isupper())
        features['caps_ratio'] = round(caps_count / len(alpha_chars), 3)

    features['exclamation_count'] = combined_text.count('!')
    features['dollar_sign_count'] = combined_text.count('$')

    # Add domain risk score
    domain_risks = [d.get('risk_score', 0) for d in domain_analysis.get('domains', [])]
    features['max_domain_risk'] = max(domain_risks) if domain_risks else 0
    features['avg_domain_risk'] = sum(domain_risks) / len(domain_risks) if domain_risks else 0

    # Add URL risk score
    url_risks = [u.get('risk_score', 0) for u in url_analysis.get('urls', [])]
    features['max_url_risk'] = max(url_risks) if url_risks else 0
    features['avg_url_risk'] = sum(url_risks) / len(url_risks) if url_risks else 0

    return features


def classify_email(features):
    """Classify email using rule-based heuristics (fallback when ML model unavailable)."""
    score = 0
    indicators = []

    # URL-based signals
    if features['suspicious_url_count'] > 0:
        score += features['suspicious_url_count'] * 15
        indicators.append(f"Detected {features['suspicious_url_count']} suspicious URL(s)")

    if features['url_count'] > 5:
        score += 10
        indicators.append("High number of URLs in email")

    # Authentication failures
    if features['spf_fail']:
        score += 15
        indicators.append("SPF authentication failed")

    if features['dkim_fail']:
        score += 15
        indicators.append("DKIM authentication failed")

    if features['dmarc_fail']:
        score += 15
        indicators.append("DMARC authentication failed")

    # Sender mismatch
    if features['has_reply_to_mismatch']:
        score += 15
        indicators.append("Reply-To address differs from sender")

    # Phishing keywords
    if features['phishing_keyword_count'] >= 3:
        score += 20
        indicators.append(f"Multiple phishing keywords detected ({features['phishing_keyword_count']})")
    elif features['phishing_keyword_count'] >= 1:
        score += 10
        indicators.append(f"Phishing keywords detected ({features['phishing_keyword_count']})")

    # Urgency language
    if features['urgency_score'] >= 3:
        score += 15
        indicators.append("Strong urgency language detected")
    elif features['urgency_score'] >= 1:
        score += 8
        indicators.append("Urgency language detected")

    # Excessive caps
    if features['caps_ratio'] > 0.4:
        score += 8
        indicators.append("Excessive use of capital letters")

    # Dollar signs (financial scam)
    if features['dollar_sign_count'] > 3:
        score += 10
        indicators.append("Multiple dollar sign references")

    # High domain risk
    if features['max_domain_risk'] >= 30:
        score += 10
        indicators.append("High-risk domain detected")

    # Normalize score to 0-100
    confidence = min(score, 100)

    # Classification based on score
    if confidence >= 70:
        classification = 'MALICIOUS'
    elif confidence >= 50:
        classification = 'PHISHING'
    elif confidence >= 25:
        classification = 'SUSPICIOUS'
    else:
        classification = 'BENIGN'

    return {
        'classification': classification,
        'confidence': confidence,
        'indicators': indicators,
        'raw_score': score,
    }


def detect_phishing(parsed_email, url_analysis, ip_analysis, auth_analysis, domain_analysis):
    """Main phishing detection function."""
    features = extract_features(parsed_email, url_analysis, ip_analysis, auth_analysis, domain_analysis)
    classification = classify_email(features)

    return {
        'features': features,
        'classification': classification['classification'],
        'confidence': classification['confidence'],
        'indicators': classification['indicators'],
        'model_used': 'rule_based_heuristic',
    }
