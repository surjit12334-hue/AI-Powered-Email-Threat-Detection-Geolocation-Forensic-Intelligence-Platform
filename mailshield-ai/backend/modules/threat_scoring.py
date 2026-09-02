from config import SCORING_WEIGHTS


def calculate_threat_score(auth_analysis, url_analysis, ip_analysis,
                           domain_analysis, phishing_result, header_analysis):
    """Calculate an overall threat score from all analysis modules."""
    score = 0
    breakdown = []

    # Authentication failures
    if auth_analysis.get('spf', {}).get('status') == 'FAIL':
        points = SCORING_WEIGHTS['spf_fail']
        score += points
        breakdown.append({
            'factor': 'SPF Authentication Failure',
            'points': points,
            'reason': 'Sender IP is not authorized to send from this domain.',
        })

    if auth_analysis.get('dkim', {}).get('status') == 'FAIL':
        points = SCORING_WEIGHTS['dkim_fail']
        score += points
        breakdown.append({
            'factor': 'DKIM Authentication Failure',
            'points': points,
            'reason': 'Email signature verification failed.',
        })

    if auth_analysis.get('dmarc', {}).get('status') == 'FAIL':
        points = SCORING_WEIGHTS['dmarc_fail']
        score += points
        breakdown.append({
            'factor': 'DMARC Authentication Failure',
            'points': points,
            'reason': 'DMARC policy check failed.',
        })

    # Suspicious URLs
    suspicious_url_count = url_analysis.get('suspicious_urls', 0)
    if suspicious_url_count > 0:
        points = min(suspicious_url_count * SCORING_WEIGHTS['suspicious_url'], 40)
        score += points
        breakdown.append({
            'factor': 'Suspicious URLs Detected',
            'points': points,
            'reason': f'{suspicious_url_count} suspicious URL(s) found in the email.',
        })

    # Malicious IP indicators
    ip_flags = []
    for ip in ip_analysis.get('ips', []):
        ip_flags.extend(ip.get('flags', []))
    if 'KNOWN_SUSPICIOUS_RANGE' in ip_flags:
        points = SCORING_WEIGHTS['malicious_ip']
        score += points
        breakdown.append({
            'factor': 'Suspicious IP Address',
            'points': points,
            'reason': 'Email received from known suspicious IP range.',
        })

    # Suspicious domains
    high_risk_domains = [d for d in domain_analysis.get('domains', [])
                         if d.get('risk_level') in ['HIGH', 'CRITICAL']]
    if high_risk_domains:
        points = min(len(high_risk_domains) * SCORING_WEIGHTS['suspicious_domain'], 20)
        score += points
        domain_names = ', '.join(d['domain'] for d in high_risk_domains[:3])
        breakdown.append({
            'factor': 'Suspicious Domains',
            'points': points,
            'reason': f'High-risk domains detected: {domain_names}',
        })

    # Sender/Reply-To mismatch
    header_findings = header_analysis.get('findings', [])
    mismatch_findings = [f for f in header_findings
                         if f.get('type') in ['REPLY_TO_MISMATCH', 'RETURN_PATH_MISMATCH']]
    if mismatch_findings:
        points = SCORING_WEIGHTS['sender_mismatch']
        score += points
        breakdown.append({
            'factor': 'Sender Identity Mismatch',
            'points': points,
            'reason': 'Reply-To or Return-Path differs from sender address.',
        })

    # Phishing language detection
    phishing_indicators = phishing_result.get('indicators', [])
    phishing_lang = [i for i in phishing_indicators
                     if 'keyword' in i.lower() or 'urgency' in i.lower()]
    if phishing_lang:
        points = SCORING_WEIGHTS['phishing_language']
        score += points
        breakdown.append({
            'factor': 'Phishing Language Detected',
            'points': points,
            'reason': f'{len(phishing_lang)} phishing indicator(s) found.',
        })

    # Normalize score to 0-100
    normalized_score = min(score, 100)

    # Determine threat level
    if normalized_score >= 76:
        threat_level = 'CRITICAL'
    elif normalized_score >= 51:
        threat_level = 'HIGH'
    elif normalized_score >= 21:
        threat_level = 'MEDIUM'
    else:
        threat_level = 'LOW'

    return {
        'score': normalized_score,
        'threat_level': threat_level,
        'breakdown': breakdown,
        'total_factors': len(breakdown),
    }
