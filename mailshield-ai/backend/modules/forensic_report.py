from datetime import datetime


def generate_forensic_report(case_id, parsed_email, email_info, header_analysis,
                             auth_analysis, url_analysis, ip_analysis,
                             domain_analysis, phishing_result, threat_score,
                             indicators):
    """Generate a comprehensive forensic investigation report."""
    basic = parsed_email.get('basic_info', {})
    body = parsed_email.get('body', {})

    report = {
        'report_id': f'RPT-{case_id[:8].upper()}',
        'generated_at': datetime.utcnow().isoformat(),
        'case_id': case_id,

        'case_information': {
            'case_id': case_id,
            'report_id': f'RPT-{case_id[:8].upper()}',
            'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'analyzer_version': '1.0.0',
        },

        'file_information': {
            'filename': email_info.get('filename', 'Unknown'),
            'file_hash': email_info.get('file_hash', 'Unknown'),
            'file_size': email_info.get('file_size', 0),
            'upload_time': email_info.get('upload_time', 'Unknown'),
        },

        'email_metadata': {
            'from': basic.get('from', 'N/A'),
            'to': basic.get('to', 'N/A'),
            'cc': basic.get('cc', 'N/A'),
            'subject': basic.get('subject', 'N/A'),
            'date': basic.get('date', 'N/A'),
            'reply_to': basic.get('reply_to', 'N/A'),
            'return_path': basic.get('return_path', 'N/A'),
            'message_id': basic.get('message_id', 'N/A'),
            'x_mailer': basic.get('x_mailer', 'N/A'),
            'has_attachments': len(parsed_email.get('attachments', [])) > 0,
            'attachment_count': len(parsed_email.get('attachments', [])),
            'attachments': parsed_email.get('attachments', []),
        },

        'header_analysis': {
            'summary': 'Email header analysis completed.',
            'findings': header_analysis.get('findings', []),
            'risk_score': header_analysis.get('risk_score', 0),
        },

        'authentication_analysis': {
            'spf': auth_analysis.get('spf', {}),
            'dkim': auth_analysis.get('dkim', {}),
            'dmarc': auth_analysis.get('dmarc', {}),
            'risk_score': auth_analysis.get('risk_score', 0),
            'findings': auth_analysis.get('findings', []),
        },

        'url_intelligence': {
            'total_urls': url_analysis.get('total_urls', 0),
            'suspicious_urls': url_analysis.get('suspicious_urls', 0),
            'average_risk_score': url_analysis.get('average_risk_score', 0),
            'urls': url_analysis.get('urls', []),
        },

        'domain_intelligence': {
            'total_domains': domain_analysis.get('total_domains', 0),
            'sender_domain': domain_analysis.get('sender_domain', ''),
            'domains': domain_analysis.get('domains', []),
        },

        'ip_intelligence': {
            'total_ips': ip_analysis.get('total_ips', 0),
            'public_ips': ip_analysis.get('public_ips', 0),
            'ips': ip_analysis.get('ips', []),
        },

        'ai_classification': {
            'classification': phishing_result.get('classification', 'UNKNOWN'),
            'confidence': phishing_result.get('confidence', 0),
            'indicators': phishing_result.get('indicators', []),
            'model_used': phishing_result.get('model_used', 'unknown'),
        },

        'threat_score': {
            'score': threat_score.get('score', 0),
            'threat_level': threat_score.get('threat_level', 'UNKNOWN'),
            'breakdown': threat_score.get('breakdown', []),
        },

        'evidence_indicators': indicators,

        'conclusion': _generate_conclusion(threat_score, phishing_result),

        'recommended_actions': _generate_recommendations(threat_score, phishing_result),
    }

    return report


def _generate_conclusion(threat_score, phishing_result):
    """Generate a conclusion based on analysis results."""
    score = threat_score.get('score', 0)
    level = threat_score.get('threat_level', 'LOW')
    classification = phishing_result.get('classification', 'BENIGN')

    if level == 'CRITICAL':
        return (f"This email has been classified as {classification} with a CRITICAL threat "
                f"score of {score}/100. Strong indicators of malicious intent were detected. "
                f"This email poses a significant security risk and should be treated as a "
                f"confirmed threat. Immediate action is recommended.")
    elif level == 'HIGH':
        return (f"This email has been classified as {classification} with a HIGH threat "
                f"score of {score}/100. Multiple indicators of suspicious activity were "
                f"detected. This email likely represents a phishing attempt or social "
                f"engineering attack. Caution is strongly advised.")
    elif level == 'MEDIUM':
        return (f"This email has been classified as {classification} with a MEDIUM threat "
                f"score of {score}/100. Some suspicious indicators were found. While not "
                f"confirmed malicious, the email warrants further investigation.")
    else:
        return (f"This email has been classified as {classification} with a LOW threat "
                f"score of {score}/100. No significant threat indicators were detected. "
                f"However, continued vigilance is always recommended.")


def _generate_recommendations(threat_score, phishing_result):
    """Generate recommended actions based on analysis."""
    score = threat_score.get('score', 0)
    level = threat_score.get('threat_level', 'LOW')
    recommendations = []

    if level in ['CRITICAL', 'HIGH']:
        recommendations.extend([
            "Do NOT click any links in this email.",
            "Do NOT download or open any attachments.",
            "Do NOT reply to this email or provide any information.",
            "Report this email to your security team or IT department.",
            "Block the sender's email address.",
            "Mark this email as phishing in your email client.",
        ])
    elif level == 'MEDIUM':
        recommendations.extend([
            "Exercise caution when interacting with this email.",
            "Verify the sender through a separate communication channel.",
            "Do not click links without verifying their legitimacy.",
            "Report to IT if you are unsure about the email's authenticity.",
        ])
    else:
        recommendations.extend([
            "This email appears to be legitimate based on automated analysis.",
            "Always remain cautious with unexpected emails.",
            "Verify sender identity if the email requests sensitive actions.",
        ])

    if phishing_result.get('classification') in ['PHISHING', 'MALICIOUS']:
        recommendations.append("Consider blocking the sender domain at the email gateway.")
        recommendations.append("Add IOCs to your threat intelligence platform.")

    return recommendations
