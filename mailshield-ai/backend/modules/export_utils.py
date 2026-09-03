import csv
import io
import json
from datetime import datetime


def export_report_json(report):
    """Export forensic report as formatted JSON."""
    return json.dumps(report, indent=2, default=str)


def export_report_csv(report):
    """Export key indicators as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(['MailShield AI - Forensic Report'])
    writer.writerow(['Report ID', report.get('report_id', '')])
    writer.writerow(['Case ID', report.get('case_id', '')])
    writer.writerow(['Generated', report.get('generated_at', '')])
    writer.writerow([])

    # File info
    writer.writerow(['FILE INFORMATION'])
    finfo = report.get('file_information', {})
    writer.writerow(['Filename', finfo.get('filename', '')])
    writer.writerow(['SHA-256', finfo.get('file_hash', '')])
    writer.writerow(['File Size', f"{finfo.get('file_size', 0)} bytes"])
    writer.writerow([])

    # Email metadata
    writer.writerow(['EMAIL METADATA'])
    meta = report.get('email_metadata', {})
    writer.writerow(['From', meta.get('from', '')])
    writer.writerow(['To', meta.get('to', '')])
    writer.writerow(['Subject', meta.get('subject', '')])
    writer.writerow(['Date', meta.get('date', '')])
    writer.writerow(['Reply-To', meta.get('reply_to', '')])
    writer.writerow([])

    # Threat score
    writer.writerow(['THREAT ASSESSMENT'])
    ts = report.get('threat_score', {})
    writer.writerow(['Score', ts.get('score', 0)])
    writer.writerow(['Level', ts.get('threat_level', '')])
    writer.writerow([])

    # Breakdown
    writer.writerow(['SCORE BREAKDOWN'])
    writer.writerow(['Factor', 'Points', 'Reason'])
    for item in ts.get('breakdown', []):
        writer.writerow([item.get('factor', ''), item.get('points', 0), item.get('reason', '')])
    writer.writerow([])

    # Authentication
    writer.writerow(['AUTHENTICATION'])
    auth = report.get('authentication_analysis', {})
    writer.writerow(['SPF', auth.get('spf', {}).get('status', '')])
    writer.writerow(['DKIM', auth.get('dkim', {}).get('status', '')])
    writer.writerow(['DMARC', auth.get('dmarc', {}).get('status', '')])
    writer.writerow([])

    # AI Classification
    writer.writerow(['AI CLASSIFICATION'])
    ai = report.get('ai_classification', {})
    writer.writerow(['Classification', ai.get('classification', '')])
    writer.writerow(['Confidence', f"{ai.get('confidence', 0)}%"])
    for ind in ai.get('indicators', []):
        writer.writerow(['Indicator', ind])
    writer.writerow([])

    # URLs
    writer.writerow(['URL ANALYSIS'])
    writer.writerow(['URL', 'Domain', 'Risk Score', 'Risk Level', 'Flags'])
    urls = report.get('url_intelligence', {}).get('urls', [])
    for u in urls:
        writer.writerow([
            u.get('url', ''),
            u.get('domain', ''),
            u.get('risk_score', 0),
            u.get('risk_level', ''),
            ', '.join(u.get('flags', [])),
        ])
    writer.writerow([])

    # IPs
    writer.writerow(['IP ANALYSIS'])
    writer.writerow(['IP Address', 'Country', 'City', 'ISP', 'ASN', 'Risk Level'])
    ips = report.get('ip_intelligence', {}).get('ips', [])
    for ip in ips:
        writer.writerow([
            ip.get('ip_address', ''),
            ip.get('country', ''),
            ip.get('city', ''),
            ip.get('isp', ''),
            ip.get('asn', ''),
            ip.get('risk_level', ''),
        ])
    writer.writerow([])

    # Recommendations
    writer.writerow(['RECOMMENDED ACTIONS'])
    for rec in report.get('recommended_actions', []):
        writer.writerow([rec])

    return output.getvalue()


def export_indicators_json(indicators):
    """Export indicators as structured JSON for threat intel platforms."""
    stix_indicators = []
    for ind in indicators:
        stix_indicators.append({
            'type': ind.get('indicator_type', 'unknown'),
            'value': ind.get('indicator_value', ''),
            'severity': ind.get('risk_level', 'unknown'),
            'score': ind.get('risk_score', 0),
            'details': ind.get('details', ''),
        })
    return json.dumps(stix_indicators, indent=2)
