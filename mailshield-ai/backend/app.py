import os
import sys
import uuid
import json
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from config import (UPLOAD_FOLDER, REPORTS_FOLDER, MAX_CONTENT_LENGTH,
                    ALLOWED_EXTENSIONS, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY,
                    SCORING_WEIGHTS)
from database import (init_db, save_case, update_case, save_email_info,
                      save_indicator, save_url_analysis, save_ip_analysis,
                      save_auth_results, save_analysis_result,
                      get_case, get_all_cases, get_email_info,
                      get_indicators, get_url_analyses, get_ip_analyses,
                      get_auth_results)
from modules.email_parser import parse_eml_file, calculate_file_hash
from modules.header_analyzer import analyze_headers, get_header_summary
from modules.url_analyzer import analyze_urls
from modules.ip_analyzer import analyze_ips
from modules.domain_analyzer import analyze_domains
from modules.authentication_analyzer import analyze_authentication
from modules.phishing_detector import detect_phishing
from modules.threat_scoring import calculate_threat_score
from modules.forensic_report import generate_forensic_report
from modules.threat_intel import threat_intel
from modules.attachment_analyzer import analyze_attachments
from modules.export_utils import export_report_json, export_report_csv, export_indicators_json

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'),
            static_folder=os.path.join(os.path.dirname(__file__), '..', 'static'))
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

init_db()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/reports')
def reports_page():
    return render_template('reports.html')


@app.route('/report')
def report_page():
    return render_template('report.html')


@app.route('/api/cases', methods=['GET'])
def list_cases():
    cases = get_all_cases()
    return jsonify({'cases': cases})


@app.route('/api/upload', methods=['POST'])
def upload_email():
    if 'email_file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['email_file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only .eml files are accepted.'}), 400

    case_id = str(uuid.uuid4())
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, f'{case_id}_{filename}')
    file.save(file_path)

    file_size = os.path.getsize(file_path)
    file_hash = calculate_file_hash(file_path)

    # Save case to database
    save_case(case_id, filename, file_hash, file_size)

    # Run full analysis
    try:
        analysis_results = run_analysis(case_id, file_path, filename, file_hash, file_size)
        return jsonify(analysis_results)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}', 'case_id': case_id}), 500


def run_analysis(case_id, file_path, filename, file_hash, file_size):
    """Run complete email analysis pipeline."""
    # Parse email
    parsed_email = parse_eml_file(file_path)

    # Header analysis
    header_analysis = analyze_headers(parsed_email)
    header_summary = get_header_summary(parsed_email)

    # URL analysis
    url_analysis = analyze_urls(parsed_email)

    # IP analysis
    ip_analysis = analyze_ips(parsed_email)

    # Domain analysis
    domain_analysis = analyze_domains(parsed_email, url_analysis)

    # Authentication analysis
    auth_analysis = analyze_authentication(parsed_email)

    # Phishing detection
    phishing_result = detect_phishing(
        parsed_email, url_analysis, ip_analysis, auth_analysis, domain_analysis
    )

    # Attachment analysis
    attachments = parsed_email.get('attachments', [])
    attachment_analysis = analyze_attachments(attachments) if attachments else {
        'attachments': [],
        'total_attachments': 0,
        'dangerous_count': 0,
        'total_risk_score': 0,
        'average_risk_score': 0,
    }

    # Threat scoring
    threat_score = calculate_threat_score(
        auth_analysis, url_analysis, ip_analysis, domain_analysis,
        phishing_result, header_analysis
    )

    # Collect all indicators
    indicators = []
    for finding in header_analysis.get('findings', []):
        indicators.append(finding)
    for finding in auth_analysis.get('findings', []):
        indicators.append(finding)
    for finding in phishing_result.get('indicators', []):
        indicators.append({
            'type': 'PHISHING_INDICATOR',
            'severity': 'HIGH',
            'description': finding,
        })

    # Save to database
    body = parsed_email.get('body', {})
    save_email_info(
        case_id,
        sender=parsed_email['basic_info'].get('from', ''),
        recipient=parsed_email['basic_info'].get('to', ''),
        cc=parsed_email['basic_info'].get('cc', ''),
        bcc=parsed_email['basic_info'].get('bcc', ''),
        subject=parsed_email['basic_info'].get('subject', ''),
        date=parsed_email['basic_info'].get('date', ''),
        reply_to=parsed_email['basic_info'].get('reply_to', ''),
        return_path=parsed_email['basic_info'].get('return_path', ''),
        message_id=parsed_email['basic_info'].get('message_id', ''),
        mime_type=parsed_email['basic_info'].get('mime_type', ''),
        has_html=1 if body.get('html') else 0,
        has_plain=1 if body.get('plain') else 0,
        body_preview=body.get('plain', '')[:500] if body.get('plain') else '',
    )

    update_case(
        case_id,
        threat_score=threat_score['score'],
        threat_level=threat_score['threat_level'],
        ai_classification=phishing_result.get('classification', 'UNKNOWN'),
        ai_confidence=phishing_result.get('confidence', 0),
    )

    # Save URL analyses
    for url_result in url_analysis.get('urls', []):
        save_url_analysis(
            case_id,
            url=url_result.get('url', ''),
            domain=url_result.get('domain', ''),
            risk_score=url_result.get('risk_score', 0),
            risk_level=url_result.get('risk_level', 'LOW'),
            details=json.dumps(url_result.get('flags', [])),
        )

    # Save IP analyses
    for ip_result in ip_analysis.get('ips', []):
        save_ip_analysis(
            case_id,
            ip_address=ip_result.get('ip_address', ''),
            country=ip_result.get('country', 'Unknown'),
            city=ip_result.get('city', 'Unknown'),
            isp=ip_result.get('isp', 'Unknown'),
            asn=ip_result.get('asn', 'Unknown'),
            latitude=ip_result.get('latitude'),
            longitude=ip_result.get('longitude'),
            risk_score=ip_result.get('risk_score', 0),
            risk_level=ip_result.get('risk_level', 'LOW'),
            details=json.dumps(ip_result.get('flags', [])),
        )

    # Save auth results
    save_auth_results(
        case_id,
        spf_result=auth_analysis.get('spf', {}).get('status', 'UNKNOWN'),
        dkim_result=auth_analysis.get('dkim', {}).get('status', 'UNKNOWN'),
        dmarc_result=auth_analysis.get('dmarc', {}).get('status', 'UNKNOWN'),
        details=json.dumps(auth_analysis.get('findings', [])),
    )

    # Save indicators
    for ind in indicators:
        save_indicator(
            case_id,
            indicator_type=ind.get('type', 'UNKNOWN'),
            indicator_value=ind.get('description', ''),
            risk_score=10 if ind.get('severity') == 'HIGH' else 5,
            risk_level=ind.get('severity', 'UNKNOWN'),
            details=json.dumps(ind),
        )

    # Generate forensic report
    email_info = {
        'filename': filename,
        'file_hash': file_hash,
        'file_size': file_size,
        'upload_time': datetime.now(timezone.utc).isoformat(),
    }
    report = generate_forensic_report(
        case_id, parsed_email, email_info, header_analysis,
        auth_analysis, url_analysis, ip_analysis, domain_analysis,
        phishing_result, threat_score, indicators, attachment_analysis,
    )

    # Save report JSON
    report_path = os.path.join(REPORTS_FOLDER, f'{case_id}_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    save_analysis_result(case_id, 'full_report', report)

    # Build timeline
    timeline = [
        {'step': 1, 'action': 'Email uploaded', 'status': 'completed', 'timestamp': datetime.now(timezone.utc).isoformat()},
        {'step': 2, 'action': 'Headers parsed', 'status': 'completed', 'timestamp': datetime.now(timezone.utc).isoformat()},
        {'step': 3, 'action': 'URLs extracted and analyzed', 'status': 'completed', 'timestamp': datetime.now(timezone.utc).isoformat()},
        {'step': 4, 'action': 'IP addresses identified', 'status': 'completed', 'timestamp': datetime.now(timezone.utc).isoformat()},
        {'step': 5, 'action': 'Email authentication checked', 'status': 'completed', 'timestamp': datetime.now(timezone.utc).isoformat()},
        {'step': 6, 'action': 'AI classification completed', 'status': 'completed', 'timestamp': datetime.now(timezone.utc).isoformat()},
        {'step': 7, 'action': 'Threat score generated', 'status': 'completed', 'timestamp': datetime.now(timezone.utc).isoformat()},
    ]

    return {
        'case_id': case_id,
        'filename': filename,
        'file_hash': file_hash,
        'file_size': file_size,
        'timeline': timeline,
        'email_metadata': header_summary,
        'header_analysis': header_analysis,
        'authentication': auth_analysis,
        'url_analysis': url_analysis,
        'ip_analysis': ip_analysis,
        'domain_analysis': domain_analysis,
        'attachment_analysis': attachment_analysis,
        'phishing_detection': phishing_result,
        'threat_score': threat_score,
        'indicators': indicators,
        'report': report,
    }


@app.route('/api/case/<case_id>', methods=['GET'])
def get_case_details(case_id):
    case = get_case(case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404

    email_info = get_email_info(case_id)
    indicators = get_indicators(case_id)
    url_analyses = get_url_analyses(case_id)
    ip_analyses = get_ip_analyses(case_id)
    auth_results = get_auth_results(case_id)

    # Load the full report if available (contains all analysis data)
    report_path = os.path.join(REPORTS_FOLDER, f'{case_id}_report.json')
    full_report = None
    if os.path.exists(report_path):
        try:
            with open(report_path, 'r') as f:
                full_report = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    # Build response matching dashboard.js expected structure
    if full_report:
        return jsonify({
            'case_id': case_id,
            'filename': case.get('filename', ''),
            'file_hash': case.get('file_hash', ''),
            'file_size': case.get('file_size', 0),
            'threat_score': full_report.get('threat_score', {}),
            'phishing_detection': full_report.get('ai_classification', {}),
            'url_analysis': full_report.get('url_intelligence', {}),
            'ip_analysis': full_report.get('ip_intelligence', {}),
            'domain_analysis': full_report.get('domain_intelligence', {}),
            'authentication': full_report.get('authentication_analysis', {}),
            'email_metadata': full_report.get('email_metadata', {}),
            'header_analysis': full_report.get('header_analysis', {}),
            'attachment_analysis': full_report.get('attachment_intelligence', {}),
            'timeline': [
                {'step': 1, 'action': 'Email uploaded', 'status': 'completed'},
                {'step': 2, 'action': 'Headers parsed', 'status': 'completed'},
                {'step': 3, 'action': 'URLs extracted and analyzed', 'status': 'completed'},
                {'step': 4, 'action': 'IP addresses identified', 'status': 'completed'},
                {'step': 5, 'action': 'Email authentication checked', 'status': 'completed'},
                {'step': 6, 'action': 'AI classification completed', 'status': 'completed'},
                {'step': 7, 'action': 'Threat score generated', 'status': 'completed'},
            ],
            'indicators': indicators,
            'report': full_report,
        })
    else:
        # Fallback: reconstruct from database tables
        return jsonify({
            'case_id': case_id,
            'filename': case.get('filename', ''),
            'threat_score': {
                'score': case.get('threat_score', 0),
                'threat_level': case.get('threat_level', 'UNKNOWN'),
                'breakdown': [],
            },
            'phishing_detection': {
                'classification': case.get('ai_classification', 'UNKNOWN'),
                'confidence': case.get('ai_confidence', 0),
                'indicators': [i.get('indicator_value', '') for i in indicators],
                'model_used': 'unknown',
            },
            'url_analysis': {
                'urls': url_analyses,
                'total_urls': len(url_analyses),
                'suspicious_urls': sum(1 for u in url_analyses if u.get('risk_level') in ['HIGH', 'CRITICAL']),
            },
            'ip_analysis': {
                'ips': ip_analyses,
                'total_ips': len(ip_analyses),
                'public_ips': sum(1 for i in ip_analyses if 'PRIVATE' not in (i.get('details', '') or '')),
            },
            'authentication': {
                'spf': {'status': auth_results.get('spf_result', 'UNKNOWN') if auth_results else 'UNKNOWN', 'details': ''},
                'dkim': {'status': auth_results.get('dkim_result', 'UNKNOWN') if auth_results else 'UNKNOWN', 'details': ''},
                'dmarc': {'status': auth_results.get('dmarc_result', 'UNKNOWN') if auth_results else 'UNKNOWN', 'details': ''},
            },
            'email_metadata': {
                'from': email_info.get('sender', 'N/A') if email_info else 'N/A',
                'to': email_info.get('recipient', 'N/A') if email_info else 'N/A',
                'cc': email_info.get('cc', 'N/A') if email_info else 'N/A',
                'subject': email_info.get('subject', 'N/A') if email_info else 'N/A',
                'date': email_info.get('date', 'N/A') if email_info else 'N/A',
                'reply_to': email_info.get('reply_to', 'N/A') if email_info else 'N/A',
                'return_path': email_info.get('return_path', 'N/A') if email_info else 'N/A',
                'message_id': email_info.get('message_id', 'N/A') if email_info else 'N/A',
                'x_mailer': 'N/A',
            },
            'timeline': [
                {'step': 1, 'action': 'Email uploaded', 'status': 'completed'},
                {'step': 2, 'action': 'Headers parsed', 'status': 'completed'},
                {'step': 3, 'action': 'URLs extracted and analyzed', 'status': 'completed'},
                {'step': 4, 'action': 'IP addresses identified', 'status': 'completed'},
                {'step': 5, 'action': 'Email authentication checked', 'status': 'completed'},
                {'step': 6, 'action': 'AI classification completed', 'status': 'completed'},
                {'step': 7, 'action': 'Threat score generated', 'status': 'completed'},
            ],
            'indicators': indicators,
        })


@app.route('/api/report/<case_id>', methods=['GET'])
def get_report(case_id):
    report_path = os.path.join(REPORTS_FOLDER, f'{case_id}_report.json')
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report not found'}), 404

    with open(report_path, 'r') as f:
        report = json.load(f)

    return jsonify(report)


@app.route('/reports/<filename>')
def serve_report(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        return jsonify({'error': 'Invalid filename'}), 400
    return send_from_directory(REPORTS_FOLDER, safe_name)


@app.route('/settings')
def settings_page():
    return render_template('settings.html')


@app.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify({
        'apis': threat_intel.get_config_status(),
        'scoring_weights': SCORING_WEIGHTS,
    })


@app.route('/api/train', methods=['POST'])
def train():
    try:
        from ai.train_model import train_model
        result = train_model()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/<case_id>/<fmt>', methods=['GET'])
def export_report(case_id, fmt):
    report_path = os.path.join(REPORTS_FOLDER, f'{case_id}_report.json')
    if not os.path.exists(report_path):
        return jsonify({'error': 'Report not found'}), 404

    with open(report_path, 'r') as f:
        report = json.load(f)

    if fmt == 'json':
        return export_report_json(report), 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': f'attachment; filename=mailshield_report_{case_id[:8]}.json'
        }
    elif fmt == 'csv':
        csv_data = export_report_csv(report)
        return csv_data, 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=mailshield_report_{case_id[:8]}.csv'
        }
    elif fmt == 'ioc':
        indicators = get_indicators(case_id)
        ioc_data = export_indicators_json(indicators)
        return ioc_data, 200, {
            'Content-Type': 'application/json',
            'Content-Disposition': f'attachment; filename=mailshield_iocs_{case_id[:8]}.json'
        }
    return jsonify({'error': 'Invalid format'}), 400


@app.route('/api/threat-intel/ip/<ip_address>', methods=['GET'])
def threat_intel_ip(ip_address):
    result = threat_intel.check_ip(ip_address)
    return jsonify(result)


@app.route('/api/threat-intel/url', methods=['GET'])
def threat_intel_url():
    url = request.args.get('url', '')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    result = threat_intel.check_url(url)
    return jsonify(result)


@app.route('/api/threat-intel/domain/<domain>', methods=['GET'])
def threat_intel_domain(domain):
    result = threat_intel.check_domain(domain)
    return jsonify(result)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    cases = get_all_cases()
    total = len(cases)
    critical = sum(1 for c in cases if c.get('threat_level') == 'CRITICAL')
    high = sum(1 for c in cases if c.get('threat_level') == 'HIGH')
    medium = sum(1 for c in cases if c.get('threat_level') == 'MEDIUM')
    low = sum(1 for c in cases if c.get('threat_level') == 'LOW')
    phishing = sum(1 for c in cases if c.get('ai_classification') in ['PHISHING', 'MALICIOUS'])
    avg_score = sum(c.get('threat_score', 0) for c in cases) / total if total else 0

    return jsonify({
        'total_cases': total,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'phishing_detected': phishing,
        'average_score': round(avg_score, 1),
    })


if __name__ == '__main__':
    # Train ML model on first run if not exists
    model_path = os.path.join(os.path.dirname(__file__), 'ai', 'model', 'random_forest.joblib')
    if not os.path.exists(model_path):
        print("Training ML model...")
        from ai.train_model import train_model
        result = train_model()
        print(f"Model trained - RF Accuracy: {result['rf_accuracy']:.2%}")

    app.run(debug=True, host='0.0.0.0', port=5000)
