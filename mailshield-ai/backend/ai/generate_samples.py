"""Generate realistic sample .eml files for demo and testing."""
import os
from datetime import datetime, timedelta, timezone
import random
import uuid


PHISHING_TEMPLATES = [
    {
        'name': 'PayPal Phishing',
        'from': 'security@paypa1-secure-login.xyz',
        'reply_to': 'scammer@freemail.ml',
        'return_path': 'bounces@freemail.ml',
        'subject': 'URGENT: Your PayPal account has been suspended!',
        'x_mailer': 'PHPMailer 6.1.4',
        'x_originating_ip': '41.168.23.45',
        'spf': 'fail',
        'dkim': 'fail',
        'dmarc': 'fail',
        'received_from_ip': '197.210.55.12',
        'received_from_helo': 'mail.freemail.ml',
        'body_html': '''<html><body style="font-family:Arial,sans-serif;">
<h2 style="color:red;">SECURITY ALERT</h2>
<p>Dear Customer,</p>
<p>We have detected UNAUTHORIZED ACCESS to your PayPal account. Your account has been SUSPENDED.</p>
<p>Verify your identity within 24 HOURS or your account will be PERMANENTLY DELETED.</p>
<p><a href="http://paypal-secure-login.xyz/verify?id=12345">VERIFY MY ACCOUNT NOW</a></p>
<p>Visit: http://www.paypal-secure123-update.top/account/restore?token=abc123</p>
<p>Also check: https://login.paypa1.com/secure/verify?u=victim</p>
</body></html>''',
    },
    {
        'name': 'Microsoft 365 Phishing',
        'from': 'alerts@microsft365-security.com',
        'reply_to': 'helpdesk@outlook-verify.ml',
        'return_path': 'bounce@microsft365-security.com',
        'subject': 'Microsoft 365: Unusual sign-in activity detected',
        'x_mailer': 'Microsoft Outlook 16.0',
        'x_originating_ip': '103.224.182.251',
        'spf': 'fail',
        'dkim': 'fail',
        'dmarc': 'fail',
        'received_from_ip': '103.224.182.251',
        'received_from_helo': 'smtp.microsft365-security.com',
        'body_html': '''<html><body style="font-family:Segoe UI,sans-serif;">
<h2>Microsoft Account Security Notice</h2>
<p>We detected a sign-in from an unrecognized device in Moscow, Russia.</p>
<p>If this wasn't you, secure your account immediately by clicking below.</p>
<p><a href="http://microsoft-365-verify.tk/security/check">REVIEW SIGN-IN ACTIVITY</a></p>
<p>Device: Windows 10 / Chrome Browser<br>Location: Moscow, RU<br>IP: 185.220.101.45</p>
</body></html>''',
    },
    {
        'name': 'Banking Credential Harvest',
        'from': 'noreply@chase-secure-banking.xyz',
        'reply_to': 'support@chase-verify.top',
        'return_path': 'mailer@chase-secure-banking.xyz',
        'subject': 'Action Required: Verify your Chase account',
        'x_mailer': 'BulkMailer Pro',
        'x_originating_ip': '192.168.1.100',
        'spf': 'softfail',
        'dkim': 'fail',
        'dmarc': 'fail',
        'received_from_ip': '41.168.23.45',
        'received_from_helo': 'relay.chase-secure-banking.xyz',
        'body_html': '''<html><body>
<p>Dear Valued Customer,</p>
<p>Your Chase account has been flagged for suspicious activity. We need you to verify your identity.</p>
<p>Please click the link below and enter your online banking credentials:</p>
<p><a href="https://chase-secure-verify.xyz/login?ref=urgent">VERIFY ACCOUNT</a></p>
<p>Failure to verify within 48 hours will result in account limitation.</p>
<p>Chase Customer Service</p>
</body></html>''',
    },
    {
        'name': 'Tech Support Scam',
        'from': 'support@windows-defender-alert.com',
        'reply_to': 'tech@windows-support.pw',
        'return_path': 'bounce@windows-defender-alert.com',
        'subject': 'CRITICAL: Your computer is infected with 5 viruses!',
        'x_mailer': ' mass mailer',
        'x_originating_ip': '197.210.55.12',
        'spf': 'fail',
        'dkim': 'none',
        'dmarc': 'fail',
        'received_from_ip': '197.210.55.12',
        'received_from_helo': 'mail.windows-defender-alert.com',
        'body_html': '''<html><body style="background:#000;color:#fff;">
<div style="padding:20px;">
<h1 style="color:red;">WARNING!</h1>
<p>Your computer has been infected with <strong>5 different viruses</strong>!</p>
<p>Your personal data, banking information, and photos are at risk.</p>
<p>Call Microsoft Support immediately: <strong>1-800-FAKE-NUM</strong></p>
<p>Or click here to remove viruses: <a href="http://windows-defender-remove.gq/scan" style="color:#0ff;">REMOVE VIRUSES NOW</a></p>
<p>Act NOW before your data is stolen!</p>
</div>
</body></html>''',
    },
]


LEGITIMATE_TEMPLATES = [
    {
        'name': 'GitHub Notification',
        'from': 'notifications@github.com',
        'reply_to': 'notifications@github.com',
        'return_path': 'notifications@github.com',
        'subject': '[GitHub] A new dependency vulnerability has been detected',
        'x_mailer': '',
        'x_originating_ip': '',
        'spf': 'pass',
        'dkim': 'pass',
        'dmarc': 'pass',
        'received_from_ip': '140.82.121.3',
        'received_from_helo': 'github.com',
        'body_html': '''<html><body style="font-family:-apple-system,sans-serif;">
<h3>Dependency Alert</h3>
<p>A new vulnerability has been detected in one of your repositories.</p>
<p><strong>Repository:</strong> my-project<br>
<strong>Severity:</strong> Moderate<br>
<strong>Package:</strong> lodash@4.17.20</p>
<p>View details on GitHub.</p>
</body></html>''',
    },
    {
        'name': 'Newsletter',
        'from': 'newsletter@techcrunch.com',
        'reply_to': 'newsletter@techcrunch.com',
        'return_path': 'newsletter@techcrunch.com',
        'subject': 'TechCrunch Daily - Top Stories',
        'x_mailer': 'Mailchimp',
        'x_originating_ip': '',
        'spf': 'pass',
        'dkim': 'pass',
        'dmarc': 'pass',
        'received_from_ip': '205.201.128.0',
        'received_from_helo': 'mailchimp.com',
        'body_html': '''<html><body>
<h2>TechCrunch Daily</h2>
<p>Here are today's top stories in tech and startups.</p>
<ul>
<li>AI startup raises $50M Series B</li>
<li>New programming language gains traction</li>
<li>Cloud computing trends for 2025</li>
</ul>
</body></html>''',
    },
]


def generate_sample_eml(template, output_dir):
    """Generate a sample .eml file from a template."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime('%a, %d %b %Y %H:%M:%S +0000')
    message_id = f'<{uuid.uuid4().hex[:16]}@{template["from"].split("@")[1]}>'

    received_line = (f'from {template["received_from_helo"]} '
                     f'({template["received_from_helo"]} [{template["received_from_ip"]}])\n'
                     f'\tby mx.example.com with ESMTP id {uuid.uuid4().hex[:12]}\n'
                     f'\tfor <victim@example.com>; {date_str}')

    eml_content = f"""From: {template['from']}
To: victim@example.com
Reply-To: {template['reply_to']}
Subject: {template['subject']}
Date: {date_str}
Message-ID: {message_id}
Return-Path: <{template['return_path']}>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit
X-Mailer: {template['x_mailer']}
X-Originating-IP: [{template['x_originating_ip']}]
Authentication-Results: mx.example.com;
    spf={template['spf']} domain of {template['from'].split("@")[1]} does not designate {template['received_from_ip']} as permitted sender;
    dkim={template['dkim']} header.d={template['from'].split("@")[1]};
    dmarc={template['dmarc']}
Received: {received_line}

{template['body_html']}"""

    filename = f"{template['name'].lower().replace(' ', '_')}.eml"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w') as f:
        f.write(eml_content)

    return filepath


def generate_all_samples(output_dir):
    """Generate all sample .eml files."""
    os.makedirs(output_dir, exist_ok=True)
    generated = []
    for template in PHISHING_TEMPLATES + LEGITIMATE_TEMPLATES:
        path = generate_sample_eml(template, output_dir)
        generated.append(path)
    return generated


if __name__ == '__main__':
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'tests', 'samples')
    paths = generate_all_samples(output_dir)
    print(f"Generated {len(paths)} sample .eml files in {output_dir}")
    for p in paths:
        print(f"  - {os.path.basename(p)}")
