import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(os.path.dirname(BASE_DIR), 'uploads')
REPORTS_FOLDER = os.path.join(os.path.dirname(BASE_DIR), 'reports')
DATABASE_PATH = os.path.join(BASE_DIR, 'mailshield.db')
MODEL_DIR = os.path.join(BASE_DIR, 'ai', 'model')

MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
ALLOWED_EXTENSIONS = {'eml'}

# Threat Intelligence API Keys (optional)
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
URLHAUS_API_KEY = os.getenv('URLHAUS_API_KEY', '')
ALIENVAULT_OTX_API_KEY = os.getenv('ALIENVAULT_OTX_API_KEY', '')

# Threat scoring weights
SCORING_WEIGHTS = {
    'spf_fail': 15,
    'dkim_fail': 15,
    'dmarc_fail': 15,
    'suspicious_url': 20,
    'malicious_ip': 20,
    'suspicious_domain': 10,
    'sender_mismatch': 10,
    'phishing_language': 10,
}

# Phishing keywords for detection
PHISHING_KEYWORDS = [
    'urgent', 'verify your account', 'suspended', 'click here immediately',
    'confirm your identity', 'update your payment', 'unauthorized access',
    'your account will be', 'act now', 'limited time', 'security alert',
    'unusual sign-in', 'password expires', 'validate your account',
    'winning prize', 'congratulations you won', 'claim your reward',
    'bank of america', 'paypal security', 'microsoft account',
    'apple id', 'google security', 'amazon alert',
]

SUSPICIOUS_TLDS = ['.xyz', '.top', '.buzz', '.club', '.work', '.live',
                   '.gq', '.ml', '.cf', '.ga', '.tk', '.pw', '.cc']

SUSPICIOUS_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'banking', 'password', 'credential', 'auth',
    'paypal', 'apple', 'microsoft', 'google', 'amazon',
]
