# MailShield AI

### AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

A cybersecurity tool for analyzing suspicious email files, detecting phishing attempts, investigating indicators, and generating actionable forensic intelligence.

---

## Features

- **Email Parsing** — Parse .eml files, extract headers, body, and metadata
- **Header Analysis** — Detect Reply-To mismatches, missing headers, suspicious patterns
- **SPF / DKIM / DMARC** — Email authentication verification
- **URL Analysis** — Extract and analyze URLs for phishing indicators
- **IP Analysis** — Extract IPs from headers, geolocation, risk assessment
- **Domain Analysis** — Suspicious TLD detection, brand impersonation checks
- **AI Phishing Detection** — Machine learning classification (Random Forest + Logistic Regression ensemble)
- **Threat Scoring** — Transparent risk scoring engine (0-100)
- **Interactive Map** — Leaflet.js geolocation visualization of suspicious IPs
- **Forensic Reports** — Generate detailed investigation reports
- **Dark SOC Dashboard** — Modern cybersecurity-themed UI

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, JavaScript, Chart.js, Leaflet.js |
| Backend | Python 3, Flask |
| Database | SQLite |
| AI/ML | Scikit-learn, Pandas, NumPy, Joblib |

---

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd mailshield-ai
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys (all optional)
```

5. Run the application:
```bash
cd backend
python app.py
```

6. Open in browser: `http://localhost:5000`

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key for URL/IP reputation |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key for IP reputation |
| `URLHAUS_API_KEY` | No | URLhaus API key for URL reputation |
| `ALIENVAULT_OTX_API_KEY` | No | AlienVault OTX API key for threat intel |

All API keys are optional. The application works fully without them.

---

## Project Structure

```
mailshield-ai/
├── backend/
│   ├── app.py                 # Flask application
│   ├── config.py              # Configuration
│   ├── database.py            # SQLite database
│   ├── modules/
│   │   ├── email_parser.py
│   │   ├── header_analyzer.py
│   │   ├── url_analyzer.py
│   │   ├── ip_analyzer.py
│   │   ├── domain_analyzer.py
│   │   ├── authentication_analyzer.py
│   │   ├── phishing_detector.py
│   │   ├── threat_scoring.py
│   │   └── forensic_report.py
│   └── ai/
│       ├── train_model.py
│       ├── predict.py
│       └── model/
├── templates/
│   ├── index.html
│   ├── dashboard.html
│   └── report.html
├── static/
│   ├── css/style.css
│   └── js/
│       ├── main.js
│       └── dashboard.js
├── uploads/
├── reports/
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Usage

1. Upload a `.eml` file via the dashboard
2. The system automatically analyzes the email
3. Review the threat score, AI classification, and detailed findings
4. Investigate URLs, IP addresses, and domains on the interactive map
5. Generate a forensic report for documentation

---

## Security Considerations

- Uploaded email files are never executed
- Email attachments are never opened or executed
- Suspicious URLs are never visited in a browser
- API keys are stored in environment variables only
- File uploads are validated and size-limited
- SHA-256 hashes ensure evidence integrity

---

## License

MIT
