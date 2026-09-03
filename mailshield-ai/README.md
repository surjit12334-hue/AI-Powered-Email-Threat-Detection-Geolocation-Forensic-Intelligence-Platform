# MailShield AI

## AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

MailShield AI is a cybersecurity web application that analyzes suspicious `.eml` email files to detect phishing attempts, spoofing, malicious URLs, suspicious IP addresses, and other cybersecurity threats. Built for hackathon demonstration with a complete end-to-end pipeline.

---

## Features

- **Email Parsing** - Full `.eml` file parsing with header extraction, body extraction, and attachment metadata
- **Header Analysis** - Detects Reply-To mismatch, Return-Path mismatch, missing headers, suspicious mailers
- **SPF/DKIM/DMARC Analysis** - Email authentication verification from header data
- **URL Analysis** - 13+ risk checks per URL including brand impersonation, suspicious TLDs, punycode detection
- **IP Address Analysis** - Validation, geolocation via ip-api.com, reverse DNS, private/public classification
- **Domain Analysis** - 10+ risk checks including brand impersonation, suspicious patterns, punycode
- **Attachment Analysis** - Dangerous extension detection, double-extension tricks, MIME type mismatch
- **AI Phishing Detection** - Random Forest + Logistic Regression ensemble ML model with rule-based fallback
- **Threat Scoring Engine** - Weighted scoring across all analysis modules (0-100 scale)
- **Geolocation Map** - Interactive Leaflet.js map with IP location markers
- **Forensic Reports** - Detailed investigation reports with conclusion and recommended actions
- **Export** - JSON, CSV, and IOC export formats
- **Threat Intelligence** - Optional VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX integration
- **Dark SOC Dashboard** - Modern cybersecurity-themed UI with charts and animations

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, JavaScript, Chart.js, Leaflet.js |
| Backend | Python 3, Flask |
| Database | SQLite |
| AI/ML | Scikit-learn (Random Forest + Logistic Regression) |
| IP Geolocation | ip-api.com (free tier) |

---

## Project Structure

```
mailshield-ai/
├── backend/
│   ├── app.py                          # Flask web application
│   ├── config.py                       # Configuration and environment variables
│   ├── database.py                     # SQLite database layer
│   ├── ai/
│   │   ├── train_model.py              # ML model training
│   │   ├── predict.py                  # ML model prediction
│   │   ├── generate_samples.py         # Sample .eml file generator
│   │   └── model/                      # Trained model files (generated at runtime)
│   └── modules/
│       ├── email_parser.py             # .eml file parsing
│       ├── header_analyzer.py          # Email header analysis
│       ├── url_analyzer.py             # URL risk analysis
│       ├── ip_analyzer.py              # IP analysis with geolocation
│       ├── domain_analyzer.py          # Domain risk analysis
│       ├── authentication_analyzer.py  # SPF/DKIM/DMARC analysis
│       ├── phishing_detector.py        # AI + heuristic phishing detection
│       ├── threat_scoring.py           # Threat score calculation
│       ├── forensic_report.py          # Report generation
│       ├── threat_intel.py             # External threat intel APIs
│       ├── attachment_analyzer.py      # Attachment risk analysis
│       └── export_utils.py             # JSON/CSV/IOC export
├── templates/
│   ├── index.html                      # Upload page
│   ├── dashboard.html                  # Investigation dashboard
│   ├── report.html                     # Forensic report viewer
│   ├── reports.html                    # Case listing
│   └── settings.html                   # API configuration settings
├── static/
│   ├── css/style.css                   # Dark cybersecurity theme
│   └── js/
│       ├── main.js                     # Upload logic
│       └── dashboard.js                # Dashboard rendering
├── tests/
│   └── samples/                        # Sample .eml files for testing
├── uploads/                            # Uploaded email files
├── reports/                            # Generated report JSON files
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Installation

### Prerequisites

- Python 3.8+
- pip

### Steps

1. Clone the repository:
```bash
git clone <repository-url>
cd mailshield-ai
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. (Optional) Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys
```

5. Run the application:
```bash
cd backend
python app.py
```

6. Open your browser and navigate to:
```
http://localhost:5000
```

---

## Environment Variables

All API keys are optional. The application works without them.

| Variable | Description |
|----------|-------------|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for URL/IP/domain reputation |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key for IP abuse confidence |
| `URLHAUS_API_KEY` | URLhaus API key for malicious URL database |
| `ALIENVAULT_OTX_API_KEY` | AlienVault OTX API key for threat intelligence |

---

## How to Run

```bash
cd backend
python app.py
```

The application will:
1. Initialize the SQLite database
2. Train the ML model (if not already trained)
3. Start the Flask server on `http://0.0.0.0:5000`

---

## Usage

1. **Upload** - Navigate to the home page and upload a `.eml` email file
2. **Analyze** - The system automatically runs the full analysis pipeline
3. **Investigate** - View the dashboard with threat score, geolocation map, URL/IP tables, and AI classification
4. **Report** - Generate a detailed forensic investigation report
5. **Export** - Export findings as JSON, CSV, or IOC format

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Upload page |
| `/dashboard` | GET | Investigation dashboard |
| `/reports` | GET | Case listing |
| `/settings` | GET | Settings page |
| `/api/upload` | POST | Upload and analyze .eml file |
| `/api/cases` | GET | List all cases |
| `/api/case/<id>` | GET | Get case details |
| `/api/report/<id>` | GET | Get forensic report |
| `/api/export/<id>/<fmt>` | GET | Export report (json/csv/ioc) |
| `/api/stats` | GET | Aggregate statistics |
| `/api/train` | POST | Retrain ML model |
| `/api/settings` | GET | API configuration status |
| `/api/threat-intel/ip/<ip>` | GET | Check IP against threat intel |
| `/api/threat-intel/url` | GET | Check URL against threat intel |
| `/api/threat-intel/domain/<domain>` | GET | Check domain against threat intel |

---

## Testing

Sample `.eml` files are provided in `tests/samples/`:

- `paypal_phishing.eml` - PayPal credential phishing
- `microsoft_365_phishing.eml` - Microsoft 365 phishing
- `banking_credential_harvest.eml` - Chase banking phishing
- `tech_support_scam.eml` - Tech support scam
- `github_notification.eml` - Legitimate GitHub notification
- `newsletter.eml` - Legitimate TechCrunch newsletter

Upload any of these through the web interface to test the analysis pipeline.

---

## Security Considerations

- Never executes uploaded files or email attachments
- Never automatically opens suspicious URLs
- Sanitizes all user input
- Uses secure filenames via `werkzeug.secure_filename`
- Calculates SHA-256 hash for evidence integrity
- API keys stored in `.env` (gitignored)
- Limiting upload size to 16MB
- HTML content extracted safely without script execution

---

## Threat Intelligence

The application integrates with external threat intelligence APIs (all optional):

- **VirusTotal** - URL, IP, and domain reputation scanning
- **AbuseIPDB** - IP address abuse confidence scoring
- **URLhaus** - Malicious URL database by abuse.ch
- **AlienVault OTX** - Open threat intelligence community

If an API key is not configured, the application continues working and displays "Threat intelligence API not configured."

---

## Future Improvements

- PDF report export
- Email attachment sandboxing
- Real-time threat intelligence feeds
- User authentication and multi-tenant support
- Historical trend analysis
- Custom detection rules
- Webhook integrations
- Bulk email analysis
- API rate limiting and caching

---

## License

This project was developed for a cybersecurity hackathon.
