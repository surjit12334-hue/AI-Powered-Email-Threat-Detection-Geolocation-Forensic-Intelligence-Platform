import sqlite3
import os
from datetime import datetime, timezone
from config import DATABASE_PATH


def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER,
            upload_time TEXT NOT NULL,
            threat_score REAL DEFAULT 0,
            threat_level TEXT DEFAULT 'UNKNOWN',
            ai_classification TEXT DEFAULT 'UNKNOWN',
            ai_confidence REAL DEFAULT 0,
            status TEXT DEFAULT 'analyzed'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            sender TEXT,
            recipient TEXT,
            cc TEXT,
            bcc TEXT,
            subject TEXT,
            date TEXT,
            reply_to TEXT,
            return_path TEXT,
            message_id TEXT,
            mime_type TEXT,
            has_html INTEGER DEFAULT 0,
            has_plain INTEGER DEFAULT 0,
            body_preview TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            risk_score REAL DEFAULT 0,
            risk_level TEXT DEFAULT 'UNKNOWN',
            details TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            analysis_type TEXT NOT NULL,
            result_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            url TEXT NOT NULL,
            domain TEXT,
            risk_score REAL DEFAULT 0,
            risk_level TEXT DEFAULT 'UNKNOWN',
            details TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            country TEXT,
            city TEXT,
            isp TEXT,
            asn TEXT,
            latitude REAL,
            longitude REAL,
            risk_score REAL DEFAULT 0,
            risk_level TEXT DEFAULT 'UNKNOWN',
            details TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            spf_result TEXT DEFAULT 'UNKNOWN',
            dkim_result TEXT DEFAULT 'UNKNOWN',
            dmarc_result TEXT DEFAULT 'UNKNOWN',
            details TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
    ''')

    conn.commit()
    conn.close()


def save_case(case_id, filename, file_hash, file_size):
    conn = get_db()
    conn.execute(
        'INSERT INTO cases (case_id, filename, file_hash, file_size, upload_time) VALUES (?, ?, ?, ?, ?)',
        (case_id, filename, file_hash, file_size, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()


def update_case(case_id, **kwargs):
    conn = get_db()
    updates = []
    values = []
    for key, value in kwargs.items():
        updates.append(f'{key} = ?')
        values.append(value)
    values.append(case_id)
    conn.execute(f'UPDATE cases SET {", ".join(updates)} WHERE case_id = ?', values)
    conn.commit()
    conn.close()


def save_email_info(case_id, sender, recipient, cc, bcc, subject, date,
                    reply_to, return_path, message_id, mime_type,
                    has_html, has_plain, body_preview):
    conn = get_db()
    conn.execute(
        '''INSERT INTO email_info (case_id, sender, recipient, cc, bcc, subject,
           date, reply_to, return_path, message_id, mime_type,
           has_html, has_plain, body_preview) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (case_id, sender, recipient, cc, bcc, subject, date,
         reply_to, return_path, message_id, mime_type, has_html, has_plain, body_preview)
    )
    conn.commit()
    conn.close()


def save_indicator(case_id, indicator_type, indicator_value, risk_score, risk_level, details=''):
    conn = get_db()
    conn.execute(
        'INSERT INTO indicators (case_id, indicator_type, indicator_value, risk_score, risk_level, details) VALUES (?, ?, ?, ?, ?, ?)',
        (case_id, indicator_type, indicator_value, risk_score, risk_level, details)
    )
    conn.commit()
    conn.close()


def save_url_analysis(case_id, url, domain, risk_score, risk_level, details=''):
    conn = get_db()
    conn.execute(
        'INSERT INTO url_analysis (case_id, url, domain, risk_score, risk_level, details) VALUES (?, ?, ?, ?, ?, ?)',
        (case_id, url, domain, risk_score, risk_level, details)
    )
    conn.commit()
    conn.close()


def save_ip_analysis(case_id, ip_address, country, city, isp, asn,
                     latitude, longitude, risk_score, risk_level, details=''):
    conn = get_db()
    conn.execute(
        '''INSERT INTO ip_analysis (case_id, ip_address, country, city, isp, asn,
           latitude, longitude, risk_score, risk_level, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (case_id, ip_address, country, city, isp, asn, latitude, longitude,
         risk_score, risk_level, details)
    )
    conn.commit()
    conn.close()


def save_auth_results(case_id, spf_result, dkim_result, dmarc_result, details=''):
    conn = get_db()
    conn.execute(
        'INSERT INTO auth_results (case_id, spf_result, dkim_result, dmarc_result, details) VALUES (?, ?, ?, ?, ?)',
        (case_id, spf_result, dkim_result, dmarc_result, details)
    )
    conn.commit()
    conn.close()


def save_analysis_result(case_id, analysis_type, result_data):
    import json
    conn = get_db()
    conn.execute(
        'INSERT INTO analysis_results (case_id, analysis_type, result_data, created_at) VALUES (?, ?, ?, ?)',
        (case_id, analysis_type, json.dumps(result_data), datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()


def get_case(case_id):
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE case_id = ?', (case_id,)).fetchone()
    conn.close()
    return dict(case) if case else None


def get_all_cases():
    conn = get_db()
    cases = conn.execute('SELECT * FROM cases ORDER BY upload_time DESC').fetchall()
    conn.close()
    return [dict(c) for c in cases]


def get_email_info(case_id):
    conn = get_db()
    info = conn.execute('SELECT * FROM email_info WHERE case_id = ?', (case_id,)).fetchone()
    conn.close()
    return dict(info) if info else None


def get_indicators(case_id):
    conn = get_db()
    indicators = conn.execute('SELECT * FROM indicators WHERE case_id = ?', (case_id,)).fetchall()
    conn.close()
    return [dict(i) for i in indicators]


def get_url_analyses(case_id):
    conn = get_db()
    urls = conn.execute('SELECT * FROM url_analysis WHERE case_id = ?', (case_id,)).fetchall()
    conn.close()
    return [dict(u) for u in urls]


def get_ip_analyses(case_id):
    conn = get_db()
    ips = conn.execute('SELECT * FROM ip_analysis WHERE case_id = ?', (case_id,)).fetchall()
    conn.close()
    return [dict(i) for i in ips]


def get_auth_results(case_id):
    conn = get_db()
    auth = conn.execute('SELECT * FROM auth_results WHERE case_id = ?', (case_id,)).fetchone()
    conn.close()
    return dict(auth) if auth else None
