import re
import os
from datetime import datetime


# Dangerous file extensions
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.msp', '.mst',
    '.cpl', '.hta', '.inf', '.reg', '.rgs', '.sct', '.shb', '.shs',
    '.lnk', '.url', '.application', '.gadget', '.webpnp', '.xnk',
}

# Archive extensions that may contain malware
ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
}

# Document macros
MACRO_EXTENSIONS = {
    '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
    '.dot', '.dotm', '.xlt', '.xltm', '.pot', '.potm',
}


def analyze_attachments(attachments):
    """Analyze email attachments for risk indicators."""
    results = []
    total_risk = 0

    for att in attachments:
        filename = att.get('filename', '')
        content_type = att.get('content_type', '')
        size = att.get('size', 0)

        analysis = {
            'filename': filename,
            'content_type': content_type,
            'size': size,
            'size_human': _human_size(size),
            'risk_score': 0,
            'risk_level': 'LOW',
            'flags': [],
        }

        # Get file extension
        _, ext = os.path.splitext(filename.lower())

        # Check dangerous extensions
        if ext in DANGEROUS_EXTENSIONS:
            analysis['flags'].append('DANGEROUS_EXECUTABLE')
            analysis['risk_score'] += 40

        # Check macro-enabled documents
        if ext in MACRO_EXTENSIONS:
            analysis['flags'].append('MACRO_DOCUMENT')
            analysis['risk_score'] += 20

        # Check archive files
        if ext in ARCHIVE_EXTENSIONS:
            analysis['flags'].append('ARCHIVE_FILE')
            analysis['risk_score'] += 10

        # Check double extensions (e.g., document.pdf.exe)
        parts = filename.split('.')
        if len(parts) > 2:
            real_ext = '.' + parts[-1].lower()
            if real_ext in DANGEROUS_EXTENSIONS:
                analysis['flags'].append('DOUBLE_EXTENSION_TRICK')
                analysis['risk_score'] += 35

        # Check for hidden extensions
        if filename.endswith(' '):
            analysis['flags'].append('HIDDEN_EXTENSION_SPACE')
            analysis['risk_score'] += 25

        # Check suspicious filenames
        suspicious_names = ['invoice', 'receipt', 'payment', 'urgent', 'confidential',
                            'salary', 'password', 'credentials', 'backup']
        for name in suspicious_names:
            if name in filename.lower():
                analysis['flags'].append(f'SUSPICIOUS_NAME:{name.upper()}')
                analysis['risk_score'] += 5
                break

        # Check MIME type mismatch
        if content_type and ext:
            mime_ext_map = {
                'application/pdf': '.pdf',
                'application/msword': '.doc',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
                'text/plain': '.txt',
                'text/html': '.html',
            }
            expected_ext = mime_ext_map.get(content_type)
            if expected_ext and ext != expected_ext:
                analysis['flags'].append('MIME_TYPE_MISMATCH')
                analysis['risk_score'] += 15

        # Oversized attachment
        if size > 10 * 1024 * 1024:  # > 10MB
            analysis['flags'].append('OVERSIZED_ATTACHMENT')
            analysis['risk_score'] += 5

        # Empty attachment
        if size == 0:
            analysis['flags'].append('EMPTY_ATTACHMENT')
            analysis['risk_score'] += 10

        # Calculate risk level
        if analysis['risk_score'] >= 40:
            analysis['risk_level'] = 'CRITICAL'
        elif analysis['risk_score'] >= 25:
            analysis['risk_level'] = 'HIGH'
        elif analysis['risk_score'] >= 10:
            analysis['risk_level'] = 'MEDIUM'
        else:
            analysis['risk_level'] = 'LOW'

        total_risk += analysis['risk_score']
        results.append(analysis)

    avg_risk = total_risk / len(results) if results else 0

    return {
        'attachments': results,
        'total_attachments': len(results),
        'dangerous_count': sum(1 for r in results if r['risk_level'] in ['HIGH', 'CRITICAL']),
        'total_risk_score': total_risk,
        'average_risk_score': round(avg_risk, 1),
    }


def _human_size(size_bytes):
    """Convert bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
