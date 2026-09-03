import re


def analyze_authentication(parsed_email):
    """Analyze email authentication headers (SPF, DKIM, DMARC)."""
    headers = parsed_email.get('headers', {})
    result = {
        'spf': {'status': 'UNKNOWN', 'details': ''},
        'dkim': {'status': 'UNKNOWN', 'details': ''},
        'dmarc': {'status': 'UNKNOWN', 'details': ''},
        'risk_score': 0,
        'findings': [],
    }

    # Check Authentication-Results header
    auth_header = ''
    for key, value in headers.items():
        if key.lower() == 'authentication-results':
            auth_header += ' ' + str(value) if auth_header else str(value)

    # Check Arc-Authentication-Results as well
    for key, value in headers.items():
        if key.lower() == 'arc-authentication-results':
            auth_header += ' ' + str(value) if auth_header else str(value)

    if auth_header:
        auth_lower = auth_header.lower()

        # Parse SPF result
        spf_match = re.search(r'spf[=:]\s*(\w+)', auth_lower)
        if spf_match:
            spf_status = spf_match.group(1).upper()
            if spf_status == 'PASS':
                result['spf']['status'] = 'PASS'
                result['spf']['details'] = 'SPF check passed - sender IP is authorized.'
            elif spf_status in ['FAIL', 'SOFTFAIL', 'NEUTRAL', 'HARDFAIL']:
                result['spf']['status'] = 'FAIL'
                result['spf']['details'] = f'SPF check failed ({spf_status}) - sender IP is not authorized.'
                result['risk_score'] += 15
                result['findings'].append({
                    'type': 'SPF_FAIL',
                    'severity': 'HIGH',
                    'description': f'SPF authentication failed ({spf_status})',
                })
            elif spf_status == 'NONE':
                result['spf']['status'] = 'NONE'
                result['spf']['details'] = 'No SPF record found for the sender domain.'
                result['risk_score'] += 10
            else:
                result['spf']['status'] = spf_status.upper()

        # Parse DKIM result
        dkim_match = re.search(r'dkim[=:]\s*(\w+)', auth_lower)
        if dkim_match:
            dkim_status = dkim_match.group(1).upper()
            if dkim_status == 'PASS':
                result['dkim']['status'] = 'PASS'
                result['dkim']['details'] = 'DKIM signature verified successfully.'
            elif dkim_status in ['FAIL', 'REJECT', 'NEUTRAL', 'TEMPERROR', 'PERMERROR']:
                result['dkim']['status'] = 'FAIL'
                result['dkim']['details'] = f'DKIM verification failed ({dkim_status}).'
                result['risk_score'] += 15
                result['findings'].append({
                    'type': 'DKIM_FAIL',
                    'severity': 'HIGH',
                    'description': f'DKIM authentication failed ({dkim_status})',
                })
            elif dkim_status == 'NONE':
                result['dkim']['status'] = 'NONE'
                result['dkim']['details'] = 'No DKIM signature found.'
                result['risk_score'] += 5
            else:
                result['dkim']['status'] = dkim_status.upper()

        # Parse DMARC result
        dmarc_match = re.search(r'dmarc[=:]\s*(\w+)', auth_lower)
        if dmarc_match:
            dmarc_status = dmarc_match.group(1).upper()
            if dmarc_status == 'PASS':
                result['dmarc']['status'] = 'PASS'
                result['dmarc']['details'] = 'DMARC policy check passed.'
            elif dmarc_status in ['FAIL', 'REJECT', 'QUARANTINE']:
                result['dmarc']['status'] = 'FAIL'
                result['dmarc']['details'] = f'DMARC policy check failed ({dmarc_status}).'
                result['risk_score'] += 15
                result['findings'].append({
                    'type': 'DMARC_FAIL',
                    'severity': 'HIGH',
                    'description': f'DMARC authentication failed ({dmarc_status})',
                })
            elif dmarc_status == 'NONE':
                result['dmarc']['status'] = 'NONE'
                result['dmarc']['details'] = 'No DMARC policy configured for sender domain.'
                result['risk_score'] += 5
            else:
                result['dmarc']['status'] = dmarc_status.upper()

    # Check for Received-SPF header (older format)
    if result['spf']['status'] == 'UNKNOWN':
        for key, value in headers.items():
            if key.lower() == 'received-spf':
                value_str = str(value).lower()
                if 'pass' in value_str:
                    result['spf']['status'] = 'PASS'
                    result['spf']['details'] = 'SPF check passed (from Received-SPF header).'
                elif 'fail' in value_str or 'softfail' in value_str:
                    result['spf']['status'] = 'FAIL'
                    result['spf']['details'] = 'SPF check failed (from Received-SPF header).'
                    result['risk_score'] += 15
                    result['findings'].append({
                        'type': 'SPF_FAIL',
                        'severity': 'HIGH',
                        'description': 'SPF authentication failed (Received-SPF)',
                    })
                break

    # Summary finding if all unknown
    if (result['spf']['status'] == 'UNKNOWN' and
        result['dkim']['status'] == 'UNKNOWN' and
        result['dmarc']['status'] == 'UNKNOWN'):
        result['findings'].append({
            'type': 'NO_AUTH_HEADERS',
            'severity': 'MEDIUM',
            'description': 'No email authentication headers found in the message.',
        })
        result['risk_score'] += 10

    return result
