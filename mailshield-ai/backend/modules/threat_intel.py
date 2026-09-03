import os
import requests
import time
from config import (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY,
                    URLHAUS_API_KEY, ALIENVAULT_OTX_API_KEY)


class ThreatIntelService:
    """Generic threat intelligence API service layer."""

    def __init__(self):
        self.vt_key = VIRUSTOTAL_API_KEY
        self.abuseipdb_key = ABUSEIPDB_API_KEY
        self.urlhaus_key = URLHAUS_API_KEY
        self.otx_key = ALIENVAULT_OTX_API_KEY

    def _safe_request(self, url, headers=None, params=None, timeout=10):
        """Make a safe HTTP request with error handling."""
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            return None
        except (requests.RequestException, ValueError):
            return None

    # --- VirusTotal ---
    def vt_check_url(self, url):
        if not self.vt_key:
            return {'status': 'unconfigured', 'source': 'VirusTotal'}
        result = self._safe_request(
            f'https://www.virustotal.com/api/v3/urls',
            headers={'x-apikey': self.vt_key},
            params={'url': url},
        )
        if not result:
            return {'status': 'error', 'source': 'VirusTotal'}
        try:
            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 1
            return {
                'status': 'ok',
                'source': 'VirusTotal',
                'malicious': malicious,
                'total': total,
                'ratio': round(malicious / total * 100, 1) if total else 0,
                'clean': stats.get('clean', 0),
                'unrated': stats.get('unrated', 0),
            }
        except Exception:
            return {'status': 'error', 'source': 'VirusTotal'}

    def vt_check_ip(self, ip_address):
        if not self.vt_key:
            return {'status': 'unconfigured', 'source': 'VirusTotal'}
        result = self._safe_request(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
            headers={'x-apikey': self.vt_key},
        )
        if not result:
            return {'status': 'error', 'source': 'VirusTotal'}
        try:
            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 1
            country = result.get('data', {}).get('attributes', {}).get('country', 'Unknown')
            as_owner = result.get('data', {}).get('attributes', {}).get('as_owner', 'Unknown')
            return {
                'status': 'ok',
                'source': 'VirusTotal',
                'malicious': malicious,
                'total': total,
                'ratio': round(malicious / total * 100, 1) if total else 0,
                'country': country,
                'as_owner': as_owner,
            }
        except Exception:
            return {'status': 'error', 'source': 'VirusTotal'}

    def vt_check_domain(self, domain):
        if not self.vt_key:
            return {'status': 'unconfigured', 'source': 'VirusTotal'}
        result = self._safe_request(
            f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers={'x-apikey': self.vt_key},
        )
        if not result:
            return {'status': 'error', 'source': 'VirusTotal'}
        try:
            attrs = result.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 1
            reputation = attrs.get('reputation', 0)
            return {
                'status': 'ok',
                'source': 'VirusTotal',
                'malicious': malicious,
                'total': total,
                'ratio': round(malicious / total * 100, 1) if total else 0,
                'reputation': reputation,
                'registrar': attrs.get('registrar', 'Unknown'),
                'creation_date': attrs.get('creation_date', 'Unknown'),
            }
        except Exception:
            return {'status': 'error', 'source': 'VirusTotal'}

    # --- AbuseIPDB ---
    def abuseipdb_check(self, ip_address):
        if not self.abuseipdb_key:
            return {'status': 'unconfigured', 'source': 'AbuseIPDB'}
        result = self._safe_request(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': self.abuseipdb_key, 'Accept': 'application/json'},
            params={'ipAddress': ip_address, 'maxAgeInDays': '90'},
        )
        if not result:
            return {'status': 'error', 'source': 'AbuseIPDB'}
        try:
            data = result.get('data', {})
            return {
                'status': 'ok',
                'source': 'AbuseIPDB',
                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country_code': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'usage_type': data.get('usageType', 'Unknown'),
                'is_tor': data.get('isTor', False),
                'is_whitelisted': data.get('isWhitelisted', False),
            }
        except Exception:
            return {'status': 'error', 'source': 'AbuseIPDB'}

    # --- URLhaus ---
    def urlhaus_check_url(self, url):
        if not self.urlhaus_key:
            return {'status': 'unconfigured', 'source': 'URLhaus'}
        result = self._safe_request(
            'https://urlhaus-api.abuse.ch/v1/url/',
            params={'url': url},
        )
        if not result:
            return {'status': 'error', 'source': 'URLhaus'}
        try:
            query_status = result.get('query_status', '')
            if query_status == 'no_results':
                return {'status': 'ok', 'source': 'URLhaus', 'threat': 'not_listed'}
            return {
                'status': 'ok',
                'source': 'URLhaus',
                'threat': result.get('threat', 'unknown'),
                'url_status': result.get('url_status', 'unknown'),
                'tags': result.get('tags', []),
                'date_added': result.get('date_added', 'unknown'),
            }
        except Exception:
            return {'status': 'error', 'source': 'URLhaus'}

    def urlhaus_check_domain(self, domain):
        if not self.urlhaus_key:
            return {'status': 'unconfigured', 'source': 'URLhaus'}
        result = self._safe_request(
            'https://urlhaus-api.abuse.ch/v1/host/',
            params={'host': domain},
        )
        if not result:
            return {'status': 'error', 'source': 'URLhaus'}
        try:
            query_status = result.get('query_status', '')
            if query_status == 'no_results':
                return {'status': 'ok', 'source': 'URLhaus', 'threat': 'not_listed'}
            return {
                'status': 'ok',
                'source': 'URLhaus',
                'threat': 'listed',
                'urls_online': result.get('urls_online', 0),
                'blacklists': result.get('blacklists', {}),
            }
        except Exception:
            return {'status': 'error', 'source': 'URLhaus'}

    # --- AlienVault OTX ---
    def otx_check_ip(self, ip_address):
        if not self.otx_key:
            return {'status': 'unconfigured', 'source': 'AlienVault OTX'}
        result = self._safe_request(
            f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general',
            headers={'X-OTX-API-KEY': self.otx_key},
        )
        if not result:
            return {'status': 'error', 'source': 'AlienVault OTX'}
        try:
            pulse_count = result.get('pulse_info', {}).get('count', 0)
            return {
                'status': 'ok',
                'source': 'AlienVault OTX',
                'pulse_count': pulse_count,
                'reputation': result.get('reputation', 0),
                'country': result.get('country_code', 'Unknown'),
                'asn': result.get('asn', 'Unknown'),
            }
        except Exception:
            return {'status': 'error', 'source': 'AlienVault OTX'}

    def otx_check_domain(self, domain):
        if not self.otx_key:
            return {'status': 'unconfigured', 'source': 'AlienVault OTX'}
        result = self._safe_request(
            f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general',
            headers={'X-OTX-API-KEY': self.otx_key},
        )
        if not result:
            return {'status': 'error', 'source': 'AlienVault OTX'}
        try:
            pulse_count = result.get('pulse_info', {}).get('count', 0)
            return {
                'status': 'ok',
                'source': 'AlienVault OTX',
                'pulse_count': pulse_count,
                'alexa': result.get('alexa', 'Unknown'),
            }
        except Exception:
            return {'status': 'error', 'source': 'AlienVault OTX'}

    # --- Aggregate checks ---
    def check_ip(self, ip_address):
        """Run all available IP checks."""
        results = {}
        results['virustotal'] = self.vt_check_ip(ip_address)
        results['abuseipdb'] = self.abuseipdb_check(ip_address)
        results['otx'] = self.otx_check_ip(ip_address)
        return results

    def check_url(self, url):
        """Run all available URL checks."""
        results = {}
        results['virustotal'] = self.vt_check_url(url)
        results['urlhaus'] = self.urlhaus_check_url(url)
        return results

    def check_domain(self, domain):
        """Run all available domain checks."""
        results = {}
        results['virustotal'] = self.vt_check_domain(domain)
        results['urlhaus'] = self.urlhaus_check_domain(domain)
        results['otx'] = self.otx_check_domain(domain)
        return results

    def get_config_status(self):
        """Return which APIs are configured."""
        return {
            'virustotal': bool(self.vt_key),
            'abuseipdb': bool(self.abuseipdb_key),
            'urlhaus': bool(self.urlhaus_key),
            'otx': bool(self.otx_key),
        }


# Singleton instance
threat_intel = ThreatIntelService()
