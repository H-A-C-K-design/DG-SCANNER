"""
URL Scanner Module
Author: Durgesh Gaikwad
"""

import re
import requests
import whois
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

class URLScanner:
    """
    Advanced URL Scanner for malicious URL detection
    """
    
    def __init__(self):
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        self.known_shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
        
    def scan(self, url):
        """
        Scan URL for malicious content
        
        Args:
            url: URL to scan
            
        Returns:
            dict: Scan results
        """
        results = {}
        
        # Validate URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Parse URL
        parsed = urlparse(url)
        results['url_info'] = {
            'full_url': url,
            'domain': parsed.netloc,
            'path': parsed.path,
            'scheme': parsed.scheme,
            'params': parsed.params
        }
        
        # Domain analysis
        results['domain_analysis'] = self.analyze_domain(parsed.netloc)
        
        # SSL Certificate check
        results['ssl_check'] = self.check_ssl(url)
        
        # WHOIS lookup
        results['whois_info'] = self.get_whois_info(parsed.netloc)
        
        # Phishing check
        results['phishing_check'] = self.check_phishing_indicators(url)
        
        # Blacklist check
        results['blacklist_check'] = self.check_blacklists(url)
        
        # Response analysis
        results['response_analysis'] = self.analyze_response(url)
        
        # Overall risk
        results['risk_assessment'] = self.assess_risk(results)
        
        return results
        
    def analyze_domain(self, domain):
        """Analyze domain for suspicious characteristics"""
        analysis = {}
        
        # Check TLD
        tld = '.' + domain.split('.')[-1]
        analysis['suspicious_tld'] = tld in self.suspicious_tlds
        
        # Check domain length
        analysis['domain_length'] = len(domain)
        analysis['suspicious_length'] = len(domain) > 30
        
        # Check for IP address
        analysis['is_ip'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
        
        # Check for special characters
        analysis['special_chars'] = sum(1 for c in domain if not c.isalnum() and c not in '.-')
        
        return analysis
        
    def check_ssl(self, url):
        """Check SSL certificate"""
        try:
            hostname = urlparse(url).netloc
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': cert['notAfter'],
                        'subject': dict(x[0] for x in cert['subject'])
                    }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
            
    def get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers[:5] if w.name_servers else []
            }
        except:
            return {'error': 'WHOIS lookup failed'}
            
    def check_phishing_indicators(self, url):
        """Check for phishing indicators"""
        indicators = []
        
        # Check for deceptive patterns
        if re.search(r'(login|signin|account|password|paypal|banking)', url.lower()):
            if not url.startswith('https://'):
                indicators.append("Sensitive keywords without HTTPS")
                
        # Check for data URIs
        if url.startswith('data:'):
            indicators.append("Data URI scheme detected")
            
        # Check for excessive subdomains
        subdomain_count = url.count('.') - 1
        if subdomain_count > 3:
            indicators.append(f"Excessive subdomains: {subdomain_count}")
            
        # Check for @ symbol
        if '@' in url:
            indicators.append("URL contains @ symbol")
            
        return indicators
        
    def check_blacklists(self, url):
        """Check URL against known blacklists"""
        # This would integrate with VirusTotal API or similar
        return {
            'checked': False,
            'note': 'API key not configured for blacklist check'
        }
        
    def analyze_response(self, url):
        """Analyze HTTP response"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            return {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'redirects': len(response.history),
                'final_url': response.url
            }
        except Exception as e:
            return {'error': str(e)}
            
    def assess_risk(self, results):
        """Assess overall risk"""
        risk_score = 0
        
        # Domain risks
        domain_analysis = results.get('domain_analysis', {})
        if domain_analysis.get('suspicious_tld'):
            risk_score += 20
        if domain_analysis.get('is_ip'):
            risk_score += 30
        if domain_analysis.get('suspicious_length'):
            risk_score += 10
            
        # SSL risks
        if not results.get('ssl_check', {}).get('valid', False):
            risk_score += 40
            
        # Phishing indicators
        phishing = results.get('phishing_check', [])
        risk_score += len(phishing) * 15
        
        if risk_score >= 70:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "SAFE"