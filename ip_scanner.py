"""
IP Scanner Module
Author: Durgesh Gaikwad
"""

import socket
import requests
import json
from datetime import datetime

class IPScanner:
    """
    Advanced IP Scanner for threat analysis
    """
    
    def __init__(self):
        self.cloud_ranges = [
            '13.', '52.', '54.', '35.', '18.', '23.'  # AWS
        ]
        
    def scan(self, ip):
        """
        Scan IP address for threats
        
        Args:
            ip: IP address to scan
            
        Returns:
            dict: Scan results
        """
        results = {}
        
        # Validate IP
        try:
            socket.inet_aton(ip)
        except:
            return {"error": "Invalid IP address"}
            
        results['ip_info'] = {
            'ip': ip,
            'is_private': self.is_private_ip(ip),
            'is_cloud': self.is_cloud_ip(ip),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Reverse DNS
        results['dns_info'] = self.reverse_dns(ip)
        
        # Geo location
        results['geolocation'] = self.get_geolocation(ip)
        
        # Port scan (basic)
        results['port_scan'] = self.basic_port_scan(ip)
        
        # AbuseIPDB check
        results['abuse_check'] = self.check_abuseipdb(ip)
        
        # Threat assessment
        results['risk_assessment'] = self.assess_risk(results)
        
        return results
        
    def is_private_ip(self, ip):
        """Check if IP is private"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255')
        ]
        
        ip_parts = list(map(int, ip.split('.')))
        ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
        
        for start, end in private_ranges:
            start_parts = list(map(int, start.split('.')))
            end_parts = list(map(int, end.split('.')))
            start_int = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
            end_int = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]
            
            if start_int <= ip_int <= end_int:
                return True
        return False
        
    def is_cloud_ip(self, ip):
        """Check if IP belongs to cloud provider"""
        for range_start in self.cloud_ranges:
            if ip.startswith(range_start):
                return True
        return False
        
    def reverse_dns(self, ip):
        """Perform reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {
                'hostname': hostname,
                'resolves': True
            }
        except:
            return {
                'hostname': None,
                'resolves': False
            }
            
    def get_geolocation(self, ip):
        """Get IP geolocation"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown')
                }
        except:
            pass
        return {'error': 'Geolocation failed'}
        
    def basic_port_scan(self, ip):
        """Basic port scan of common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
        open_ports = []
        
        for port in common_ports[:5]:  # Limit to 5 for speed
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = socket.getservbyport(port)
                    open_ports.append({'port': port, 'service': service})
                sock.close()
            except:
                pass
                
        return {
            'scanned_ports': len(common_ports[:5]),
            'open_ports': open_ports,
            'open_count': len(open_ports)
        }
        
    def check_abuseipdb(self, ip):
        """Check IP against AbuseIPDB"""
        # This would require an API key
        return {
            'checked': False,
            'note': 'API key not configured for AbuseIPDB'
        }
        
    def assess_risk(self, results):
        """Assess overall risk"""
        risk_score = 0
        
        # Port scan risks
        port_scan = results.get('port_scan', {})
        risk_ports = {21, 23, 445, 3389}
        for port_info in port_scan.get('open_ports', []):
            if port_info['port'] in risk_ports:
                risk_score += 15
                
        # DNS risks
        if not results.get('dns_info', {}).get('resolves', True):
            risk_score += 10
            
        # Geolocation risks
        # (Would check against known malicious countries)
        
        if risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "SAFE"