"""
APK Scanner Module
Author: Durgesh Gaikwad
"""

import os
import zipfile
import hashlib
from pathlib import Path

class APKScanner:
    """
    Advanced APK Scanner for Android malware detection
    """
    
    def __init__(self):
        self.suspicious_permissions = [
            'RECORD_AUDIO',
            'READ_SMS',
            'SEND_SMS',
            'READ_CONTACTS',
            'ACCESS_FINE_LOCATION',
            'CAMERA',
            'SYSTEM_ALERT_WINDOW',
            'INSTALL_PACKAGES',
            'READ_EXTERNAL_STORAGE',
            'WRITE_EXTERNAL_STORAGE'
        ]
        
    def scan(self, apk_path):
        """
        Scan APK for malicious content
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            dict: Scan results
        """
        results = {}
        
        if not os.path.exists(apk_path):
            return {"error": "APK file not found"}
            
        if not apk_path.endswith('.apk'):
            return {"error": "File is not an APK"}
            
        # Basic info
        results['file_info'] = {
            'filename': os.path.basename(apk_path),
            'size': f"{os.path.getsize(apk_path) / (1024*1024):.2f} MB",
            'hash': self.calculate_hash(apk_path)
        }
        
        # Extract and analyze
        try:
            manifest = self.extract_manifest(apk_path)
            if manifest:
                results['manifest_analysis'] = self.analyze_manifest(manifest)
                
            results['dex_analysis'] = self.analyze_dex(apk_path)
            results['resource_analysis'] = self.analyze_resources(apk_path)
            
        except Exception as e:
            results['extraction_error'] = str(e)
            
        results['risk_assessment'] = self.assess_risk(results)
        
        return results
        
    def calculate_hash(self, file_path):
        """Calculate SHA256 hash"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
        
    def extract_manifest(self, apk_path):
        """Extract AndroidManifest.xml"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if 'AndroidManifest.xml' in zf.namelist():
                    # In production, would decode binary XML
                    return {'found': True, 'raw_available': True}
        except:
            pass
        return None
        
    def analyze_manifest(self, manifest):
        """Analyze AndroidManifest.xml"""
        analysis = {}
        
        # Permission analysis (simulated)
        analysis['requested_permissions'] = [
            'INTERNET',
            'ACCESS_NETWORK_STATE',
            'READ_EXTERNAL_STORAGE',
            'WRITE_EXTERNAL_STORAGE'
        ]
        
        # Check for suspicious permissions
        analysis['suspicious_permissions'] = []
        for perm in analysis['requested_permissions']:
            if perm in self.suspicious_permissions:
                analysis['suspicious_permissions'].append(perm)
                
        analysis['suspicious_count'] = len(analysis['suspicious_permissions'])
        
        # Entry point analysis
        analysis['activities'] = 3
        analysis['services'] = 1
        analysis['receivers'] = 1
        
        return analysis
        
    def analyze_dex(self, apk_path):
        """Analyze DEX files"""
        # In production, would use androguard or similar
        return {
            'dex_count': 1,
            'classes_estimate': 150,
            'obfuscation_detected': False
        }
        
    def analyze_resources(self, apk_path):
        """Analyze APK resources"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                files = zf.namelist()
                return {
                    'total_files': len(files),
                    'native_libs': [f for f in files if f.endswith('.so')],
                    'assets_count': len([f for f in files if f.startswith('assets/')])
                }
        except:
            return {'error': 'Resource analysis failed'}
            
    def assess_risk(self, results):
        """Assess overall risk"""
        risk_score = 0
        
        manifest = results.get('manifest_analysis', {})
        if manifest:
            risk_score += manifest.get('suspicious_count', 0) * 10
            
        dex = results.get('dex_analysis', {})
        if dex.get('obfuscation_detected'):
            risk_score += 20
            
        if risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "SAFE"