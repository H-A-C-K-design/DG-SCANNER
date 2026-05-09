"""
File Scanner Module
Author: Durgesh Gaikwad
"""

import hashlib
import os
import magic
import yara
import time
from pathlib import Path

class FileScanner:
    """
    Advanced File Scanner for malicious content detection
    """
    
    def __init__(self):
        self.rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")
        self.load_yara_rules()
        
    def load_yara_rules(self):
        """Load YARA rules for malware detection"""
        try:
            if os.path.exists(self.rules_path):
                rule_files = {}
                for root, dirs, files in os.walk(self.rules_path):
                    for file in files:
                        if file.endswith('.yar') or file.endswith('.yara'):
                            filepath = os.path.join(root, file)
                            namespace = file.replace('.', '_')
                            rule_files[namespace] = filepath
                
                if rule_files:
                    self.yara_rules = yara.compile(filepaths=rule_files)
                else:
                    self.yara_rules = None
            else:
                self.yara_rules = None
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            self.yara_rules = None
            
    def scan(self, file_path):
        """
        Scan file for malicious content
        
        Args:
            file_path: Path to file
            
        Returns:
            dict: Scan results
        """
        results = {}
        
        if not os.path.exists(file_path):
            return {"error": "File not found"}
            
        # Basic file info
        file_stat = os.stat(file_path)
        results['file_info'] = {
            'filename': os.path.basename(file_path),
            'size': f"{file_stat.st_size / 1024:.2f} KB",
            'extension': Path(file_path).suffix,
            'created': time.ctime(file_stat.st_ctime),
            'modified': time.ctime(file_stat.st_mtime)
        }
        
        # File type detection
        try:
            mime = magic.Magic(mime=True)
            file_type = magic.Magic()
            results['file_info']['mime_type'] = mime.from_file(file_path)
            results['file_info']['file_type'] = file_type.from_file(file_path)
        except:
            results['file_info']['mime_type'] = "Unknown"
            results['file_info']['file_type'] = "Unknown"
            
        # Hash calculation
        results['hashes'] = self.calculate_hashes(file_path)
        
        # YARA scan
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(file_path)
                results['yara_matches'] = []
                for match in matches:
                    results['yara_matches'].append({
                        'rule': match.rule,
                        'tags': match.tags,
                        'meta': match.meta
                    })
                results['malicious_yara'] = len(matches) > 0
            except Exception as e:
                results['yara_error'] = str(e)
                
        # Suspicious strings check
        results['suspicious_strings'] = self.check_suspicious_strings(file_path)
        
        # Overall risk assessment
        results['risk_assessment'] = self.assess_risk(results)
        
        return results
        
    def calculate_hashes(self, file_path):
        """Calculate file hashes"""
        hashes = {}
        algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for algo in algorithms.values():
                        algo.update(chunk)
                        
            for name, algo in algorithms.items():
                hashes[name] = algo.hexdigest()
        except Exception as e:
            hashes['error'] = str(e)
            
        return hashes
        
    def check_suspicious_strings(self, file_path):
        """Check for suspicious strings in file"""
        suspicious_patterns = [
            'cmd.exe', 'powershell', 'wget', 'curl', '/bin/bash',
            'eval(', 'exec(', 'base64_decode', 'system(',
            'rm -rf', 'net user', 'reg add', 'schtasks',
            'CreateObject', 'ShellExecute', 'URLDownloadToFile'
        ]
        
        found_strings = []
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                for pattern in suspicious_patterns:
                    if pattern.encode() in content:
                        found_strings.append(pattern)
        except:
            pass
            
        return found_strings
        
    def assess_risk(self, results):
        """Assess overall risk level"""
        risk_score = 0
        
        # YARA matches
        if results.get('malicious_yara', False):
            risk_score += 50
            
        # Suspicious strings
        if len(results.get('suspicious_strings', [])) > 0:
            risk_score += 20
            
        # File type based risk
        high_risk_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.ps1', '.js']
        if results['file_info']['extension'].lower() in high_risk_extensions:
            risk_score += 10
            
        # Determine risk level
        if risk_score >= 70:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "SAFE"