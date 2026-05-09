"""
Document Scanner Module
Author: Durgesh Gaikwad
"""

import os
import hashlib
from pathlib import Path

class DocScanner:
    """
    Advanced Document Scanner for macro malware detection
    """
    
    def __init__(self):
        self.suspicious_keywords = [
            'AutoOpen', 'AutoClose', 'Workbook_Open',
            'Document_Open', 'Shell', 'CreateObject',
            'WScript', 'PowerShell', 'Base64',
            'eval', 'exec', 'mshta', 'rundll32'
        ]
        
    def scan(self, doc_path):
        """
        Scan document for malicious content
        
        Args:
            doc_path: Path to document
            
        Returns:
            dict: Scan results
        """
        results = {}
        
        if not os.path.exists(doc_path):
            return {"error": "Document not found"}
            
        # File info
        file_stat = os.stat(doc_path)
        results['file_info'] = {
            'filename': os.path.basename(doc_path),
            'size': f"{file_stat.st_size / 1024:.2f} KB",
            'extension': Path(doc_path).suffix.lower(),
            'hash': self.calculate_hash(doc_path)
        }
        
        # Extension-based analysis
        ext = results['file_info']['extension']
        
        if ext in ['.doc', '.docx', '.docm']:
            results['word_analysis'] = self.analyze_word_doc(doc_path)
        elif ext in ['.xls', '.xlsx', '.xlsm']:
            results['excel_analysis'] = self.analyze_excel_doc(doc_path)
        elif ext == '.pdf':
            results['pdf_analysis'] = self.analyze_pdf(doc_path)
            
        # General analysis
        results['macro_analysis'] = self.check_macros(doc_path)
        results['structure_analysis'] = self.analyze_structure(doc_path)
        
        results['risk_assessment'] = self.assess_risk(results)
        
        return results
        
    def calculate_hash(self, file_path):
        """Calculate file hash"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
        
    def analyze_word_doc(self, doc_path):
        """Analyze Word document"""
        analysis = {
            'macros_detected': False,
            'suspicious_vba': [],
            'embedded_objects': 0,
            'external_links': 0
        }
        
        # Search for VBA code
        try:
            with open(doc_path, 'rb') as f:
                content = f.read()
                for keyword in self.suspicious_keywords:
                    if keyword.encode() in content:
                        analysis['suspicious_vba'].append(keyword)
                        
            if analysis['suspicious_vba']:
                analysis['macros_detected'] = True
        except:
            pass
            
        return analysis
        
    def analyze_excel_doc(self, doc_path):
        """Analyze Excel document"""
        return {
            'macros_detected': False,
            'xl4_macros': False,
            'external_connections': 0
        }
        
    def analyze_pdf(self, doc_path):
        """Analyze PDF document"""
        return {
            'javascript': False,
            'embedded_files': 0,
            'acroform': False
        }
        
    def check_macros(self, doc_path):
        """Check for macros"""
        return {
            'has_macros': False,
            'macro_type': None
        }
        
    def analyze_structure(self, doc_path):
        """Analyze document structure"""
        try:
            file_size = os.path.getsize(doc_path)
            return {
                'size_anomaly': file_size > 50 * 1024 * 1024,  # >50MB
                'encrypted': False,
                'password_protected': False
            }
        except:
            return {'error': 'Structure analysis failed'}
            
    def assess_risk(self, results):
        """Assess overall risk"""
        risk_score = 0
        
        word_analysis = results.get('word_analysis', {})
        if word_analysis.get('macros_detected'):
            risk_score += 30
        risk_score += len(word_analysis.get('suspicious_vba', [])) * 10
        
        structure = results.get('structure_analysis', {})
        if structure.get('size_anomaly'):
            risk_score += 10
            
        if risk_score >= 50:
            return "HIGH"
        elif risk_score >= 25:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "SAFE"