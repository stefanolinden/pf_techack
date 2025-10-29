#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from zapv2 import ZAPv2
import nmap
import sys
from typing import Dict, List, Any
from utils.helpers import validate_url, normalize_url

class WebSecurityScanner:
    def __init__(self, target_url: str):
        self.target_url = validate_url(target_url)
        self.findings = []
        self.session = requests.Session()
        self.session.timeout = (10, 30)  # (connect timeout, read timeout)
        self.session.verify = False  # Allow self-signed certificates
        # Suppress only the single warning from urllib3 needed.
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
    def scan_xss(self) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '\'><script>alert("XSS")</script>',
            '"><img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg/onload=alert("XSS")>',
        ]
        findings = []
        
        # First check if the site is accessible
        try:
            response = self.session.get(self.target_url, timeout=(5, 15))
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error accessing {self.target_url}: {str(e)}")
            return findings
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                for payload in payloads:
                    # Test each input field
                    for input_field in form.find_all('input'):
                        if input_field.get('type') not in ['submit', 'button', 'image']:
                            data = {i.get('name'): '' for i in form.find_all('input') if i.get('name')}
                            data[input_field.get('name')] = payload
                            
                            try:
                                if form.get('method', 'get').lower() == 'post':
                                    test_response = self.session.post(self.target_url, data=data)
                                else:
                                    test_response = self.session.get(self.target_url, params=data)
                                
                                if payload in test_response.text:
                                    findings.append({
                                        'type': 'XSS',
                                        'severity': 'High',
                                        'url': self.target_url,
                                        'parameter': input_field.get('name'),
                                        'payload': payload
                                    })
                            except requests.exceptions.RequestException:
                                continue
                            
        except Exception as e:
            print(f"Error during XSS scan: {str(e)}")
            
        return findings

    def scan_sqli(self) -> List[Dict[str, Any]]:
        """Scan for SQL Injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL--",
        ]
        findings = []
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                for payload in payloads:
                    for input_field in form.find_all('input'):
                        if input_field.get('type') not in ['submit', 'button', 'image']:
                            data = {i.get('name'): '' for i in form.find_all('input') if i.get('name')}
                            data[input_field.get('name')] = payload
                            
                            try:
                                if form.get('method', 'get').lower() == 'post':
                                    test_response = self.session.post(self.target_url, data=data)
                                else:
                                    test_response = self.session.get(self.target_url, params=data)
                                
                                # Look for SQL error messages
                                error_patterns = [
                                    "SQL syntax",
                                    "mysql_fetch",
                                    "ORA-",
                                    "PostgreSQL",
                                    "SQLite3::"
                                ]
                                
                                for pattern in error_patterns:
                                    if pattern.lower() in test_response.text.lower():
                                        findings.append({
                                            'type': 'SQL Injection',
                                            'severity': 'Critical',
                                            'url': self.target_url,
                                            'parameter': input_field.get('name'),
                                            'payload': payload,
                                            'error_pattern': pattern
                                        })
                            except requests.exceptions.RequestException:
                                continue
                            
        except Exception as e:
            print(f"Error during SQL injection scan: {str(e)}")
            
        return findings

    def scan_directory_traversal(self) -> List[Dict[str, Any]]:
        """Scan for Directory Traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        findings = []
        
        for payload in payloads:
            try:
                url = f"{self.target_url}?file={payload}"
                response = self.session.get(url)
                
                # Check for common patterns that might indicate successful traversal
                indicators = [
                    "root:x:",
                    "[fonts]",
                    "boot loader",
                    "etc/passwd",
                    "win.ini"
                ]
                
                for indicator in indicators:
                    if indicator in response.text:
                        findings.append({
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'url': url,
                            'payload': payload,
                            'indicator': indicator
                        })
                        break
                        
            except requests.exceptions.RequestException:
                continue
                
        return findings

    def scan_csrf(self) -> List[Dict[str, Any]]:
        """Scan for CSRF vulnerabilities"""
        findings = []
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                # Check for CSRF token
                has_csrf_token = False
                
                # Common CSRF token field names
                csrf_fields = [
                    'csrf', 'csrftoken', 'csrf_token', 
                    'csrf-token', '_csrf', 'xsrf', 
                    '_token', 'token'
                ]
                
                for input_field in form.find_all('input'):
                    field_name = input_field.get('name', '').lower()
                    if any(token in field_name for token in csrf_fields):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    findings.append({
                        'type': 'CSRF',
                        'severity': 'Medium',
                        'url': self.target_url,
                        'form_action': form.get('action', ''),
                        'form_method': form.get('method', 'get'),
                        'description': 'Form lacks CSRF protection'
                    })
                    
        except Exception as e:
            print(f"Error during CSRF scan: {str(e)}")
            
        return findings

    def run_full_scan(self) -> Dict[str, List[Dict[str, Any]]]:
        """Run all security scans"""
        results = {
            'xss': self.scan_xss(),
            'sqli': self.scan_sqli(),
            'directory_traversal': self.scan_directory_traversal(),
            'csrf': self.scan_csrf()
        }
        return results

def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)
        
    target_url = sys.argv[1]
    scanner = WebSecurityScanner(target_url)
    results = scanner.run_full_scan()
    
    # Print results to console (basic output)
    for vuln_type, findings in results.items():
        if findings:
            print(f"\n=== {vuln_type.upper()} Findings ===")
            for finding in findings:
                print("\nVulnerability Details:")
                for key, value in finding.items():
                    print(f"{key}: {value}")

if __name__ == "__main__":
    main()