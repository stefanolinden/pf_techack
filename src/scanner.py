"""
Web Security Scanner - Main Scanner Module
Detects multiple vulnerabilities: XSS, SQL Injection, CSRF, Directory Traversal, Information Disclosure, and more
"""
import logging
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from utils.http_client import make_request, parse_forms, get_url_parameters, is_valid_url
from utils.logger import setup_logger
from utils.advanced_scanner import AdvancedScanner

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = setup_logger()


class VulnerabilityScanner:
    """Main scanner class for detecting web vulnerabilities"""
    
    # XSS payloads for testing
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>"
    ]
    
    # SQL Injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ]
    
    # SQL error patterns to detect in responses
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL[-_]Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"SqlClient\.",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_.*",
        r"Warning.*ora_.*"
    ]
    
    # Directory Traversal payloads
    DIR_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....\\\\....\\\\....\\\\windows\\\\win.ini"
    ]
    
    # Directory Traversal success patterns
    DIR_TRAVERSAL_PATTERNS = [
        r"root:.*:0:0:",
        r"\[boot loader\]",
        r"\[fonts\]",
        r"for 16-bit app support"
    ]
    
    # Sensitive information patterns
    SENSITIVE_INFO_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'api_key': r'(?i)(api[_-]?key|apikey)[\s]*[=:]+[\s]*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        'password': r'(?i)password[\s]*[=:]+[\s]*["\']?([^\s"\'<>]{3,})["\']?',
        'private_key': r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
        'aws_key': r'(?i)aws[_-]?access[_-]?key[_-]?id[\s]*[=:]+[\s]*["\']?([A-Z0-9]{20})["\']?',
        'db_conn': r'(?i)(jdbc|mysql|postgresql|mongodb)://[^\s<>"\']+',
        'internal_ip': r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
    }
    
    def __init__(self, target_url: str):
        """
        Initialize scanner with target URL
        
        Args:
            target_url: The URL to scan
        """
        if not is_valid_url(target_url):
            raise ValueError(f"Invalid URL: {target_url}")
        
        self.target_url = target_url
        self.vulnerabilities = []
        self.scanned_urls = set()
        self.advanced_scanner = AdvancedScanner()
        
        logger.info(f"Scanner initialized for target: {target_url}")
    
    def scan(self) -> List[Dict]:
        """
        Perform complete scan for vulnerabilities
        
        Returns:
            List of detected vulnerabilities
        """
        logger.info("Starting vulnerability scan...")
        
        # Run Nmap port scan if available
        self._run_nmap_scan()
        
        # Scan the main URL
        self._scan_url(self.target_url)
        
        # Run advanced security checks
        self._run_advanced_checks()
        
        logger.info(f"Scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _run_nmap_scan(self):
        """Run Nmap port scan"""
        try:
            logger.info("Running Nmap port scan...")
            nmap_result = self.advanced_scanner.scan_ports_nmap(self.target_url)
            
            if 'error' not in nmap_result and nmap_result.get('open_ports'):
                # Report open ports as informational
                open_ports_list = [f"{p['port']}/{p['service']}" for p in nmap_result['open_ports']]
                vulnerability = {
                    'type': 'Port Scan (Nmap)',
                    'severity': 'INFO',
                    'url': self.target_url,
                    'description': f"Found {nmap_result['total_open']} open ports",
                    'evidence': f"Open ports: {', '.join(open_ports_list[:10])}",
                    'ports': nmap_result['open_ports']
                }
                self.vulnerabilities.append(vulnerability)
                logger.info(f"Nmap found {nmap_result['total_open']} open ports")
        except Exception as e:
            logger.warning(f"Nmap scan failed: {e}")
    
    def _run_advanced_checks(self):
        """Run advanced security checks"""
        try:
            response = make_request(self.target_url)
            if not response:
                return
            
            # Check security headers
            missing_headers = self.advanced_scanner.check_security_headers(response)
            if missing_headers:
                for header_info in missing_headers:
                    vulnerability = {
                        'type': 'Missing Security Header',
                        'severity': header_info['severity'],
                        'url': self.target_url,
                        'description': f"Missing {header_info['header']}: {header_info['description']}",
                        'evidence': header_info['recommendation'],
                        'header': header_info['header']
                    }
                    self.vulnerabilities.append(vulnerability)
                logger.warning(f"Found {len(missing_headers)} missing security headers")
            
            # Check SSL/TLS
            ssl_result = self.advanced_scanner.check_ssl_tls(self.target_url)
            if ssl_result and ssl_result.get('weak_protocol'):
                vulnerability = {
                    'type': 'Weak SSL/TLS Configuration',
                    'severity': ssl_result['severity'],
                    'url': self.target_url,
                    'description': f"Weak protocol detected: {ssl_result['protocol']}",
                    'evidence': f"Cipher: {ssl_result.get('cipher', 'unknown')}",
                    'recommendation': 'Use TLS 1.2 or higher'
                }
                self.vulnerabilities.append(vulnerability)
                logger.warning(f"Weak SSL/TLS protocol: {ssl_result['protocol']}")
            
            # Check XXE
            xxe_vuln = self.advanced_scanner.check_xxe_vulnerability(response, self.target_url)
            if xxe_vuln:
                self.vulnerabilities.append(xxe_vuln)
                logger.warning("Potential XXE vulnerability detected")
            
            # Check CORS
            cors_vuln = self.advanced_scanner.check_cors_misconfiguration(response, self.target_url)
            if cors_vuln:
                self.vulnerabilities.append(cors_vuln)
                logger.warning("CORS misconfiguration detected")
            
            # Check HTTP methods
            methods_result = self.advanced_scanner.check_http_methods(self.target_url)
            if methods_result.get('type'):  # It's a vulnerability
                self.vulnerabilities.append(methods_result)
                logger.warning("Dangerous HTTP methods enabled")
            
            # Check for open redirect
            params = get_url_parameters(self.target_url)
            if params:
                redirect_vuln = self.advanced_scanner.check_open_redirect(
                    self.target_url, response, params
                )
                if redirect_vuln:
                    self.vulnerabilities.append(redirect_vuln)
                    logger.warning("Open redirect vulnerability detected")
                
        except Exception as e:
            logger.error(f"Advanced checks error: {e}")
    
    def _scan_url(self, url: str):
        """
        Scan a specific URL for vulnerabilities
        
        Args:
            url: URL to scan
        """
        if url in self.scanned_urls:
            return
        
        self.scanned_urls.add(url)
        logger.info(f"Scanning URL: {url}")
        
        # Get the page
        response = make_request(url)
        if not response:
            logger.warning(f"Failed to access URL: {url}")
            return
        
        # Check for sensitive information disclosure
        self._check_information_disclosure(url, response)
        
        # Check for CSRF vulnerabilities in forms
        self._check_csrf(url, response)
        
        # Test URL parameters for vulnerabilities
        params = get_url_parameters(url)
        if params:
            self._test_url_parameters(url, params)
        
        # Parse and test forms
        forms = parse_forms(response.text, url)
        for form in forms:
            self._test_form(form)
    
    def _test_url_parameters(self, url: str, params: Dict):
        """
        Test URL parameters for XSS and SQL Injection
        
        Args:
            url: Base URL
            params: URL parameters
        """
        base_url = url.split('?')[0]
        
        for param_name in params.keys():
            # Test XSS
            self._test_xss_in_param(base_url, params, param_name)
            
            # Test SQL Injection
            self._test_sqli_in_param(base_url, params, param_name)
            
            # Test Directory Traversal
            self._test_dir_traversal_in_param(base_url, params, param_name)
    
    def _test_xss_in_param(self, base_url: str, params: Dict, param_name: str):
        """
        Test for XSS vulnerability in a URL parameter
        
        Args:
            base_url: Base URL without parameters
            params: Original parameters
            param_name: Parameter to test
        """
        for payload in self.XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            test_url = f"{base_url}?{urlencode(test_params)}"
            response = make_request(test_url)
            
            if response and payload in response.text:
                vulnerability = {
                    'type': 'XSS (Cross-Site Scripting)',
                    'severity': 'HIGH',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'description': f'XSS vulnerability detected in parameter "{param_name}". The payload was reflected in the response.',
                    'evidence': response.text[:200] if len(response.text) > 200 else response.text
                }
                self.vulnerabilities.append(vulnerability)
                logger.warning(f"XSS vulnerability found at {base_url} in parameter {param_name}")
                break  # One payload is enough to confirm
    
    def _test_sqli_in_param(self, base_url: str, params: Dict, param_name: str):
        """
        Test for SQL Injection vulnerability in a URL parameter
        
        Args:
            base_url: Base URL without parameters
            params: Original parameters
            param_name: Parameter to test
        """
        for payload in self.SQL_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            test_url = f"{base_url}?{urlencode(test_params)}"
            response = make_request(test_url)
            
            if response:
                # Check for SQL error messages
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerability = {
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'description': f'SQL Injection vulnerability detected in parameter "{param_name}". Database error messages were found in the response.',
                            'evidence': response.text[:200] if len(response.text) > 200 else response.text
                        }
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"SQL Injection vulnerability found at {base_url} in parameter {param_name}")
                        return  # One confirmation is enough
    
    def _test_form(self, form: Dict):
        """
        Test a form for vulnerabilities
        
        Args:
            form: Form dictionary with action, method, and inputs
        """
        action_url = form['action']
        method = form['method']
        inputs = form['inputs']
        
        if not inputs:
            return
        
        logger.info(f"Testing form: {action_url}")
        
        # Test each input field
        for input_field in inputs:
            field_name = input_field['name']
            
            # Test XSS
            self._test_xss_in_form(action_url, method, inputs, field_name)
            
            # Test SQL Injection
            self._test_sqli_in_form(action_url, method, inputs, field_name)
    
    def _test_xss_in_form(self, action_url: str, method: str, inputs: List[Dict], test_field: str):
        """
        Test for XSS in a form field
        
        Args:
            action_url: Form action URL
            method: HTTP method
            inputs: Form inputs
            test_field: Field to test
        """
        for payload in self.XSS_PAYLOADS:
            form_data = {}
            for inp in inputs:
                if inp['name'] == test_field:
                    form_data[inp['name']] = payload
                else:
                    form_data[inp['name']] = inp.get('value', 'test')
            
            if method == 'GET':
                response = make_request(action_url, method='GET', params=form_data)
            else:
                response = make_request(action_url, method='POST', data=form_data)
            
            if response and payload in response.text:
                vulnerability = {
                    'type': 'XSS (Cross-Site Scripting)',
                    'severity': 'HIGH',
                    'url': action_url,
                    'parameter': test_field,
                    'method': method,
                    'payload': payload,
                    'description': f'XSS vulnerability detected in form field "{test_field}". The payload was reflected in the response.',
                    'evidence': response.text[:200] if len(response.text) > 200 else response.text
                }
                self.vulnerabilities.append(vulnerability)
                logger.warning(f"XSS vulnerability found in form at {action_url} in field {test_field}")
                break
    
    def _test_sqli_in_form(self, action_url: str, method: str, inputs: List[Dict], test_field: str):
        """
        Test for SQL Injection in a form field
        
        Args:
            action_url: Form action URL
            method: HTTP method
            inputs: Form inputs
            test_field: Field to test
        """
        for payload in self.SQL_PAYLOADS:
            form_data = {}
            for inp in inputs:
                if inp['name'] == test_field:
                    form_data[inp['name']] = payload
                else:
                    form_data[inp['name']] = inp.get('value', 'test')
            
            if method == 'GET':
                response = make_request(action_url, method='GET', params=form_data)
            else:
                response = make_request(action_url, method='POST', data=form_data)
            
            if response:
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerability = {
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'url': action_url,
                            'parameter': test_field,
                            'method': method,
                            'payload': payload,
                            'description': f'SQL Injection vulnerability detected in form field "{test_field}". Database error messages were found in the response.',
                            'evidence': response.text[:200] if len(response.text) > 200 else response.text
                        }
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"SQL Injection vulnerability found in form at {action_url} in field {test_field}")
                        return
    
    def _test_dir_traversal_in_param(self, base_url: str, params: Dict, param_name: str):
        """
        Test for Directory Traversal vulnerability in a URL parameter
        
        Args:
            base_url: Base URL without parameters
            params: Original parameters
            param_name: Parameter to test
        """
        for payload in self.DIR_TRAVERSAL_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            
            test_url = f"{base_url}?{urlencode(test_params)}"
            response = make_request(test_url)
            
            if response:
                for pattern in self.DIR_TRAVERSAL_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerability = {
                            'type': 'Directory Traversal',
                            'severity': 'HIGH',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'description': f'Directory Traversal vulnerability detected in parameter "{param_name}". System files are accessible.',
                            'evidence': response.text[:200] if len(response.text) > 200 else response.text
                        }
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Directory Traversal vulnerability found at {base_url} in parameter {param_name}")
                        return
    
    def _check_csrf(self, url: str, response):
        """
        Check for CSRF vulnerabilities (missing CSRF tokens in forms)
        
        Args:
            url: Target URL
            response: HTTP response object
        """
        forms = parse_forms(response.text, url)
        
        for form in forms:
            # Check if form modifies data (POST, PUT, DELETE methods)
            method = form.get('method', 'GET').upper()
            if method in ['POST', 'PUT', 'DELETE']:
                # Check for CSRF token
                has_csrf_token = False
                csrf_token_names = ['csrf', 'csrf_token', '_csrf', 'token', '_token', 'xsrf']
                
                for input_field in form.get('inputs', []):
                    field_name = input_field.get('name', '').lower()
                    if any(csrf_name in field_name for csrf_name in csrf_token_names):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    vulnerability = {
                        'type': 'CSRF (Cross-Site Request Forgery)',
                        'severity': 'MEDIUM',
                        'url': form.get('action', url),
                        'method': method,
                        'description': f'Form with {method} method lacks CSRF protection. No CSRF token found in form fields.',
                        'evidence': f"Form action: {form.get('action', url)}, Method: {method}, Inputs: {len(form.get('inputs', []))}"
                    }
                    self.vulnerabilities.append(vulnerability)
                    logger.warning(f"CSRF vulnerability found in form at {form.get('action', url)}")
    
    def _check_information_disclosure(self, url: str, response):
        """
        Check for sensitive information disclosure
        
        Args:
            url: Target URL
            response: HTTP response object
        """
        disclosed_info = []
        
        # Check response body
        for info_type, pattern in self.SENSITIVE_INFO_PATTERNS.items():
            matches = re.findall(pattern, response.text)
            if matches:
                for match in matches[:3]:  # Limit to first 3 matches
                    match_str = match if isinstance(match, str) else match[0] if isinstance(match, tuple) else str(match)
                    disclosed_info.append({
                        'type': info_type,
                        'value': match_str[:50] + '...' if len(match_str) > 50 else match_str
                    })
        
        # Check headers for sensitive information
        sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in sensitive_headers:
            if header in response.headers:
                disclosed_info.append({
                    'type': 'server_info',
                    'value': f"{header}: {response.headers[header]}"
                })
        
        # Check for debug/error messages
        debug_patterns = [
            r'(?i)stack trace',
            r'(?i)debug mode',
            r'(?i)exception',
            r'(?i)warning:',
            r'(?i)error in line',
            r'(?i)fatal error'
        ]
        
        for pattern in debug_patterns:
            if re.search(pattern, response.text):
                disclosed_info.append({
                    'type': 'debug_info',
                    'value': 'Debug or error messages detected in response'
                })
                break
        
        # Create vulnerability if sensitive info found
        if disclosed_info:
            vulnerability = {
                'type': 'Information Disclosure',
                'severity': 'MEDIUM',
                'url': url,
                'description': f'Sensitive information exposed. Found: {", ".join([i["type"] for i in disclosed_info])}',
                'evidence': str(disclosed_info[:5]),  # Limit to first 5 items
                'disclosed_items': disclosed_info
            }
            self.vulnerabilities.append(vulnerability)
            logger.warning(f"Information disclosure found at {url}: {len(disclosed_info)} items")
    
    def get_results(self) -> List[Dict]:
        """
        Get scan results
        
        Returns:
            List of vulnerabilities found
        """
        return self.vulnerabilities
