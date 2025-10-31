"""
Advanced Security Scanner Tools
Includes: Nmap integration, SSL/TLS testing, Security Headers, XXE, SSRF detection
"""
import re
import logging
import subprocess
from typing import List, Dict, Optional
from urllib.parse import urlparse
import socket

logger = logging.getLogger('WebSecurityScanner')


class AdvancedScanner:
    """Advanced security scanning tools"""
    
    def __init__(self):
        self.nmap_available = self._check_nmap_available()
    
    def _check_nmap_available(self) -> bool:
        """Check if nmap is installed"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("Nmap not found. Port scanning will be limited.")
            return False
    
    def scan_ports_nmap(self, target_url: str) -> Dict:
        """
        Scan ports using Nmap
        
        Args:
            target_url: Target URL
            
        Returns:
            Dictionary with scan results
        """
        if not self.nmap_available:
            return {'error': 'Nmap not available'}
        
        parsed = urlparse(target_url)
        hostname = parsed.hostname or parsed.netloc
        
        if not hostname:
            return {'error': 'Invalid hostname'}
        
        try:
            # Quick scan of most common ports
            cmd = ['nmap', '-Pn', '-T4', '--top-ports', '100', hostname]
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=60)
            
            if result.returncode != 0:
                return {'error': 'Nmap scan failed'}
            
            # Parse nmap output
            open_ports = []
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0].split('/')[0]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'state': 'open'
                        })
            
            return {
                'hostname': hostname,
                'open_ports': open_ports,
                'total_open': len(open_ports),
                'raw_output': result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Nmap scan timed out'}
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return {'error': str(e)}
    
    def check_security_headers(self, response) -> List[Dict]:
        """
        Check for missing security headers
        
        Args:
            response: HTTP response object
            
        Returns:
            List of missing security headers
        """
        required_headers = {
            'X-Frame-Options': {
                'description': 'Protects against clickjacking attacks',
                'severity': 'MEDIUM',
                'recommendation': 'Set to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'severity': 'MEDIUM',
                'recommendation': 'Set to nosniff'
            },
            'Strict-Transport-Security': {
                'description': 'Forces HTTPS connections',
                'severity': 'HIGH',
                'recommendation': 'Set to max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS and data injection attacks',
                'severity': 'HIGH',
                'recommendation': "Set appropriate CSP policy"
            },
            'X-XSS-Protection': {
                'description': 'Enables XSS filtering in older browsers',
                'severity': 'LOW',
                'recommendation': 'Set to 1; mode=block'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'severity': 'LOW',
                'recommendation': 'Set to no-referrer or strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features and APIs',
                'severity': 'LOW',
                'recommendation': 'Set appropriate permissions policy'
            }
        }
        
        missing_headers = []
        for header, info in required_headers.items():
            if header not in response.headers:
                missing_headers.append({
                    'header': header,
                    'description': info['description'],
                    'severity': info['severity'],
                    'recommendation': info['recommendation']
                })
        
        return missing_headers
    
    def check_ssl_tls(self, target_url: str) -> Optional[Dict]:
        """
        Check SSL/TLS configuration
        
        Args:
            target_url: Target URL
            
        Returns:
            Dictionary with SSL/TLS info
        """
        parsed = urlparse(target_url)
        
        if parsed.scheme != 'https':
            return {
                'error': 'Not an HTTPS URL',
                'severity': 'HIGH',
                'description': 'Site does not use HTTPS encryption'
            }
        
        hostname = parsed.hostname
        port = parsed.port or 443
        
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check for weak protocols
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    is_weak = version in weak_protocols
                    
                    return {
                        'protocol': version,
                        'cipher': cipher[0] if cipher else 'unknown',
                        'bits': cipher[2] if cipher and len(cipher) > 2 else 0,
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'weak_protocol': is_weak,
                        'severity': 'HIGH' if is_weak else 'LOW'
                    }
        except Exception as e:
            logger.error(f"SSL/TLS check error: {e}")
            return {
                'error': str(e),
                'severity': 'MEDIUM',
                'description': 'Could not verify SSL/TLS configuration'
            }
    
    def check_xxe_vulnerability(self, response, url: str) -> Optional[Dict]:
        """
        Check for XXE (XML External Entity) vulnerability indicators
        
        Args:
            response: HTTP response
            url: Target URL
            
        Returns:
            Vulnerability dict if found
        """
        # Check if response suggests XML processing
        content_type = response.headers.get('Content-Type', '')
        
        if 'xml' not in content_type.lower() and 'xml' not in response.text[:500].lower():
            return None
        
        # XXE indicators
        xxe_indicators = [
            r'<!DOCTYPE',
            r'<!ENTITY',
            r'SYSTEM\s+["\']',
            r'PUBLIC\s+["\']'
        ]
        
        for pattern in xxe_indicators:
            if re.search(pattern, response.text, re.IGNORECASE):
                return {
                    'type': 'XXE (XML External Entity)',
                    'severity': 'HIGH',
                    'url': url,
                    'description': 'Application processes XML and may be vulnerable to XXE attacks',
                    'evidence': 'XML processing detected with DOCTYPE or ENTITY declarations',
                    'recommendation': 'Disable external entity processing in XML parser'
                }
        
        return None
    
    def check_ssrf_parameters(self, url: str, params: Dict) -> List[str]:
        """
        Identify parameters that might be vulnerable to SSRF
        
        Args:
            url: Target URL
            params: URL parameters
            
        Returns:
            List of suspicious parameter names
        """
        ssrf_param_patterns = [
            'url', 'uri', 'path', 'dest', 'destination', 'redirect',
            'next', 'target', 'rurl', 'link', 'load', 'file',
            'document', 'folder', 'root', 'page', 'html', 'feed'
        ]
        
        suspicious_params = []
        for param in params.keys():
            param_lower = param.lower()
            if any(pattern in param_lower for pattern in ssrf_param_patterns):
                suspicious_params.append(param)
        
        return suspicious_params
    
    def check_open_redirect(self, url: str, response, params: Dict) -> Optional[Dict]:
        """
        Check for open redirect vulnerabilities
        
        Args:
            url: Target URL
            response: HTTP response
            params: URL parameters
            
        Returns:
            Vulnerability dict if found
        """
        redirect_params = self.check_ssrf_parameters(url, params)
        
        if not redirect_params:
            return None
        
        # Check if response is a redirect
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            
            # Check if any parameter value appears in Location header
            for param in redirect_params:
                param_value = params.get(param, '')
                if param_value and param_value in location:
                    return {
                        'type': 'Open Redirect',
                        'severity': 'MEDIUM',
                        'url': url,
                        'parameter': param,
                        'description': f'Parameter "{param}" controls redirect destination',
                        'evidence': f'Location: {location}',
                        'recommendation': 'Validate redirect destinations against whitelist'
                    }
        
        return None
    
    def check_cors_misconfiguration(self, response, url: str) -> Optional[Dict]:
        """
        Check for CORS misconfiguration
        
        Args:
            response: HTTP response
            url: Target URL
            
        Returns:
            Vulnerability dict if found
        """
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        # Dangerous: ACAO: * with credentials
        if acao == '*' and acac == 'true':
            return {
                'type': 'CORS Misconfiguration',
                'severity': 'HIGH',
                'url': url,
                'description': 'CORS allows any origin with credentials',
                'evidence': f'Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}',
                'recommendation': 'Use specific origins instead of wildcard when allowing credentials'
            }
        
        # Overly permissive
        if acao == '*':
            return {
                'type': 'CORS Misconfiguration',
                'severity': 'MEDIUM',
                'url': url,
                'description': 'CORS allows any origin',
                'evidence': f'Access-Control-Allow-Origin: {acao}',
                'recommendation': 'Restrict allowed origins to trusted domains'
            }
        
        return None
    
    def check_http_methods(self, url: str) -> Dict:
        """
        Check allowed HTTP methods
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with allowed methods
        """
        try:
            import requests
            response = requests.options(url, timeout=10, verify=False)
            
            allowed = response.headers.get('Allow', '')
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            
            found_dangerous = [m for m in dangerous_methods if m in allowed.upper()]
            
            if found_dangerous:
                return {
                    'type': 'Dangerous HTTP Methods',
                    'severity': 'MEDIUM',
                    'url': url,
                    'description': f'Dangerous HTTP methods enabled: {", ".join(found_dangerous)}',
                    'evidence': f'Allow: {allowed}',
                    'recommendation': 'Disable unnecessary HTTP methods'
                }
            
            return {'allowed_methods': allowed, 'safe': True}
            
        except Exception as e:
            logger.error(f"HTTP methods check error: {e}")
            return {'error': str(e)}
