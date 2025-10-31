"""
Vulnerability Analysis and Risk Scoring Module
Provides heuristic analysis and risk prioritization
"""
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


# Severity scores
SEVERITY_SCORES = {
    'CRITICAL': 10,
    'HIGH': 7,
    'MEDIUM': 4,
    'LOW': 2
}

# Vulnerability type weights
VULN_TYPE_WEIGHTS = {
    'SQL Injection': 1.5,
    'XSS (Cross-Site Scripting)': 1.2,
    'Directory Traversal': 1.3,
    'CSRF (Cross-Site Request Forgery)': 1.0,
    'Information Disclosure': 0.8
}

# Mitigation recommendations
MITIGATION_RECOMMENDATIONS = {
    'SQL Injection': {
        'summary': 'Use parameterized queries or prepared statements',
        'recommendations': [
            'Always use parameterized queries (prepared statements) instead of string concatenation',
            'Use ORM frameworks (SQLAlchemy, Django ORM, etc.) that handle sanitization automatically',
            'Implement principle of least privilege for database accounts',
            'Validate and sanitize all user inputs',
            'Use stored procedures with parameterized inputs',
            'Disable detailed error messages in production',
            'Implement web application firewall (WAF) rules'
        ],
        'example_code': '''# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE username='{username}'"

# ✅ SECURE
query = "SELECT * FROM users WHERE username=?"
cursor.execute(query, (username,))'''
    },
    'XSS (Cross-Site Scripting)': {
        'summary': 'Sanitize and encode all user inputs before output',
        'recommendations': [
            'HTML encode all user-supplied data before displaying',
            'Use Content Security Policy (CSP) headers',
            'Validate input on both client and server side',
            'Use auto-escaping template engines',
            'Implement HTTPOnly and Secure flags on cookies',
            'Use modern frameworks with built-in XSS protection (React, Vue, Angular)',
            'Never insert user input into JavaScript contexts directly'
        ],
        'example_code': '''# ❌ VULNERABLE
output = f"<div>{user_input}</div>"

# ✅ SECURE (Python)
from html import escape
output = f"<div>{escape(user_input)}</div>"'''
    },
    'Directory Traversal': {
        'summary': 'Validate file paths and restrict access to allowed directories',
        'recommendations': [
            'Validate all user-supplied input for file operations',
            'Use whitelist of allowed files/directories',
            'Normalize and canonicalize file paths',
            'Use path.join() instead of string concatenation',
            'Set strict file permissions on the server',
            'Never pass user input directly to file system operations',
            'Implement chroot jails or sandboxing'
        ],
        'example_code': '''# ❌ VULNERABLE
file = open(user_input, 'r')

# ✅ SECURE
import os
base_dir = '/safe/directory'
filepath = os.path.join(base_dir, os.path.basename(user_input))
if filepath.startswith(base_dir):
    file = open(filepath, 'r')'''
    },
    'CSRF (Cross-Site Request Forgery)': {
        'summary': 'Implement CSRF tokens in all state-changing forms',
        'recommendations': [
            'Use CSRF tokens in all POST/PUT/DELETE requests',
            'Implement SameSite cookie attribute',
            'Verify Referer/Origin headers',
            'Use frameworks with built-in CSRF protection',
            'Require re-authentication for sensitive actions',
            'Implement CAPTCHA for critical operations',
            'Use double-submit cookie pattern'
        ],
        'example_code': '''<!-- ❌ VULNERABLE -->
<form method="POST" action="/transfer">
  <input name="amount" />
  <button>Submit</button>
</form>

<!-- ✅ SECURE -->
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
  <input name="amount" />
  <button>Submit</button>
</form>'''
    },
    'Information Disclosure': {
        'summary': 'Remove sensitive information from responses and headers',
        'recommendations': [
            'Disable detailed error messages in production',
            'Remove or obscure server version headers',
            'Remove comments from production code',
            'Dont expose internal IPs, paths, or system information',
            'Use generic error pages',
            'Implement proper logging without exposing sensitive data',
            'Scan code for hardcoded credentials and API keys',
            'Use environment variables for sensitive configuration'
        ],
        'example_code': '''# ❌ VULNERABLE
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3

# ✅ SECURE
Server: WebServer
# Remove or obscure version information'''
    }
}


def calculate_risk_score(vulnerabilities: List[Dict]) -> Dict:
    """
    Calculate overall risk score based on vulnerabilities
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Dictionary with risk score and analysis
    """
    if not vulnerabilities:
        return {
            'score': 0,
            'level': 'SECURE',
            'total_vulnerabilities': 0,
            'by_severity': {}
        }
    
    total_score = 0
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'LOW')
        vuln_type = vuln.get('type', '')
        
        base_score = SEVERITY_SCORES.get(severity, 1)
        weight = VULN_TYPE_WEIGHTS.get(vuln_type, 1.0)
        
        total_score += base_score * weight
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Normalize score to 0-100
    max_possible_score = len(vulnerabilities) * 10 * 1.5  # Max severity * max weight
    normalized_score = min(100, (total_score / max_possible_score * 100) if max_possible_score > 0 else 0)
    
    # Determine risk level
    if normalized_score >= 75:
        risk_level = 'CRITICAL'
    elif normalized_score >= 50:
        risk_level = 'HIGH'
    elif normalized_score >= 25:
        risk_level = 'MEDIUM'
    elif normalized_score > 0:
        risk_level = 'LOW'
    else:
        risk_level = 'SECURE'
    
    return {
        'score': round(normalized_score, 2),
        'level': risk_level,
        'total_vulnerabilities': len(vulnerabilities),
        'by_severity': severity_counts,
        'details': f'{len(vulnerabilities)} vulnerabilities found with combined risk score of {round(normalized_score, 2)}/100'
    }


def prioritize_vulnerabilities(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Prioritize vulnerabilities by severity and type
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Sorted list of vulnerabilities with priority scores
    """
    def get_priority_score(vuln):
        severity = vuln.get('severity', 'LOW')
        vuln_type = vuln.get('type', '')
        
        base_score = SEVERITY_SCORES.get(severity, 1)
        weight = VULN_TYPE_WEIGHTS.get(vuln_type, 1.0)
        
        return base_score * weight
    
    # Add priority score to each vulnerability
    for vuln in vulnerabilities:
        vuln['priority_score'] = get_priority_score(vuln)
    
    # Sort by priority score (highest first)
    sorted_vulns = sorted(vulnerabilities, key=lambda v: v['priority_score'], reverse=True)
    
    return sorted_vulns


def get_mitigation_recommendation(vulnerability_type: str) -> Dict:
    """
    Get mitigation recommendations for a vulnerability type
    
    Args:
        vulnerability_type: Type of vulnerability
        
    Returns:
        Dictionary with mitigation recommendations
    """
    return MITIGATION_RECOMMENDATIONS.get(
        vulnerability_type,
        {
            'summary': 'Follow security best practices',
            'recommendations': [
                'Validate all user inputs',
                'Follow principle of least privilege',
                'Keep software up to date',
                'Implement security testing in CI/CD',
                'Conduct regular security audits'
            ],
            'example_code': 'N/A'
        }
    )


def generate_executive_summary(vulnerabilities: List[Dict]) -> str:
    """
    Generate executive summary of scan results
    
    Args:
        vulnerabilities: List of vulnerabilities
        
    Returns:
        Executive summary as string
    """
    risk_analysis = calculate_risk_score(vulnerabilities)
    
    if not vulnerabilities:
        return "The application appears to be secure. No vulnerabilities were detected during the scan."
    
    summary_parts = []
    
    # Risk level statement
    risk_level = risk_analysis['level']
    if risk_level == 'CRITICAL':
        summary_parts.append("⚠️ URGENT: Critical security issues detected!")
    elif risk_level == 'HIGH':
        summary_parts.append("⚠️ WARNING: Significant security vulnerabilities found.")
    elif risk_level == 'MEDIUM':
        summary_parts.append("⚠️ NOTICE: Moderate security issues identified.")
    else:
        summary_parts.append("ℹ️ INFO: Minor security concerns detected.")
    
    # Vulnerability breakdown
    summary_parts.append(f"\nTotal vulnerabilities: {len(vulnerabilities)}")
    
    severity_counts = risk_analysis['by_severity']
    if severity_counts.get('CRITICAL', 0) > 0:
        summary_parts.append(f"- {severity_counts['CRITICAL']} CRITICAL (immediate action required)")
    if severity_counts.get('HIGH', 0) > 0:
        summary_parts.append(f"- {severity_counts['HIGH']} HIGH (priority remediation)")
    if severity_counts.get('MEDIUM', 0) > 0:
        summary_parts.append(f"- {severity_counts['MEDIUM']} MEDIUM (should be addressed)")
    if severity_counts.get('LOW', 0) > 0:
        summary_parts.append(f"- {severity_counts['LOW']} LOW (low priority)")
    
    # Most common vulnerability
    vuln_types = {}
    for vuln in vulnerabilities:
        vtype = vuln.get('type', 'Unknown')
        vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
    
    if vuln_types:
        most_common = max(vuln_types, key=vuln_types.get)
        summary_parts.append(f"\nMost common issue: {most_common} ({vuln_types[most_common]} occurrences)")
    
    # Recommendations
    summary_parts.append(f"\nOverall Risk Score: {risk_analysis['score']}/100 ({risk_level})")
    summary_parts.append("\nImmediate actions recommended:")
    summary_parts.append("1. Address all CRITICAL and HIGH severity vulnerabilities")
    summary_parts.append("2. Review and implement security best practices")
    summary_parts.append("3. Conduct follow-up testing after remediation")
    
    return "\n".join(summary_parts)
