"""
Unit tests for the Web Security Scanner
"""
import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import VulnerabilityScanner
from report_generator import ReportGenerator
from utils.http_client import is_valid_url, get_url_parameters


class TestURLValidation(unittest.TestCase):
    """Test URL validation functions"""
    
    def test_valid_urls(self):
        """Test that valid URLs are accepted"""
        valid_urls = [
            'http://example.com',
            'https://example.com',
            'http://example.com/path',
            'https://example.com/path?param=value'
        ]
        for url in valid_urls:
            self.assertTrue(is_valid_url(url), f"URL should be valid: {url}")
    
    def test_invalid_urls(self):
        """Test that invalid URLs are rejected"""
        invalid_urls = [
            'not a url',
            'example.com',  # Missing scheme
            ''
        ]
        for url in invalid_urls:
            self.assertFalse(is_valid_url(url), f"URL should be invalid: {url}")


class TestParameterExtraction(unittest.TestCase):
    """Test URL parameter extraction"""
    
    def test_extract_parameters(self):
        """Test extracting parameters from URL"""
        url = 'http://example.com/page?id=1&name=test'
        params = get_url_parameters(url)
        
        self.assertIn('id', params)
        self.assertIn('name', params)
        self.assertEqual(params['id'], '1')
        self.assertEqual(params['name'], 'test')
    
    def test_no_parameters(self):
        """Test URL with no parameters"""
        url = 'http://example.com/page'
        params = get_url_parameters(url)
        
        self.assertEqual(len(params), 0)


class TestScanner(unittest.TestCase):
    """Test scanner initialization"""
    
    def test_scanner_init_valid_url(self):
        """Test scanner initialization with valid URL"""
        scanner = VulnerabilityScanner('http://example.com')
        self.assertEqual(scanner.target_url, 'http://example.com')
        self.assertEqual(len(scanner.vulnerabilities), 0)
    
    def test_scanner_init_invalid_url(self):
        """Test scanner initialization with invalid URL"""
        with self.assertRaises(ValueError):
            VulnerabilityScanner('not a url')


class TestReportGenerator(unittest.TestCase):
    """Test report generation"""
    
    def test_empty_report(self):
        """Test report with no vulnerabilities"""
        report_gen = ReportGenerator([], 'http://example.com')
        report = report_gen.generate_text_report()
        
        self.assertIn('No vulnerabilities detected', report)
        self.assertIn('http://example.com', report)
    
    def test_report_with_vulnerabilities(self):
        """Test report with vulnerabilities"""
        vulnerabilities = [
            {
                'type': 'XSS',
                'severity': 'HIGH',
                'url': 'http://example.com',
                'parameter': 'test',
                'payload': '<script>alert(1)</script>',
                'description': 'Test vulnerability',
                'evidence': 'Test evidence'
            }
        ]
        
        report_gen = ReportGenerator(vulnerabilities, 'http://example.com')
        report = report_gen.generate_text_report()
        
        self.assertIn('XSS', report)
        self.assertIn('HIGH', report)
        self.assertIn('Total Vulnerabilities Found: 1', report)
    
    def test_log_summary(self):
        """Test log summary generation"""
        vulnerabilities = [
            {'type': 'XSS', 'severity': 'HIGH'},
            {'type': 'SQL Injection', 'severity': 'CRITICAL'}
        ]
        
        report_gen = ReportGenerator(vulnerabilities, 'http://example.com')
        summary = report_gen.generate_log_summary()
        
        self.assertIn('Total Vulnerabilities: 2', summary)
        self.assertIn('XSS: 1', summary)
        self.assertIn('SQL Injection: 1', summary)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
