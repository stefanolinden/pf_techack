"""
HTTP Client utilities for making requests and parsing responses
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


def make_request(url: str, method: str = 'GET', data: Optional[Dict] = None, 
                 params: Optional[Dict] = None, timeout: int = 10) -> Optional[requests.Response]:
    """
    Make HTTP request to a URL
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        data: POST data
        params: URL parameters
        timeout: Request timeout in seconds
        
    Returns:
        Response object or None if request fails
    """
    headers = {
        'User-Agent': 'WebSecurityScanner/1.0'
    }
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, params=params, headers=headers, timeout=timeout, verify=False)
        elif method.upper() == 'POST':
            response = requests.post(url, data=data, params=params, headers=headers, timeout=timeout, verify=False)
        else:
            response = requests.request(method, url, data=data, params=params, headers=headers, timeout=timeout, verify=False)
        
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {url}: {str(e)}")
        return None


def parse_forms(html_content: str, base_url: str) -> List[Dict]:
    """
    Parse HTML forms from content
    
    Args:
        html_content: HTML content as string
        base_url: Base URL for resolving relative paths
        
    Returns:
        List of form dictionaries with action, method, and inputs
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = []
    
    for form in soup.find_all('form'):
        form_data = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'get').upper(),
            'inputs': []
        }
        
        # Get all input fields
        for input_field in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'name': input_field.get('name', ''),
                'type': input_field.get('type', 'text'),
                'value': input_field.get('value', '')
            }
            if input_data['name']:
                form_data['inputs'].append(input_data)
        
        forms.append(form_data)
    
    return forms


def get_url_parameters(url: str) -> Dict:
    """
    Extract parameters from URL query string
    
    Args:
        url: URL to parse
        
    Returns:
        Dictionary of parameters
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # Convert lists to single values
    return {k: v[0] if len(v) == 1 else v for k, v in params.items()}


def is_valid_url(url: str) -> bool:
    """
    Check if URL is valid
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False
