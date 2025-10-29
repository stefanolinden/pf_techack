#!/usr/bin/env python3

from urllib.parse import urlparse, urljoin
import re
from typing import Optional

def validate_url(url: str) -> str:
    """Validate and normalize URL"""
    if not url:
        raise ValueError("URL cannot be empty")
        
    # Add http:// if no scheme is present
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL format")
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")
        
    return url

def normalize_url(url: str) -> str:
    """Normalize URL by removing fragments and normalizing paths"""
    parsed = urlparse(url)
    normalized = parsed._replace(
        path=re.sub('/+', '/', parsed.path),  # Remove duplicate slashes
        fragment=''  # Remove fragments
    )
    return normalized.geturl()

def is_valid_port(port: int) -> bool:
    """Check if port number is valid"""
    return isinstance(port, int) and 0 <= port <= 65535

def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return None

def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin"""
    try:
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        
        return (parsed1.scheme == parsed2.scheme and
                parsed1.netloc == parsed2.netloc)
    except:
        return False

def join_url(base: str, path: str) -> str:
    """Safely join base URL with path"""
    return urljoin(base, path)