"""
Utility modules for the Web Security Scanner
"""

from .http_client import make_request, parse_forms
from .logger import setup_logger

__all__ = ['make_request', 'parse_forms', 'setup_logger']
