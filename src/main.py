#!/usr/bin/env python3
"""
Web Security Scanner - Command Line Interface
Basic CLI for scanning web applications for vulnerabilities
"""
import argparse
import sys
import os
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import VulnerabilityScanner
from report_generator import ReportGenerator
from utils.logger import setup_logger

logger = setup_logger()


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='Web Security Scanner - Detect XSS and SQL Injection vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://example.com
  %(prog)s -u http://testphp.vulnweb.com -o report.txt
  %(prog)s --url http://example.com/page?id=1 --json results.json
  %(prog)s -u http://example.com --csv report.csv --markdown report.md
        """
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan (e.g., http://example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for text report (default: print to console)'
    )
    
    parser.add_argument(
        '--json',
        help='Output file for JSON report'
    )
    
    parser.add_argument(
        '--csv',
        help='Output file for CSV report'
    )
    
    parser.add_argument(
        '--markdown',
        help='Output file for Markdown report'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Web Security Scanner 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose:
        import logging
        logger.setLevel(logging.DEBUG)
    
    print("=" * 80)
    print("WEB SECURITY SCANNER v1.0.0")
    print("=" * 80)
    print(f"Target: {args.url}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    print()
    
    try:
        # Initialize scanner
        scanner = VulnerabilityScanner(args.url)
        
        # Perform scan
        print("Scanning for vulnerabilities...")
        print("Testing for: XSS, SQL Injection, CSRF, Directory Traversal, Information Disclosure")
        print()
        
        vulnerabilities = scanner.scan()
        
        # Generate report
        report_gen = ReportGenerator(vulnerabilities, args.url)
        
        # Print summary
        print()
        print(report_gen.generate_log_summary())
        print()
        
        # Generate text report
        text_report = report_gen.generate_text_report(args.output)
        
        if args.output:
            print(f"\nText report saved to: {args.output}")
        else:
            print("\n" + text_report)
        
        # Generate JSON report if requested
        if args.json:
            report_gen.generate_json_report(args.json)
            print(f"JSON report saved to: {args.json}")
        
        # Generate CSV report if requested
        if args.csv:
            report_gen.generate_csv_report(args.csv)
            print(f"CSV report saved to: {args.csv}")
        
        # Generate Markdown report if requested
        if args.markdown:
            report_gen.generate_markdown_report(args.markdown)
            print(f"Markdown report saved to: {args.markdown}")
        
        print()
        print("=" * 80)
        print("Scan completed successfully!")
        print("=" * 80)
        
        # Return exit code based on vulnerabilities found
        if vulnerabilities:
            sys.exit(1)  # Vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        print(f"\nError: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
