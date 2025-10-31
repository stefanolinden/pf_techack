"""
Report Generator Module
Generates reports from scan results in multiple formats: text, JSON, CSV, Markdown
"""
import json
import csv
from datetime import datetime
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate reports from vulnerability scan results"""
    
    def __init__(self, vulnerabilities: List[Dict], target_url: str):
        """
        Initialize report generator
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            target_url: Target URL that was scanned
        """
        self.vulnerabilities = vulnerabilities
        self.target_url = target_url
        self.timestamp = datetime.now()
    
    def generate_text_report(self, output_file: str = None) -> str:
        """
        Generate a text report
        
        Args:
            output_file: Optional file path to save report
            
        Returns:
            Report as string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("WEB SECURITY SCANNER - VULNERABILITY REPORT")
        lines.append("=" * 80)
        lines.append(f"Target URL: {self.target_url}")
        lines.append(f"Scan Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}")
        lines.append("=" * 80)
        lines.append("")
        
        if not self.vulnerabilities:
            lines.append("No vulnerabilities detected. The target appears to be secure.")
            lines.append("")
        else:
            # Group by severity
            critical = [v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']
            high = [v for v in self.vulnerabilities if v.get('severity') == 'HIGH']
            medium = [v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']
            low = [v for v in self.vulnerabilities if v.get('severity') == 'LOW']
            
            lines.append("SUMMARY BY SEVERITY:")
            lines.append(f"  CRITICAL: {len(critical)}")
            lines.append(f"  HIGH:     {len(high)}")
            lines.append(f"  MEDIUM:   {len(medium)}")
            lines.append(f"  LOW:      {len(low)}")
            lines.append("")
            lines.append("-" * 80)
            lines.append("")
            
            # Detailed vulnerabilities
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                lines.append(f"VULNERABILITY #{idx}")
                lines.append(f"Type:        {vuln.get('type', 'Unknown')}")
                lines.append(f"Severity:    {vuln.get('severity', 'Unknown')}")
                lines.append(f"URL:         {vuln.get('url', 'N/A')}")
                lines.append(f"Parameter:   {vuln.get('parameter', 'N/A')}")
                if 'method' in vuln:
                    lines.append(f"Method:      {vuln.get('method')}")
                lines.append(f"Payload:     {vuln.get('payload', 'N/A')}")
                lines.append(f"Description: {vuln.get('description', 'N/A')}")
                lines.append("")
                lines.append(f"Evidence (excerpt):")
                lines.append(f"  {vuln.get('evidence', 'N/A')[:150]}...")
                lines.append("")
                lines.append("-" * 80)
                lines.append("")
        
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        report = "\n".join(lines)
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                logger.info(f"Report saved to {output_file}")
            except Exception as e:
                logger.error(f"Failed to save report: {str(e)}")
        
        return report
    
    def generate_log_summary(self) -> str:
        """
        Generate a brief log summary
        
        Returns:
            Summary string
        """
        summary = []
        summary.append(f"Scan Summary for {self.target_url}:")
        summary.append(f"  Total Vulnerabilities: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            vuln_types = {}
            for v in self.vulnerabilities:
                vtype = v.get('type', 'Unknown')
                vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
            
            summary.append("  Breakdown:")
            for vtype, count in vuln_types.items():
                summary.append(f"    - {vtype}: {count}")
        
        return "\n".join(summary)
    
    def generate_json_report(self, output_file: str) -> str:
        """
        Generate JSON report
        
        Args:
            output_file: File path to save JSON report
            
        Returns:
            JSON string
        """
        report_data = {
            'target_url': self.target_url,
            'scan_date': self.timestamp.isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities
        }
        
        json_str = json.dumps(report_data, indent=2)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_str)
            logger.info(f"JSON report saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save JSON report: {str(e)}")
        
        return json_str
    
    def generate_csv_report(self, output_file: str) -> str:
        """
        Generate CSV report
        
        Args:
            output_file: File path to save CSV report
            
        Returns:
            Success message
        """
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                if not self.vulnerabilities:
                    f.write("No vulnerabilities found\n")
                    return "CSV report saved (no vulnerabilities)"
                
                # Define CSV columns
                fieldnames = ['Type', 'Severity', 'URL', 'Parameter', 'Method', 'Payload', 'Description']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                
                writer.writeheader()
                
                for vuln in self.vulnerabilities:
                    row = {
                        'Type': vuln.get('type', ''),
                        'Severity': vuln.get('severity', ''),
                        'URL': vuln.get('url', ''),
                        'Parameter': vuln.get('parameter', 'N/A'),
                        'Method': vuln.get('method', 'N/A'),
                        'Payload': vuln.get('payload', 'N/A'),
                        'Description': vuln.get('description', '')
                    }
                    writer.writerow(row)
            
            logger.info(f"CSV report saved to {output_file}")
            return f"CSV report saved to {output_file}"
        except Exception as e:
            logger.error(f"Failed to save CSV report: {str(e)}")
            return f"Error: {str(e)}"
    
    def generate_markdown_report(self, output_file: str) -> str:
        """
        Generate Markdown report
        
        Args:
            output_file: File path to save Markdown report
            
        Returns:
            Markdown string
        """
        lines = []
        lines.append("# Web Security Scanner - Vulnerability Report\n")
        lines.append(f"**Target URL:** {self.target_url}  ")
        lines.append(f"**Scan Date:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  ")
        lines.append(f"**Total Vulnerabilities:** {len(self.vulnerabilities)}\n")
        lines.append("---\n")
        
        if not self.vulnerabilities:
            lines.append("✅ **No vulnerabilities detected.**\n")
            lines.append("The target appears to be secure against the tested attack vectors.\n")
        else:
            # Summary by severity
            critical = [v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']
            high = [v for v in self.vulnerabilities if v.get('severity') == 'HIGH']
            medium = [v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']
            low = [v for v in self.vulnerabilities if v.get('severity') == 'LOW']
            
            lines.append("## Summary by Severity\n")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            lines.append(f"| 🔴 CRITICAL | {len(critical)} |")
            lines.append(f"| 🟠 HIGH | {len(high)} |")
            lines.append(f"| 🟡 MEDIUM | {len(medium)} |")
            lines.append(f"| 🟢 LOW | {len(low)} |")
            lines.append("")
            
            # Detailed vulnerabilities
            lines.append("## Detected Vulnerabilities\n")
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                severity_icon = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(vuln.get('severity', ''), '⚪')
                
                lines.append(f"### {idx}. {severity_icon} {vuln.get('type', 'Unknown')}\n")
                lines.append(f"- **Severity:** {vuln.get('severity', 'Unknown')}")
                lines.append(f"- **URL:** `{vuln.get('url', 'N/A')}`")
                
                if 'parameter' in vuln:
                    lines.append(f"- **Parameter:** `{vuln.get('parameter')}`")
                if 'method' in vuln:
                    lines.append(f"- **Method:** `{vuln.get('method')}`")
                if 'payload' in vuln:
                    lines.append(f"- **Payload:** `{vuln.get('payload')}`")
                
                lines.append(f"- **Description:** {vuln.get('description', 'N/A')}")
                
                if 'evidence' in vuln:
                    evidence = vuln.get('evidence', '')[:150]
                    lines.append(f"\n**Evidence (excerpt):**")
                    lines.append(f"```")
                    lines.append(evidence)
                    lines.append(f"```")
                
                lines.append("")
        
        lines.append("---")
        lines.append(f"\n*Report generated by Web Security Scanner v1.0.0*")
        
        markdown_content = "\n".join(lines)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            logger.info(f"Markdown report saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save Markdown report: {str(e)}")
        
        return markdown_content

