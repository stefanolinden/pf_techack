#!/usr/bin/env python3

import json
import csv
import markdown
from typing import Dict, List, Any
from datetime import datetime

class ReportGenerator:
    def __init__(self, scan_results: Dict[str, List[Dict[str, Any]]], target_url: str):
        self.scan_results = scan_results
        self.target_url = target_url
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
    def to_json(self, output_file: str = None) -> str:
        """Generate JSON report"""
        report = {
            'target_url': self.target_url,
            'scan_date': self.timestamp,
            'findings': self.scan_results
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
        
        return json.dumps(report, indent=4)
        
    def to_csv(self, output_file: str = None) -> str:
        """Generate CSV report"""
        rows = []
        headers = ['Vulnerability Type', 'Severity', 'URL', 'Description', 'Details']
        
        for vuln_type, findings in self.scan_results.items():
            for finding in findings:
                severity = finding.get('severity', 'Unknown')
                url = finding.get('url', self.target_url)
                description = finding.get('description', '')
                # Combine remaining details
                details = ', '.join([f"{k}: {v}" for k, v in finding.items() 
                                  if k not in ['type', 'severity', 'url', 'description']])
                
                rows.append([vuln_type, severity, url, description, details])
        
        if output_file:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
        
        # Return CSV as string
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(rows)
        return output.getvalue()
        
    def to_markdown(self, output_file: str = None) -> str:
        """Generate Markdown report"""
        md_content = f"""# Security Scan Report

## Target Information
- **URL:** {self.target_url}
- **Scan Date:** {self.timestamp}

## Summary of Findings

"""
        total_findings = sum(len(findings) for findings in self.scan_results.values())
        if total_findings == 0:
            md_content += "No vulnerabilities were found.\n\n"
        else:
            # Add summary table
            md_content += "| Vulnerability Type | Count | Highest Severity |\n"
            md_content += "|-------------------|-------|------------------|\n"
            
            for vuln_type, findings in self.scan_results.items():
                if findings:
                    highest_severity = max((f.get('severity', 'Unknown') for f in findings), 
                                        default='Unknown')
                    md_content += f"| {vuln_type.upper()} | {len(findings)} | {highest_severity} |\n"
            
            # Detailed findings
            md_content += "\n## Detailed Findings\n\n"
            for vuln_type, findings in self.scan_results.items():
                if findings:
                    md_content += f"### {vuln_type.upper()}\n\n"
                    for i, finding in enumerate(findings, 1):
                        md_content += f"#### Finding {i}\n\n"
                        for key, value in finding.items():
                            md_content += f"- **{key}:** {value}\n"
                        md_content += "\n"
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(md_content)
        
        return md_content

def main():
    # Example usage
    sample_results = {
        'xss': [
            {
                'type': 'XSS',
                'severity': 'High',
                'url': 'http://example.com',
                'parameter': 'search',
                'payload': '<script>alert("XSS")</script>'
            }
        ]
    }
    
    generator = ReportGenerator(sample_results, 'http://example.com')
    
    # Generate reports in different formats
    generator.to_json('report.json')
    generator.to_csv('report.csv')
    generator.to_markdown('report.md')

if __name__ == "__main__":
    main()