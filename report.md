# Security Scan Report

## Target Information
- **URL:** http://example.com
- **Scan Date:** 2025-10-28_23-10-00

## Summary of Findings

| Vulnerability Type | Count | Highest Severity |
|-------------------|-------|------------------|
| XSS | 1 | High |

## Detailed Findings

### XSS

#### Finding 1

- **type:** XSS
- **severity:** High
- **url:** http://example.com
- **parameter:** search
- **payload:** <script>alert("XSS")</script>

