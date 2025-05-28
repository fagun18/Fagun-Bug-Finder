# XSS (Cross-Site Scripting) Payloads

This directory contains payloads for testing Cross-Site Scripting (XSS) vulnerabilities. These payloads help identify if a web application is vulnerable to client-side code injection.

## Files

- `xss_payloads.txt`: Basic XSS test cases and vectors
- `xss_polyglots.txt`: Advanced polyglot payloads that work in multiple contexts

## Common XSS Techniques

- Basic XSS: `<script>alert(1)</script>`
- Event handlers: `" onmouseover="alert(1)"`
- SVG: `<svg onload=alert(1)>`
- IMG tag: `<img src=x onerror=alert(1)>`
- JavaScript URIs: `javascript:alert(1)`
- DOM-based: `#<script>alert(1)</script>`

## Usage

1. Start with basic payloads from `xss_payloads.txt`
2. If basic payloads are filtered, try polyglot payloads from `xss_polyglots.txt`
3. Test different contexts (HTML, attribute, JavaScript, URL, etc.)
4. Test with different encodings and obfuscation techniques

## Note

- Only test on systems you have permission to test
- Some payloads might be blocked by Content Security Policy (CSP) or WAFs
- Be aware of browser XSS filters that might block certain payloads
- Always have proper authorization before testing any system
