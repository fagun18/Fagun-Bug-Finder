# Open Redirect (OR) Payloads

This directory contains payloads for testing Open Redirect vulnerabilities. These payloads help identify if a web application improperly redirects users to arbitrary URLs.

## File

- `or_payloads.txt`: Contains various open redirect payloads

## Common Open Redirect Techniques

- Basic redirect: `https://example.com/redirect?url=https://evil.com`
- Double slash: `https://example.com//evil.com`
- URL encoding: `https://example.com/redirect?url=https%3A%2F%2Fevil.com`
- JavaScript protocol: `javascript:alert(1)`
- Data URI: `data:text/html,<script>alert(1)</script>`

## Usage

1. Test with basic redirects first
2. If filtered, try different encodings or obfuscation techniques
3. Test with various protocols (http, https, javascript, data, etc.)
4. Check for open redirects in all URL parameters

## Note

- Only test on systems you have permission to test
- Some payloads might be blocked by browser security features
- Be aware of legal implications when testing without authorization
