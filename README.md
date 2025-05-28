## Fagun Bug Finder

> **Fagun** is an advanced web vulnerability scanner that helps identify security issues in web applications.

| Vulnerability | Status | Description |
|--------------|--------|-------------|
| `LFI` | | Local File Inclusion |
| `OR` | | Open Redirection |
| `XSS` | | Cross-Site Scripting |
| `SQLi` | | SQL Injection |
| `CRLF` | | CRLF Injection |

[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Vulnerability Guides](#-vulnerability-guides)
  - [LFI (Local File Inclusion)](#-lfi-local-file-inclusion)
  - [SQL Injection (SQLi)](#-sql-injection-sqli)
  - [XSS (Cross-Site Scripting)](#-xss-cross-site-scripting)
  - [Open Redirect (OR)](#-open-redirect-or)
  - [CRLF Injection](#-crlf-injection)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)

## Features

- **Multi-threaded Scanning**: Fast and efficient scanning through multi-threading
- **Comprehensive Testing**: Test for multiple vulnerability types
- **Customizable Payloads**: Modify payloads to suit specific targets
- **Detailed Reporting**: Generate HTML reports of found vulnerabilities
- **User-friendly Interface**: Simple and intuitive command-line interface
- **Save Results**: Option to save vulnerable URLs for future reference

## Installation

### Prerequisites
- Python 3.6 or higher
- Google Chrome browser
- ChromeDriver

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/fagun18/Fagun-Bug-Finder.git
   cd Fagun-Bug-Finder
   ```

2. **Install dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Install Chrome & ChromeDriver**:
   ```bash
   # On Ubuntu/Debian
   wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
   sudo dpkg -i google-chrome-stable_current_amd64.deb
   sudo apt -f install  # If you encounter any errors
   
   # Install ChromeDriver
   wget https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.119/linux64/chromedriver-linux64.zip
   unzip chromedriver-linux64.zip
   sudo mv chromedriver /usr/bin/
   ```

## Usage

```bash
python3 FAGUN.py
```

## Vulnerability Guides

<details>
<summary> LFI (Local File Inclusion)</summary>

### What is LFI?
Local File Inclusion (LFI) is a vulnerability that allows an attacker to include files on a server through the web browser. This can lead to information disclosure, cross-site scripting (XSS), and in some cases, remote code execution.

### How to Test for LFI
1. Look for URL parameters that include files (e.g., `page=about.php`)
2. Try to access system files: `http://example.com/index.php?page=../../../../etc/passwd`
3. Test with URL encoding and null bytes
4. Check for log poisoning possibilities

### Learning Resources
- [OWASP LFI Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [PortSwigger LFI Guide](https://portswigger.net/web-security/file-path-traversal)
- [HackTricks LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
</details>

<details>
<summary> SQL Injection (SQLi)</summary>

### What is SQL Injection?
SQL Injection is a code injection technique that might destroy your database. It is one of the most common web hacking techniques that can lead to unauthorized access to sensitive data.

### How to Test for SQLi
1. Test with single quote (`'`) and look for errors
2. Try boolean-based tests: `' OR '1'='1`
3. Test for UNION-based injection
4. Check for time-based blind SQLi
5. Test for error-based injection

### Learning Resources
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQLi](https://portswigger.net/web-security/sql-injection)
- [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
</details>

<details>
<summary> XSS (Cross-Site Scripting)</summary>

### What is XSS?
Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject client-side scripts into web pages viewed by other users.

### How to Test for XSS
1. Test with simple alert: `<script>alert(1)</script>`
2. Test with HTML injection: `<h1>Test</h1>`
3. Check for DOM-based XSS
4. Test for stored XSS in forms and input fields
5. Verify Content Security Policy (CSP) implementation

### Learning Resources
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
</details>

<details>
<summary> Open Redirect (OR)</summary>

### What is Open Redirect?
Open Redirect vulnerabilities occur when a web application takes a parameter and redirects users to the parameter value without proper validation.

### How to Test for Open Redirects
1. Look for URL parameters like `redirect`, `url`, `next`, `target`
2. Test with external domains: `?url=https://evil.com`
3. Check for double-encoding bypasses
4. Test for protocol-relative URLs
5. Verify if redirects validate the target domain

### Learning Resources
- [OWASP Unvalidated Redirects Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [PortSwigger Open Redirect](https://portswigger.net/web-security/ssrf)
- [HackTricks Open Redirect](https://book.hacktricks.xyz/pentesting-web/open-redirect)
</details>

<details>
<summary> CRLF Injection</summary>

### What is CRLF Injection?
CRLF (Carriage Return Line Feed) Injection is a vulnerability that occurs when an attacker is able to insert CRLF control characters into HTTP headers or content.

### How to Test for CRLF Injection
1. Look for URL parameters that get reflected in headers
2. Test with CRLF sequences: `%0D%0A`
3. Check for HTTP header injection
4. Test for HTTP response splitting
5. Verify if user input is properly encoded in headers

### Learning Resources
- [OWASP CRLF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Security_Cheat_Sheet.html)
- [PortSwigger CRLF](https://portswigger.net/kb/issues/00600b00_http-headers-injection)
- [CRLF Injection Explained](https://www.acunetix.com/websitesecurity/crlf-injection/)
</details>

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and testing purposes only. The developers are not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before scanning any website or network.
