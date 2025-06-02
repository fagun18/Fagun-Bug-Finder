Here's a **refined and better-formatted version** of your README markdown for `Fagun Bug Finder`, improving consistency, clarity, and visual structure while retaining all the important details:

---

````markdown
# Fagun Bug Finder

> **Fagun** is an advanced web vulnerability scanner that helps identify security issues in web applications.

[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

### 🔍 Supported Vulnerabilities

| Vulnerability | Status | Description                  |
|--------------:|:------:|------------------------------|
| `LFI`         |   🛠   | Local File Inclusion         |
| `OR`          |   🛠   | Open Redirection             |
| `XSS`         |   🛠   | Cross-Site Scripting         |
| `SQLi`        |   🛠   | SQL Injection                |
| `CRLF`        |   🛠   | CRLF Injection               |

---

## 📚 Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [XSS Testing with `all_url_xss_pipeline.sh`](#xss-testing-with-all_url_xss_pipelinesh)
- [Vulnerability Guides](#vulnerability-guides)
  - [LFI (Local File Inclusion)](#lfi-local-file-inclusion)
  - [SQL Injection (SQLi)](#sql-injection-sqli)
  - [XSS (Cross-Site Scripting)](#xss-cross-site-scripting)
  - [Open Redirect (OR)](#open-redirect-or)
  - [CRLF Injection](#crlf-injection)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## 🚀 Features

- **Multi-threaded Scanning** – Fast, efficient testing
- **Comprehensive Coverage** – Scan for multiple vulnerability types
- **Custom Payload Support** – Use or modify your own payloads
- **HTML Reporting** – Get detailed vulnerability reports
- **Clean CLI UI** – Simple and intuitive command-line interface
- **Save Results** – Log vulnerable URLs for future reference

---

## ⚙️ Installation

### Requirements
- Python 3.6+
- Google Chrome
- ChromeDriver

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/fagun18/Fagun-Bug-Finder.git
cd Fagun-Bug-Finder

# 2. Install dependencies
pip3 install -r requirements.txt
````

### Install Chrome & ChromeDriver

```bash
# Install Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt -f install  # Fix any dependencies

# Install ChromeDriver
wget https://storage.googleapis.com/chrome-for-testing-public/128.0.6613.119/linux64/chromedriver-linux64.zip
unzip chromedriver-linux64.zip
sudo mv chromedriver /usr/bin/
```

---

## ▶️ Usage

Run the scanner:

```bash
python3 FAGUN.py
```

---

## ⚔️ XSS Testing with `all_url_xss_pipeline.sh`

Use the `all_url_xss_pipeline.sh` script to automate XSS vulnerability testing via `fagun.py`.

### Step 1: Make script executable

```bash
chmod +x all_url_xss_pipeline.sh
```

### Step 2: Run the script

Choose one of the payload files and run:

```bash
./all_url_xss_pipeline.sh vulnweb.com /Fagun-Bug-Finder/payloads/xss/xsspollygots.txt
```

Or:

```bash
./all_url_xss_pipeline.sh vulnweb.com /Fagun-Bug-Finder/payloads/xss/xss_payloads.txt
```

---

## 🛡️ Vulnerability Guides

<details>
<summary><strong>LFI (Local File Inclusion)</strong></summary>

**What is LFI?**
Local File Inclusion allows attackers to include files from the server, leading to sensitive data exposure or code execution.

**Testing Steps:**

* Look for parameters like `?page=about.php`
* Try: `?page=../../../../etc/passwd`
* Use encoded/null byte techniques
* Explore log poisoning

**Learn More:**

* [OWASP LFI Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
* [PortSwigger LFI Guide](https://portswigger.net/web-security/file-path-traversal)
* [HackTricks LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

</details>

<details>
<summary><strong>SQL Injection (SQLi)</strong></summary>

**What is SQLi?**
A code injection vulnerability that allows execution of SQL queries, potentially leading to unauthorized data access.

**Testing Steps:**

* `' OR '1'='1`
* UNION and error-based tests
* Time-based blind injection

**Learn More:**

* [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
* [PortSwigger SQLi](https://portswigger.net/web-security/sql-injection)
* [SQLi Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

</details>

<details>
<summary><strong>XSS (Cross-Site Scripting)</strong></summary>

**What is XSS?**
Allows attackers to inject JavaScript into web pages, affecting other users.

**Testing Steps:**

* `<script>alert(1)</script>`
* HTML injection (e.g., `<h1>XSS</h1>`)
* Check for stored, reflected, and DOM-based vectors

**Learn More:**

* [OWASP XSS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
* [XSS Filter Evasion](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

</details>

<details>
<summary><strong>Open Redirect (OR)</strong></summary>

**What is Open Redirect?**
A vulnerability that redirects users to untrusted locations via user-controlled input.

**Testing Steps:**

* Parameters like `?next=`, `?redirect=`
* Use: `?url=https://evil.com`

**Learn More:**

* [OWASP Redirect Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
* [PortSwigger Open Redirect](https://portswigger.net/web-security/ssrf)
* [HackTricks OR](https://book.hacktricks.xyz/pentesting-web/open-redirect)

</details>

<details>
<summary><strong>CRLF Injection</strong></summary>

**What is CRLF?**
Inserts carriage return (CR) and line feed (LF) to manipulate HTTP headers.

**Testing Steps:**

* Use `%0D%0A` in URL params
* Look for response splitting

**Learn More:**

* [OWASP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Security_Cheat_Sheet.html)
* [PortSwigger CRLF](https://portswigger.net/kb/issues/00600b00_http-headers-injection)
* [CRLF Injection Guide](https://www.acunetix.com/websitesecurity/crlf-injection/)

</details>

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

---

## 📄 License

Licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is for **educational and authorized testing** purposes only. Use it only on systems you own or have permission to test. The authors are **not responsible for misuse or any damages** caused.

```

---

### ✅ Enhancements Made:
- Cleaned section headers and spacing for readability.
- Added emoji for visuals and quick scanning.
- Used collapsible `<details>` blocks for vulnerability explanations to reduce visual clutter.
- Applied consistent markdown and bash code block formatting.
- Improved callout styling for emphasis (e.g., `What is XSS?`, `Testing Steps`).
- Refined the language to be concise and professional.

Let me know if you'd like a version with GitHub badges for contributors, issues, forks, or a dark-themed version!
```
