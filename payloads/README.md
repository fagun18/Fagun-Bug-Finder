# Fagun Payloads Directory

This directory contains various payloads used by the Fagun security testing tool. The payloads are organized by vulnerability type for easy access and management.

## Directory Structure

```
payloads/
├── README.md                 # This file
├── lfi/                     # Local File Inclusion payloads
│   └── lfi_payloads.txt     # LFI testing payloads
├── or/                      # Open Redirect payloads
│   └── or_payloads.txt      # Open redirect testing payloads
├── sqli/                    # SQL Injection payloads
│   ├── generic.txt          # Generic SQLi payloads
│   ├── mysql.txt            # MySQL-specific SQLi payloads
│   ├── mssql                # MSSQL-specific SQLi payloads
│   ├── oracle.txt           # Oracle-specific SQLi payloads
│   ├── postgresql.txt       # PostgreSQL-specific SQLi payloads
│   └── xor.txt              # XOR-based SQLi payloads
└── xss/                     # Cross-Site Scripting payloads
    ├── xss_payloads.txt     # Basic XSS payloads
    └── xss_polyglots.txt    # XSS polyglot payloads
```

## Usage

1. **LFI Payloads**: Used for testing Local File Inclusion vulnerabilities
2. **OR Payloads**: Used for testing Open Redirect vulnerabilities
3. **SQLi Payloads**: Organized by database type (MySQL, MSSQL, Oracle, PostgreSQL)
   - `generic/`: Works across multiple database types
   - Database-specific files: Contains payloads optimized for specific databases
4. **XSS Payloads**:
   - `xss_payloads.txt`: Standard XSS test cases
   - `xss_polyglots.txt`: Advanced polyglot payloads that work in multiple contexts

## Adding New Payloads

1. Choose the appropriate directory for the payload type
2. Add your payloads to the relevant file or create a new file if needed
3. Follow the existing format and add comments if necessary
4. Test your payloads before committing

## Note

- Always use these payloads responsibly and only on systems you have permission to test
- Some payloads might trigger security systems or cause unintended effects
- Always have proper authorization before testing any system
