# SQL Injection Payloads

This directory contains SQL Injection payloads organized by database type. Each file contains specific payloads designed to work with different database management systems.

## Files

- `generic.txt`: Payloads that work across multiple database types
- `mysql.txt`: MySQL-specific SQL injection payloads
- `mssql`: MSSQL-specific SQL injection payloads
- `oracle.txt`: Oracle-specific SQL injection payloads
- `postgresql.txt`: PostgreSQL-specific SQL injection payloads
- `xor.txt`: XOR-based SQL injection payloads

## Usage

1. Start with `generic.txt` payloads for initial testing
2. If you identify the database type, use the corresponding database-specific payloads
3. For complex scenarios, try the XOR-based payloads in `xor.txt`

## Best Practices

- Always test payloads in a controlled environment first
- Be aware of Web Application Firewalls (WAFs) that might block certain payloads
- Use comments in your payloads to document their purpose
- Always have proper authorization before testing any system

## Note

These payloads are for educational and authorized security testing purposes only. Unauthorized use is illegal.
