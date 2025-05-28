# LFI (Local File Inclusion) Payloads

This directory contains payloads for testing Local File Inclusion vulnerabilities. These payloads help identify if a web application is vulnerable to reading local files on the server.

## File

- `lfi_payloads.txt`: Contains various LFI payloads for testing file inclusion vulnerabilities

## Common LFI Techniques

- Basic file inclusion: `../../../etc/passwd`
- Null byte injection: `../../../etc/passwd%00`
- Path truncation: `../../../../../../../../../etc/passwd`
- PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`

## Usage

1. Test with basic payloads first
2. If filtered, try different encodings or obfuscation techniques
3. For PHP applications, test with PHP wrappers
4. Check for log poisoning possibilities

## Note

- Always test with permission on systems you own or have authorization to test
- Some payloads might cause server load or errors
- Be aware of legal implications when testing without authorization
