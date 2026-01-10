# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in PST WEEE, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to the repository maintainer
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability and determine its severity
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical vulnerabilities within 7 days
- **Credit**: We will credit you in the release notes (unless you prefer anonymity)

## Security Considerations

### PST File Handling

- PST files may contain sensitive email data
- This tool processes files locally; no data is transmitted externally
- Output CSV files should be handled with appropriate care

### TLD Validation

- The tool downloads the IANA TLD list for validation
- This is the only network request made by the application
- The download uses HTTPS to ensure integrity

### Dependencies

We regularly audit our dependencies for known vulnerabilities:

```bash
cargo audit
```

### Resource Limits

The tool includes resource management features to prevent:

- CPU exhaustion
- Memory exhaustion
- Disk space issues

Use the `--safe` flag for conservative resource limits.

## Best Practices

When using PST WEEE:

1. **File Permissions**: Ensure output CSV files have appropriate permissions
2. **Temporary Files**: The tool does not create temporary files with sensitive data
3. **Logging**: Debug mode may log email addresses; use with caution
4. **Blacklist**: Review and customize `config/blacklist.ron` for your needs

## Security Updates

Security updates will be released as patch versions (e.g., 0.2.1, 0.2.2).

Subscribe to repository releases to be notified of security updates.
