# Security Policy

## Supported Versions

Security fixes are applied to the latest release on `main`.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

To report a security issue, email the maintainers at the address listed in the repository or contact the repository owner via [GitHub private vulnerability reporting](https://github.com/RecursiveDev/WarpShift-TUI/security/advisories/new).

### What to Include

- Description of the vulnerability and its potential impact.
- Steps to reproduce or a proof of concept.
- Affected version or commit.
- Any suggested fix, if available.

### Response Timeline

- **Acknowledgment:** Within 72 hours.
- **Initial assessment:** Within 1 week.
- **Fix or mitigation:** Dependent on severity and complexity.

You will be notified of the outcome. If the vulnerability is confirmed, a fix will be developed and a security advisory published.

## Security Considerations for Users

WarpShift-TUI handles sensitive network configuration material. Keep the following in mind:

- **Identity files** (`warpshift.identity.json`) contain private keys. Never commit them or share them.
- **WireGuard profiles** (`*.wg.conf`) contain private keys. Treat them as secrets.
- **Local configuration** (`warpshift.local.toml`) may contain environment-specific settings. Do not commit it.
- **Proxy credentials** — if using proxy authentication, store credentials securely and avoid plaintext in shared config files.

All sensitive file patterns are covered in `.gitignore`. Verify your local `.gitignore` is up to date before committing.
