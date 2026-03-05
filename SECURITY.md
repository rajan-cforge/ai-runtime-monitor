# Security Policy

## Reporting Vulnerabilities

**Please do not open a public issue for security vulnerabilities.**

Email: **rajan.conch@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Scope

This project monitors AI agent activity on your local machine. Security concerns include:

- **Data egress**: Sensitive data detected in AI sessions is stored locally in SQLite. Ensure the database file (`~/claude_watch_output/`) has appropriate file permissions.
- **Dashboard access**: The HTTP dashboard binds to `localhost:9081` by default. Do not expose it to untrusted networks.
- **mitmproxy mode**: The `claude-watch` proxy intercepts HTTPS traffic. The generated CA certificate should be treated as sensitive.

## Best Practices

- Run the monitor under your own user account, not as root
- Keep `~/claude_watch_output/` permissions restricted (`chmod 700`)
- Review alerts regularly for actual credential exposures
- Do not commit the SQLite database to version control
