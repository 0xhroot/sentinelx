# SentinelX Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in SentinelX, please report it responsibly.

**Do NOT** open a public GitHub issue.

Email your report to: **security@sentinelx.example.com**

Include in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### PGP Encryption

For sensitive reports, encrypt your email with our PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP key placeholder — contact security@sentinelx.example.com for current key]
-----END PGP PUBLIC KEY BLOCK-----
```

## Response Timeline

| Phase               | Timeline             |
|----------------------|----------------------|
| Acknowledgment       | Within 48 hours      |
| Initial assessment   | Within 1 week        |
| Fix development      | 7–30 days (depending on severity) |
| Public disclosure    | After fix is released |

Critical vulnerabilities (RCE, privilege escalation, data leakage) are prioritized for the fastest possible fix.

## Scope

### In Scope

- Remote code execution
- Privilege escalation beyond intended capabilities
- Bypass of detection mechanisms
- Data leakage of security-sensitive information
- Authentication/authorization bypass in fleet communication
- `unsafe` code misuse leading to memory corruption
- Denial of service against the detection pipeline
- SQL injection or other injection attacks
- Cryptographic weaknesses in TLS configuration

### Out of Scope

- Physical attacks
- Social engineering
- Issues in upstream dependencies (report to the dependency maintainer)
- Issues requiring pre-existing root access on the target system
- Denial of service via resource exhaustion on the host itself

## Safe Harbor

We support safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, or disruption to production systems
- Only interact with accounts you own or with explicit permission of the account holder
- Do not exploit a vulnerability beyond what is necessary to confirm its existence
- Report vulnerabilities promptly and do not publicly disclose details until a fix is released

We will not pursue legal action against researchers who follow these guidelines.

## Recognition

Security researchers who report valid vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous). We are grateful for the community's help in keeping SentinelX secure.
