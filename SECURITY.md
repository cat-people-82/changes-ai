# Security Policy

Changes AI is a security-focused tool, so vulnerability reports and privacy
issues should be handled carefully.

## Supported Versions

| Version | Supported |
|---|---|
| 0.6.3 preview | Yes |
| 0.6.2 preview | Yes |
| Older preview versions | No |

Until a stable 1.0 release exists, only the latest public preview is supported.

## Reporting a Vulnerability

Please do not open a public issue with exploit details, secrets, private source
snippets, or vulnerable target information.

Preferred reporting path:

1. Use GitHub private vulnerability reporting for this repository if it is
   enabled.
2. If private reporting is unavailable, contact the maintainer privately.
3. If no private channel is available, open a minimal public issue asking for a
   secure contact path. Do not include exploit details in that issue.

Include enough information to reproduce and assess the issue:

- affected Changes AI version or commit
- command and flags used
- relevant dependency manifest shape
- expected behavior
- actual behavior
- impact assessment
- whether secrets, source-derived usage data, or private repository data may be
  exposed

## Security Scope

In scope:

- leakage of API keys, tokens, source-derived usage data, or private repository
  data
- incorrect opt-in handling for hosted commercial LLM endpoints
- unsafe command execution or repository cloning behavior
- cache behavior that exposes sensitive data unexpectedly
- materially incorrect security output caused by deterministic application bugs

Out of scope:

- model hallucinations or judgment errors that are already labeled as
  confidence-limited LLM output
- vulnerabilities in scanned third-party projects
- rate limits or outages in upstream services such as OSV, PyPI, GitHub,
  libraries.io, or the configured LLM endpoint

## Disclosure

The maintainer will acknowledge valid private reports as soon as practical,
triage severity, and coordinate a fix or mitigation before public disclosure
where appropriate.
