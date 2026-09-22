# Security Policy

## Security Commitment

Sentinel is a high-assurance, FAPI 2.0-compliant security gateway enforcing
sender-constrained token validation (DPoP per RFC 9449, mTLS binding, replay
protection, and strict JWT validation). Security is a core design principle:
the service fails closed on dependency or validation failures, and all
security-relevant behavior is covered by automated gates, threat modeling,
and independent testing. We take vulnerability reports seriously and are
committed to timely triage, remediation, and coordinated disclosure.

## Supported Versions

| Version | Runtime | Status |
|---------|---------|--------|
| `1.0.x` | .NET 10 LTS | Supported |
| `< 1.0` / older | — | Unsupported |

Only the latest `1.0.x` release line on .NET 10 LTS receives security fixes.
Older versions are unsupported and should be upgraded. If you are unsure
which version you are running, check `version.json` or the release tag.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for a security vulnerability.**

Please report privately via one of the following:

- GitHub Security Advisories (preferred): use the **Report a vulnerability**
  (Security > Advisories) flow on this repository, or
- Email: `security@sentinel.local`

To help us triage quickly, please include where possible:

- Affected component(s) (e.g. DPoP validator, replay cache, session flow)
- Affected version / commit and deployment configuration
- Step-by-step reproduction instructions and a proof of concept
- DPoP proof traces / request samples (redact private key material)
- Impact assessment (what an attacker can achieve)

We ask that you do not access, modify, or exfiltrate data beyond what is
necessary to demonstrate the issue, and that you do not perform disruptive
testing against production systems.

## Response & Triage SLAs

Aligned with `docs/PENTEST_PROGRAM.md`:

| Severity | Initial response | Remediation SLA |
|----------|------------------|-----------------|
| Critical | < 24 hours | 24 hours |
| High | < 24 hours | 7 days |
| Medium / Low | < 72 hours | 30–90 days |

Severity is assessed by the maintainers using impact and exploitability
(e.g. authentication bypass, token replay, or remote compromise rank
highest). We will acknowledge receipt, share a triage assessment and
expected timeline, and keep you informed until resolution and disclosure.

## Safe Harbor / Coordinated Vulnerability Disclosure

We support good-faith security research and coordinated vulnerability
disclosure. Researchers who act in good faith, stay within the authorized
bounds above, avoid privacy violations and service disruption, and give us
reasonable time to remediate before public disclosure will not face legal
action for their research under this policy.

We ask that you:

- Limit testing to systems you are authorized to test
- Do not exploit a vulnerability beyond minimal demonstration
- Do not publicly disclose the issue until we have remediated it and
  agreed on a disclosure timeline

Thank you for helping keep Sentinel and its users safe.
