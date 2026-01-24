# Security Policy

Thank you for helping to keep the X07 registry secure.

## Reporting a vulnerability

Please **do not** report security vulnerabilities via public GitHub issues, pull requests, or public discussions.

Preferred (if enabled): **GitHub Private Vulnerability Reporting**

1. Open this repository's **Security** tab.
2. Click **Advisories**.
3. Click **Report a vulnerability**.

Fallback: email **security@x07lang.org**.

When reporting, please include:

- Affected endpoint(s) and any request IDs (`x-request-id` header / `request_id` fields).
- A minimal repro (redact tokens and secrets).
- Impact assessment and whether exploitation is suspected.

## Supported versions

We generally patch and redeploy the registry quickly; production deployments are expected to track the latest release.

## Disclosure timeline

- **Acknowledgement:** within 72 hours.
- **Triage:** within 7 days.
- **Fix and deployment:** typically within 30 days (may vary by complexity/coordination).

## Credits

We will credit reporters in advisories and release notes unless you request otherwise.