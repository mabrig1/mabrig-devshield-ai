# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could expose credentials, customer data, or a bypass in DevShield's security checks.

Use GitHub Private Vulnerability Reporting on this repository when enabled. If it is not available, contact the publisher through the support contact listed on the GitHub Marketplace listing.

Include the affected version, reproduction steps, expected impact, and any safe proof-of-concept details. Do not include real secrets or third-party customer source code.

## Supported versions

Security fixes are applied to the current `v1` major release line. Users should track the stable `v1` tag or a full release tag such as `v1.0.0`.

## Security model

Deterministic scanning runs locally on the GitHub Actions runner. AI review is optional. When enabled, a truncated diff is redacted for common secret formats before it is sent to the configured AI provider. Users with source-code residency restrictions should leave AI review disabled.
