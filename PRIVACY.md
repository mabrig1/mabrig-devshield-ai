# Privacy Notice

**MABRIG DevShield AI**  
Publisher: **MABRIG Technologies**  
Contact: **mabrig@mabrigkorie.org**

Last updated: September 13, 2026.

## Public GitHub Action and CLI

The self-managed DevShield Action and CLI run in the user's own GitHub Actions runner or local development environment. MABRIG Technologies does not operate a remote backend for the deterministic scanner in the public edition and does not receive repository source code from deterministic scans.

DevShield produces local/CI artifacts such as JSON and SARIF reports inside the user's workflow environment.

## Optional AI mode

AI review is opt-in. When a user supplies an AI-provider key, DevShield may send a truncated and redacted representation of relevant code changes to the configured provider for analysis. The user's relationship with that provider is also governed by the provider's own privacy and data-processing terms.

Users with source-code residency or confidentiality restrictions should keep AI mode disabled unless their policies permit the configured provider.

## Support

If users contact MABRIG Technologies for support, we may process the information they voluntarily provide, such as contact details, repository identifiers and diagnostic logs. Users should remove secrets, credentials and unnecessary proprietary source code before sending support material.

## Commercial managed service

A future DevShield Cloud/GitHub App may process installation metadata, subscription state, security findings, usage data and repository context needed to provide managed features. This notice must be updated with the final production data flows, subprocessors, retention periods and deletion process before that commercial service is launched.

## Contact

Privacy and data questions: **mabrig@mabrigkorie.org**
