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

## Optional DevShield Cloud export

DevShield v1.4 includes an opt-in export bridge to a configured managed endpoint. When enabled, the Action can send repository/revision identifiers, run metadata, aggregate scan metrics and structured security findings needed for dashboards, history, usage metering and managed services.

The v1.4 Cloud payload does not include source code, source-line text, code snippets, diff text, GitHub tokens, the DevShield Cloud token or local environment variables.

The managed endpoint, retention policy, subprocessors, deletion process and customer data controls must be documented for the production DevShield Cloud service before commercial launch.

## Contact

Privacy and data questions: **mabrig@mabrigkorie.org**
