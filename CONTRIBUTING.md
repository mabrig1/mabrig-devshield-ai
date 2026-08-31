# Contributing

Thank you for helping improve MABRIG DevShield AI.

1. Fork the repository and create a focused branch.
2. Add or update a deterministic test for rule changes.
3. Run `npm test` on Node.js 20 or newer.
4. Open a pull request explaining the risk pattern, expected signal quality, and likely false-positive cases.

Security rules should prioritize high-signal findings. Avoid broad regular expressions that generate large numbers of false positives.
