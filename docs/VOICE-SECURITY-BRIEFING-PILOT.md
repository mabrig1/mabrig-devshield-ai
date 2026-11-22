# DevShield Voice Security Briefing — Read-only Pilot

Status: **draft PR only**. This feature is not declared live, approved, merged or deployed.

## What this implements
- A mobile-friendly, accessibility-aware question-and-answer panel on the existing browser-local scanner page.
- Deterministic explanations of the latest scan's indicator counts, severity ranking and suggested human review.
- Opt-in microphone dictation using browser SpeechRecognition when available, optional spoken answers using browser speechSynthesis, and a complete typed-text fallback.
- Explicit **Unknown / Not connected** answers for Cloudflare, WAF, live incidents, geographic attribution, website safety, traffic or requests.
- A narrowly scoped read-only public NIST NVD CVE publication endpoint for 6/7/12/24-hour UTC windows; no account token, paid API or privileged changes.
- No hosted code scanning API, no remote AI, no payment, no Cloudflare account connection.

## Evidence contract
The preview only emits `devshield:local-report` after a completed local scan. It contains schema, completion status, scan time, reviewed item count, and sanitized finding metadata (rule/severity/message/remediation). It **does not** include source code, pasted snippets, file content or file paths. Clearing the browser preview clears the assistant's active report. There is no local-storage persistence.

The word *indicator* is important: matching code indicators are not proof of compromise or an observed network attack. A zero-indicator or incomplete scan does not certify safety. The assistant must never fabricate attack, block, or country counts.

## Voice privacy
- The browser asks for microphone permission only after the user presses **Speak question**.
- Speech recognition implementation and network processing vary by browser. Some browsers send audio to their speech provider; the user must not dictate credentials or confidential details.
- Text mode requires no microphone. The only new browser network call is an explicit read-only GET to the same-origin public NVD lookup endpoint, with the numeric time-window parameter; no scanned content, credentials or local report leave the browser.
- Speech playback is optional; browsers may implement voices differently. **Stop voice** cancels recognition and playback where supported.
- The existing local-code scanner remains browser-only. CSP is narrowly relaxed to `connect-src 'self'` to permit the official NVD data GET through the same-origin Worker, while the scanner code still contains no network calls. The microphone permissions policy is narrowly changed from disabled to same-origin permission availability so the user can opt in; it does not grant microphone access automatically.

## Build and review
1. Review the changed homepage, browser app, new briefing module and tests. Confirm `/security-briefing.js` is served as an asset.
2. Run `npm run build` at repository root and `npm run check` under `cloudflare-deploy`. No Cloudflare secrets are required.
3. In a branch preview, run the browser scanner with harmless test snippets, ask for a scan summary and recommended review, and check that website attack counts and country attribution reply **Unknown**. Check 6/7/12/24-hour public CVE lookups, timestamps and NVD source links.
4. Test microphone permission denial, unsupported speech recognition, speaking, stopping, mobile layout and keyboard navigation. Verify no source snippet leaves the browser. Simulate NVD upstream outage/429; the assistant must report unavailable, never zero attacks.
5. **Do not merge or deploy until reviewed and explicitly approved.** Any browser preview URL is not proof of production release.


## Global cybersecurity lookback (implemented in this draft)
- Say **"Check worldwide cybersecurity in the last 6 hours"**, **"the past seven hours"**, **"last 12 hours"** or **"last 24 hours"**, or tap the matching button.
- This first data adapter queries NIST's `/rest/json/cves/2.0` using a bounded 6/7/12/24-hour publication window, rounded down to a five-minute UTC boundary for cache sharing.
- The adapter returns up to 20 published CVE records with checked UTC window, original publication timestamps, canonical NVD CVE detail links, and an explicit **partial** flag if more exist. The UI shows a maximum of 10 links and reads only a short summary aloud.
- A CVE publication is **not** an attack observation, a breach, a threat incident, a live alert, or proof of exploitation. No single global source can support a claim about every attack worldwide. NVD publication/processing can lag the actual vulnerability discovery.
- NVD outage, rate-limit response, malformed JSON or invalid time window fail closed. No fabricated counts or fake up-to-the-minute coverage. Review NVD API availability and rate limits before considering release.
- This public read-only lookup has no login and is not connected to Cloudflare tokens, protected site logs or any customer identifiers. It may need caching or tighter request quotas in a production design.
- The first source is intentionally only NVD, not social media, the open web, press releases or all cyber incidents. More carefully sourced feeds could follow independently.

## Future live-telemetry integration — NOT implemented
Cloudflare documents the zone-scoped `firewallEventsAdaptive` Security Events dataset and Analytics GraphQL API:
- https://developers.cloudflare.com/waf/analytics/security-events/
- https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events/

A future version should use a separately authorized backend with a restricted read-only Cloudflare token, strict per-tenant authentication/authorization, explicit zone allowlists, bounded time windows, rate limits and structured audit logs. Aggregates should preserve provider action semantics and sample/retention limits; **security events are not necessarily malicious attacks**. Fail closed with Unknown when telemetry, scope or permissions are missing. Never send credentials or raw event PII to a conversational provider. Keep remediation suggestions approval-gated; no automatic WAF rule changes.
