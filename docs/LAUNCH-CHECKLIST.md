# Launch Checklist

## Phase 1 — public Action
- [x] Create the dedicated public repository `mabrig1/mabrig-devshield-ai`
- [x] Replace placeholder repository references in README/workflow examples
- [x] Add self-test workflow
- [x] Add security policy and contribution/community files
- [x] Validate the deterministic scanner and local CLI
- [x] Add dependency intelligence, finding baselines, SARIF/JSON reporting, and staged-change protection
- [x] Keep the stable `v1` compatibility branch aligned with the current v1 code
- [x] Confirm DevShield v1.4 CI passes on GitHub
- [x] Add production customer-path certification for safe-pass and unsafe-block behavior
- [x] Add a guarded release workflow for GitHub Release publication and `v1` promotion
- [ ] Publish GitHub Release `v1.4.0`
- [ ] Accept GitHub Marketplace Developer Agreement
- [ ] Publish the Action to Marketplace
- [x] Add final support/contact details (`mabrig@mabrigkorie.org`)
- [x] Add immediate paid implementation/security-hardening offers
- [x] Add commercial pricing, privacy notice and service terms
- [ ] Validate the Marketplace listing from a separate customer/test repository

## Phase 2 — GitHub App
- [ ] Create the **MABRIG Technologies** GitHub organization that will own the commercial App
- [ ] Build acquisition funnel toward at least 100 GitHub App installations before paid-plan submission
- [ ] Enable organization 2FA requirement and verify the publisher domain
- [ ] Create GitHub App with minimum repository permissions
- [ ] Deploy the private commercial backend
- [ ] Configure the production database
- [ ] Configure `marketplace_purchase`, installation, and pull-request webhooks
- [x] Handle purchased/changed/cancelled Marketplace plan events in code
- [x] Add delivery-ID idempotency
- [x] Add PR-file pagination (up to 300 files per managed review)
- [x] Update one managed review comment instead of spamming new comments
- [x] Add cancellation-data purge controls (usage deleted immediately; subscription TTL <=30 days)
- [ ] Acquire the installation threshold required by GitHub before paid listing submission
- [ ] Prepare logo, feature card, and screenshots
- [ ] Submit publisher/listing verification when eligible
- [ ] Create Community, Solo, Pro, Team and Business pricing plans using GitHub-supported billing options
- [ ] Complete financial onboarding

## Remaining production hardening for the commercial service
- [ ] Rate limiting and abuse protection
- [ ] Retry/dead-letter strategy for downstream AI/API failures
- [ ] Structured logs and alerting
- [ ] Customer usage dashboard
- [ ] Privacy and terms review by qualified counsel
- [ ] Enable GitHub Private Vulnerability Reporting
