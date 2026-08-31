# Launch Checklist

## Phase 1 — public Action
- [x] Create the dedicated public repository `mabrig1/mabrig-devshield-ai`
- [x] Replace placeholder repository references in README/workflow examples
- [x] Add self-test workflow
- [x] Add security policy and contribution/community files
- [x] Validate deterministic scanner locally
- [x] Push files and confirm GitHub-hosted CI passes
- [ ] Create `v1.0.0` release and stable `v1` tag
- [ ] Accept GitHub Marketplace Developer Agreement
- [ ] Publish the Action to Marketplace
- [ ] Add final support contact details

## Phase 2 — GitHub App
- [ ] Create or select a GitHub organization that will own the commercial App
- [ ] Enable organization 2FA requirement and verify the publisher domain
- [ ] Create GitHub App with minimum repository permissions
- [ ] Deploy the private commercial backend on Vercel
- [ ] Configure MongoDB Atlas
- [ ] Configure `marketplace_purchase`, installation, and pull-request webhooks
- [x] Handle purchased/changed/cancelled Marketplace plan events in code
- [x] Add delivery-ID idempotency
- [x] Add PR-file pagination (up to 300 files per managed review)
- [x] Update one managed review comment instead of spamming new comments
- [x] Add cancellation-data purge controls (usage deleted immediately; subscription TTL <=30 days)
- [ ] Acquire the installation threshold required by GitHub before paid listing submission
- [ ] Prepare logo, feature card, and screenshots
- [ ] Submit publisher/listing verification when eligible
- [ ] Create Free, Starter, Pro, and Team pricing plans using GitHub-supported billing options
- [ ] Complete financial onboarding

## Remaining production hardening
- [ ] Rate limiting and abuse protection
- [ ] Retry/dead-letter strategy for downstream AI/API failures
- [ ] Structured logs and alerting
- [ ] Customer usage dashboard
- [ ] Privacy and terms review by qualified counsel
- [ ] Enable GitHub Private Vulnerability Reporting
