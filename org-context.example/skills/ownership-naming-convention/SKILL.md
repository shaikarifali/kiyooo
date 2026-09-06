---
name: ownership-naming-convention
description: >
  How testcorp's hostnames and cloud resource names encode team ownership,
  for use when the ownership bundle shows low confidence or no resolved
  owner — a hint for business_impact_hypothesis and remediation framing,
  never a substitute for the real ownership pipeline.
applies_to_categories: [exposed-nonprod-to-internet, shadow-saas-tenant]
---

# Ownership naming convention

testcorp hostnames follow `<service>-<team>.<env>.example.com`
(e.g. `checkout-payments.prod.example.com`) and cloud resources are tagged
`team:<team-id>` when created via the standard Terraform module — but a
meaningful fraction of resources predate that convention or were created
by hand, which is exactly when this skill is useful.

## When to use this

Only when the finding's ownership data (if surfaced in the bundle) shows
low confidence or no resolved owner. If ownership is already confidently
resolved, ignore this skill — don't second-guess a confident attribution
based on a naming heuristic.

## Heuristics, in order of reliability

1. `<service>-<team>` prefix in the hostname — `<team>` after the last
   hyphen before the environment segment is usually accurate, but treat it
   as a hint for the ticket's "who to push back to" framing, not a fact —
   the routing layer resolves the actual assignee independently.
2. AWS account naming: `testcorp-<team>-<env>` account aliases map 1:1 to
   teams. A resource in `testcorp-data-platform-prod` is very likely
   data-platform's, even with no explicit tag.
3. A completely generic hostname (`api.example.com`, `www.example.com`)
   with no team segment is usually platform/infra-owned, not a product
   team's — don't guess a specific product team from nothing.

## What NOT to do

- Never state a specific person's name as the owner from this heuristic
  alone — only a team-level guess, and only to inform the ticket's framing
  (e.g. "likely payments-owned based on hostname, please confirm"), never
  as a confident attribution claim in `business_impact_hypothesis`.
