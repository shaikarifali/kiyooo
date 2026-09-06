---
name: ticket-house-style
description: >
  testcorp's house style for remediation writing — how appsec phrases
  steps so an on-call engineer with no security background can act on a
  ticket without a follow-up question, matching the design's ticket-contract
  goal of zero clarifying questions per ticket.
applies_to_categories: [exposed-database, exposed-admin-panel, exposed-devops-console, leaked-secret]
---

# Ticket house style

This shapes how the model's `remediation` block reads once it lands in a
ticket (`route/ticket_contract.py`'s "what to do" section) — write for the
engineer who gets paged at 2am, not for a security peer.

## Style rules

- **Imperative, numbered steps**, not prose paragraphs. "Rotate the
  credential in Vault, then redeploy" beats "The credential should be
  rotated and the service redeployed."
- **Name the actual tool/system**, not a generic category. testcorp uses
  Vault for secrets, Terraform for infra changes, and Cloudflare for the
  edge — say "add a Cloudflare Access policy," not "restrict access."
- **State the blast radius of the fix**, one line, when it's not obvious —
  "this only affects the staging listener; prod is unaffected" saves a
  Slack thread.
- **Never say "should probably"** — either the evidence supports a
  specific action or the verdict should be `needs_human`, not a hedge
  dressed up as remediation.
- **Effort estimate should assume the reader has never touched this
  service before** — testcorp's on-call rotation means the assignee is
  often not the service's usual owner.

## Example

Bad: "Consider restricting access to this admin panel and possibly
enabling authentication."

Good: "1. Add the admin panel's hostname to the internal-only Cloudflare
Access policy (`terraform/access-policies/internal.tf`). 2. Redeploy via
the standard `terraform apply` flow. 3. Confirm the panel now redirects to
SSO before closing this ticket."
