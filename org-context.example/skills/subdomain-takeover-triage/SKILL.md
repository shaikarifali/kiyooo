---
name: subdomain-takeover-triage
description: >
  Playbook for triaging dangling-DNS / subdomain-takeover findings — which
  CNAME targets are actually claimable today, and how to tell a stale-but-
  harmless CNAME from a live takeover.
applies_to_categories: [subdomain-takeover]
---

# Subdomain takeover triage

A dangling CNAME is only a real finding if the target service is currently
in a "claimable" state. Do not call this a true positive purely because a
CNAME points at a third-party domain — most third-party CNAMEs are healthy.

## Decision tree

1. **Does the CNAME target respond at all?**
   - No response / connection refused / NXDOMAIN on the target → likely
     claimable. Lean true_positive, severity high (critical if the
     hostname carries an authentication cookie's parent domain, e.g. an
     `app.` or `auth.` subdomain).
   - Target responds with the *provider's own* "no such app/site/bucket"
     page (e.g. GitHub Pages' 404, S3's `NoSuchBucket`, Heroku's "no such
     app") → claimable. This is the classic takeover signature.
   - Target responds with real content that looks like it belongs to this
     org → not_exploitable. Someone still owns it; the DNS record is just
     stale bookkeeping.

2. **Is the provider one with a known takeover history?** GitHub Pages, S3,
   Heroku, Azure, Fastly, Shopify, and Unbounce have all had documented
   takeover classes. A dangling CNAME to one of these deserves more
   confidence than an unfamiliar provider — but still verify the response,
   don't pattern-match on provider name alone.

3. **Business impact scales with what the subdomain implies.** A takeover
   of `status.example.com` is embarrassing (defacement, phishing surface).
   A takeover of a subdomain that a browser would treat as same-origin for
   session cookies (no explicit `Domain=` scoping issue aside) is a
   session-hijacking primitive — call that out explicitly in
   `business_impact_hypothesis`.

## What NOT to do

- Never conclude "claimable" from DNS resolution alone (e.g., NXDOMAIN on
  the CNAME target's own DNS) without also checking the HTTP response —
  some providers 404 differently than DNS-not-found.
- Don't downgrade a claimable subdomain because "it's just a marketing
  site" — a takeover is a takeover; severity should reflect how the
  subdomain would be *used* by an attacker (phishing, cookie theft), not
  how important the current content looks.
