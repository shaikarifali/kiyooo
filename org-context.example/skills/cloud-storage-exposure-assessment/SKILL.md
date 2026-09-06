---
name: cloud-storage-exposure-assessment
description: >
  How to assess whether a publicly-listable/readable cloud storage bucket
  actually contains anything sensitive, versus static-site or public-CDN
  content that's exposed by design.
applies_to_categories: [exposed-cloud-storage]
---

# Cloud storage exposure assessment

A publicly reachable bucket is not automatically a true positive — a large
fraction of "exposed" buckets are intentionally public (static sites,
public asset CDNs, open-data buckets). The finding is real when the bucket
serves content it shouldn't.

## Decision tree

1. **Can you list the bucket, or only fetch known object paths?**
   Listable (`?list-type=2` succeeds, or an S3-style XML listing renders)
   is worse than fetch-only, since listing itself enumerates every object
   name — potentially sensitive paths (`backups/`, `customer-exports/`)
   leak even if individual objects later turn out to require auth.

2. **What do the object names/paths suggest?**
   - `assets/`, `static/`, `public/`, `cdn/` prefixes with image/JS/CSS
     extensions → likely intentional, lean not_exploitable unless content
     says otherwise.
   - `backup`, `export`, `dump`, `db`, `.sql`, `.env`, `credentials`,
     `secrets`, date-stamped archive names (`2025-01-*.tar.gz`) → strong
     signal of a real exposure. Lean true_positive, severity critical if
     any object fetch confirms real (non-synthetic) data.
   - A bucket name matching a known internal tool or environment
     (`-staging`, `-internal`, `-admin`) is worse than a customer-facing
     product bucket name, all else equal — internal tooling buckets are
     rarely meant to be public even when misconfigured the same way.

3. **Sample, don't assume.** If evidence includes a fetched object's
   content (not just a listing), check it for real customer data vs.
   fixture/seed data (faker names, `example.com` emails, obviously
   synthetic values) — seeded data downgrades severity even if the bucket
   genuinely shouldn't be public.

## What NOT to do

- Don't call every listable bucket critical — severity should track what's
  actually inside, not just the listability misconfiguration itself.
- Don't assume a bucket is safe because its name sounds like a CDN — verify
  against the actual listing/object content when evidence includes it.
