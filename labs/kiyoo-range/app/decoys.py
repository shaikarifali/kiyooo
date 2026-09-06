"""The four decoys that had no home anywhere before this app: no lab
planted `exposed-devops-console`, `subdomain-takeover`,
`known-exploited-cve`, or `shadow-saas-tenant` assets until now. Each
function returns `(status_code, headers, body)` matching the exact
`detect:` predicate in `org-context.example/categories/00-core/` — same
discipline as `labs/kiyoo-ai`'s services: checked against the real regex,
not eyeballed.
"""

from __future__ import annotations


def jenkins() -> tuple[int, dict[str, str], str]:
    # exposed-devops-console: http_body_matches "(?i)(jenkins|argo cd|...)"
    body = (
        "<title>Dashboard [Jenkins]</title>"
        "<h1>Jenkins</h1>"
        "<p>Welcome to Jenkins! (kiyoo-range decoy — see /_lab/notice)</p>"
        "<ul><li>deploy-prod</li><li>run-migrations</li><li>rotate-secrets</li></ul>"
    )
    return 200, {"X-Jenkins": "2.440-lab"}, body


def dangling_cname() -> tuple[int, dict[str, str], str]:
    # subdomain-takeover: http_body_matches "(?i)(...the specified bucket
    # does not exist...)" — the real S3 NoSuchBucket error shape.
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<Error><Code>NoSuchBucket</Code>"
        "<Message>The specified bucket does not exist</Message>"
        "<BucketName>acmecorp-old-cdn-assets</BucketName>"
        "</Error>\n"
        "<!-- kiyoo-range decoy: this bucket was never re-registered by "
        "anyone, and never will be. See /_lab/notice. -->"
    )
    return 404, {}, body


def legacy_banner() -> tuple[int, dict[str, str], str]:
    # known-exploited-cve: no passive body predicate exists for this
    # category (evidence_required: nuclei_result, gated on cve_in_kev) —
    # this banner is what a real nuclei CVE template would fingerprint if
    # you ran one against it, not something kiyooo itself flags from a
    # passive scan of this lab. See the category page for why.
    body = "It works!"
    return 200, {"Server": "Apache/2.4.49 (Unix)"}, body


def zendesk_tenant() -> tuple[int, dict[str, str], str]:
    # shadow-saas-tenant: server header matches "(?i)(zendesk|...)" or
    # body matches "(?i)(powered by zendesk|...)".
    body = (
        "<h1>acmecorp Support</h1>"
        "<p>Powered by Zendesk.</p>"
        "<p>kiyoo-range decoy — a real instance of this pattern is a support "
        "team's helpdesk, spun up outside procurement. See /_lab/notice.</p>"
    )
    return 200, {"Server": "Zendesk"}, body


DECOYS = {
    "jenkins": jenkins,
    "dangling-cname": dangling_cname,
    "legacy-banner": legacy_banner,
    "zendesk-tenant": zendesk_tenant,
}
