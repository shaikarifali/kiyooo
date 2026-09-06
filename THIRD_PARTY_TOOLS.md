# Third-party tools

kiyooo is a correlation/triage layer over other people's open-source
scanners, not a replacement for them (the design doc §0, §36: "don't build
another scanner"). Every wrapped tool is invoked as an external
subprocess/API call and its output parsed into our own schema — none of
their source is vendored, linked, or redistributed.

Tool choice is deliberate: most community adoption (stars, active
maintenance) *and* a license that's actually free to run and use the output
of, not a paid-tier trap. Re-verify both before adding anything not listed
here — free-and-popular today is not a permanent guarantee. See the design doc
§7 Stages 1, 1b, and 13–17 for how each one is wrapped.

| Tool | Homepage | License | Stars (verified Sept 2026) | Wrapped by | Status |
|---|---|---|---|---|---|
| subfinder | https://github.com/projectdiscovery/subfinder | MIT | ~13k | Stage 1 | shipped |
| dnsx | https://github.com/projectdiscovery/dnsx | MIT | ~2.8k | Stage 1 | shipped |
| httpx | https://github.com/projectdiscovery/httpx | MIT | ~3k | Stage 1 | shipped |
| naabu | https://github.com/projectdiscovery/naabu | MIT | ~3k | Stage 1 | shipped |
| katana | https://github.com/projectdiscovery/katana | MIT | ~4k | Stage 1 | shipped |
| nuclei | https://github.com/projectdiscovery/nuclei | MIT | ~22k | Stage 1 | shipped |
| tlsx | https://github.com/projectdiscovery/tlsx | MIT | — | Stage 1 | shipped |
| amass | https://github.com/owasp-amass/amass | Apache-2.0 | ~11k | Stage 1 (passive) | shipped |
| **Prowler** | https://github.com/prowler-cloud/prowler | Apache-2.0 | ~14k | Stage 13 (cloud posture) | **shipped** |
| **Trivy** | https://github.com/aquasecurity/trivy | Apache-2.0 | ~36.5k | Stage 14 (container image CVEs + Kubernetes misconfig) | **shipped** |
| Syft | https://github.com/anchore/syft | Apache-2.0 | — | Stage 14/15 (SBOM) | planned — Trivy's own CVE detection covers Stage 14's MVP need without it |
| Kubescape | https://github.com/kubescape/kubescape | Apache-2.0 | ~11k (CNCF incubating) | Stage 14 (deeper NSA/CIS/MITRE k8s compliance frameworks) | planned — Trivy's built-in k8s misconfig checks cover Stage 14's MVP category pack without it |
| **TruffleHog (OSS engine)** | https://github.com/trufflesecurity/trufflehog | AGPL-3.0 (subprocess-only; does not affect kiyooo's own license) | ~25.7k | Stage 15 (verified live-secret scanning in repos) | **shipped** |
| Semgrep Community Edition | https://github.com/semgrep/semgrep | LGPL-2.1 (CE rules only — the ~2,800 open rules, never the paid Pro ruleset) | — | Stage 15 (SAST) | planned — deferred to keep this stage's scope tight; secret scanning is the higher-signal supply-chain finding and ships first |
| **apktool** | https://github.com/iBotPeaches/Apktool | Apache-2.0 | — | Stage 16 (mobile manifest decode + resource/smali tree for secret scanning) | **shipped** |
| jadx | https://github.com/skylot/jadx | Apache-2.0 | ~49.6k | Stage 16 (human-readable Java decompilation) | planned — deferred, apktool's smali/resource output already covers what the current secret/endpoint/Firebase-URL grep needs; jadx would improve evidence readability, not detection coverage |

Optional, non-core enrichment adapters (Shodan, Censys) are commercial APIs
kept strictly optional per the design doc's non-goals — the core product works
without them.
