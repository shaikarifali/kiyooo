"""Verification request validation (Stage 6, §4.5.5's defense-
in-depth layer: "the verification executor validates every argument
against a typed schema and ScopeGuard, so a model persuaded by injected
text to probe attacker.example.com is stopped at the executor rather than
the prompt").

Every `VerificationRequest` the model emits (`triage/schema.py`'s
`requires_verification[]`) passes through here before it ever reaches
`ScopeGuard` or a tool. This is the typed-schema half of that defense —
the scope check itself lives in `verify/executor.py`, deliberately kept
separate so a request can be rejected here without ever constructing a
target string ScopeGuard would need to evaluate.

Stage 11b's AI attack surface module names a hard constraint
that lives here by omission, not by an explicit deny-list entry: an MCP
server's `initialize`/`tools/list` handshake is read-only reconnaissance
and would be a legitimate seventh tool if one existed here — `tools/call`
never would be, unconditionally, because invoking an unknown tool on an
unauthenticated server is indistinguishable from exploitation and may
modify systems. `ALLOWED_TOOLS` below is the enforcement: adding an MCP
tool-invocation capability means adding a name to this frozenset, and
that is a scope-enforcement decision for a human to make explicitly, not
something a future contributor should do as an incidental part of
shipping Stage 11b's other detection work. Stage 11b's own module
(`detect/ai_fingerprints.py`) fingerprints MCP servers passively, off
evidence Stage 1 already collected — it never calls this executor at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiyooo.triage.schema import VerificationRequest

# The 6 tools Stage 6 names, and nothing else — the model cannot
# name a tool that isn't one of these regardless of what it asks for.
ALLOWED_TOOLS = frozenset(
    {"http_probe", "tcp_banner", "tls_handshake", "dns_resolve", "cert_chain", "nuclei_single"}
)

# Invariant #1: never these HTTP methods, for any tool, ever.
_DENIED_HTTP_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})
_ALLOWED_HTTP_METHODS = frozenset({"GET", "HEAD"})

# nuclei_single's own allowlist — one specific, reviewed template id per
# entry, not a tag category, so the model can't reach any nuclei template
# indirectly via a tag it happens to carry. Surfacing this as org-context
# config is future work, not this stage — same call Stage 1's
# NucleiAdapter made for its own tag allowlist.
ALLOWED_NUCLEI_TEMPLATE_IDS = frozenset(
    {
        "tech-detect",
        "ssl-issuer",
        "waf-detect",
        "tls-version",
        "http-missing-security-headers",
    }
)

# Belt-and-suspenders: even an allowlisted template id runs with these tags
# excluded, same as Stage 1's NucleiAdapter — a template can't be added to
# the allowlist above *and* carry one of these tags and still fire.
DENIED_NUCLEI_TAGS = frozenset({"dos", "intrusive", "fuzz"})


class VerificationRejected(Exception):
    """A `requires_verification` entry failed safety validation — never
    reaches `ScopeGuard` or a tool. The reason is returned to the agent so
    it can tell the model why, per this stage's DoD.
    """


@dataclass(frozen=True, slots=True)
class ValidatedRequest:
    tool: str
    target: str
    args: dict[str, object]


def _require_str(args: dict[str, object], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationRejected(f"{key!r} must be a non-empty string")
    return value


def _require_port(args: dict[str, object], *, default: int | None = None) -> int:
    value = args.get("port", default)
    if isinstance(value, bool) or not isinstance(value, int) or not (0 < value <= 65535):
        raise VerificationRejected("'port' must be an integer between 1 and 65535")
    return value


def _validate_http_probe(args: dict[str, object]) -> ValidatedRequest:
    host = _require_str(args, "host")
    method = str(args.get("method", "GET")).upper()
    if method in _DENIED_HTTP_METHODS:
        raise VerificationRejected(f"http method {method!r} is never permitted for verification")
    if method not in _ALLOWED_HTTP_METHODS:
        raise VerificationRejected(f"http method {method!r} is not GET/HEAD")
    path = args.get("path", "/")
    if not isinstance(path, str) or not path.startswith("/"):
        raise VerificationRejected("'path' must be a string starting with '/'")
    return ValidatedRequest(tool="http_probe", target=host, args={"method": method, "path": path})


def _validate_tcp_banner(args: dict[str, object]) -> ValidatedRequest:
    host = _require_str(args, "host")
    port = _require_port(args)
    return ValidatedRequest(tool="tcp_banner", target=f"{host}:{port}", args={"port": port})


def _validate_tls_handshake(args: dict[str, object]) -> ValidatedRequest:
    host = _require_str(args, "host")
    port = _require_port(args, default=443)
    return ValidatedRequest(tool="tls_handshake", target=f"{host}:{port}", args={"port": port})


def _validate_dns_resolve(args: dict[str, object]) -> ValidatedRequest:
    hostname = _require_str(args, "hostname")
    record_type = str(args.get("record_type", "A")).upper()
    if record_type not in {"A", "AAAA"}:
        raise VerificationRejected("'record_type' must be A or AAAA")
    return ValidatedRequest(tool="dns_resolve", target=hostname, args={"record_type": record_type})


def _validate_cert_chain(args: dict[str, object]) -> ValidatedRequest:
    host = _require_str(args, "host")
    port = _require_port(args, default=443)
    return ValidatedRequest(tool="cert_chain", target=f"{host}:{port}", args={"port": port})


def _validate_nuclei_single(args: dict[str, object]) -> ValidatedRequest:
    host = _require_str(args, "host")
    template_id = _require_str(args, "template_id")
    if template_id not in ALLOWED_NUCLEI_TEMPLATE_IDS:
        raise VerificationRejected(
            f"nuclei template {template_id!r} is not on the verification allowlist: "
            f"{sorted(ALLOWED_NUCLEI_TEMPLATE_IDS)}"
        )
    return ValidatedRequest(tool="nuclei_single", target=host, args={"template_id": template_id})


_VALIDATORS = {
    "http_probe": _validate_http_probe,
    "tcp_banner": _validate_tcp_banner,
    "tls_handshake": _validate_tls_handshake,
    "dns_resolve": _validate_dns_resolve,
    "cert_chain": _validate_cert_chain,
    "nuclei_single": _validate_nuclei_single,
}


def validate_request(request: VerificationRequest) -> ValidatedRequest:
    if request.tool not in ALLOWED_TOOLS:
        raise VerificationRejected(
            f"tool {request.tool!r} is not one of the allowed verification tools: "
            f"{sorted(ALLOWED_TOOLS)}"
        )
    return _VALIDATORS[request.tool](request.args)
