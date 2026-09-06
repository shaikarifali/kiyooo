"""The ticket contract: a ticket body renders from a
Jinja2 template, and code — not template authors — refuses to file one
missing any of six required blocks. 42% of surveyed practitioners report
tickets lacking remediation or asset context; this is the
structural fix.

Required blocks, matched as markdown headers (any `#` level, case-insensitive):
  what is exposed
  why we believe this is real
  why it matters here
  what to do
  how to verify the fix
  who to push back to
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

REQUIRED_BLOCKS: tuple[str, ...] = (
    "what is exposed",
    "why we believe this is real",
    "why it matters here",
    "what to do",
    "how to verify the fix",
    "who to push back to",
)

_DEFAULT_TEMPLATE_NAME = "default_ticket.md.j2"
_TEMPLATES_DIR = Path(__file__).parent / "templates"

_HEADER_RE = re.compile(r"^#{1,6}\s*(.+?)\s*$", re.MULTILINE)


class TicketContractViolation(Exception):
    """Raised when a rendered ticket body is missing a required block —
    `route/pipeline.py` catches this and refuses to file the ticket.
    """

    def __init__(self, missing: list[str]) -> None:
        self.missing = missing
        super().__init__(f"ticket body missing required block(s): {missing}")


@dataclass(frozen=True, slots=True)
class RenderedTicket:
    subject: str
    body: str


def _sections(body: str) -> dict[str, str]:
    parts = _HEADER_RE.split(body)
    sections: dict[str, str] = {}
    for i in range(1, len(parts), 2):
        header = parts[i].lower().strip()
        content = parts[i + 1] if i + 1 < len(parts) else ""
        sections[header] = content
    return sections


def lint_ticket_body(body: str) -> list[str]:
    """Returns the required block names that are missing or empty — an
    empty list means the body satisfies the contract.
    """
    sections = _sections(body)
    return [block for block in REQUIRED_BLOCKS if not sections.get(block, "").strip()]


def render_ticket_body(context: dict[str, object], *, template_path: Path | None = None) -> str:
    if template_path is not None:
        env = Environment(
            loader=FileSystemLoader(str(template_path.parent)), undefined=StrictUndefined
        )
        template = env.get_template(template_path.name)
    else:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), undefined=StrictUndefined)
        template = env.get_template(_DEFAULT_TEMPLATE_NAME)
    return template.render(**context)


def build_ticket_subject(*, severity: str, category_name: str, asset_value: str) -> str:
    return f"[{severity.upper()}] {category_name} — {asset_value}"


def dummy_context(*, category_name: str = "Example category") -> dict[str, object]:
    """Synthetic bundle for `kiyooo categories lint`'s template linter — every
    key the default template (and any well-formed custom one) reads, filled
    with placeholder values so rendering can't fail on a missing variable.
    """
    return {
        "category_name": category_name,
        "severity": "high",
        "asset_value": "example.corp.internal",
        "asset_type": "http_service",
        "finding_title": "Example finding",
        "finding_description": "Example finding description.",
        "cluster_assets": ["example.corp.internal"],
        "reasoning": "Example reasoning.",
        "citations": ["ev_example_1"],
        "business_impact_hypothesis": "Example business impact.",
        "exploitability": {
            "internet_reachable": True,
            "authentication_required": False,
            "realistic_attack_path": "example path",
        },
        "remediation": {
            "summary": "Example remediation summary.",
            "steps": ["Example step."],
            "verification": "Example verification.",
            "estimated_effort": "small",
        },
        "compensating_controls": [],
        "ownership_confidence": 0.9,
        "ownership_source": "codeowners",
        "ownership_note": None,
        "sla_due_at": None,
    }


def render_ticket(
    context: dict[str, object],
    *,
    subject: str,
    template_path: Path | None = None,
) -> RenderedTicket:
    """Renders and lints in one step — raises `TicketContractViolation`
    rather than returning a body that can't be filed, so callers can't
    forget to check.
    """
    body = render_ticket_body(context, template_path=template_path)
    missing = lint_ticket_body(body)
    if missing:
        raise TicketContractViolation(missing)
    return RenderedTicket(subject=subject, body=body)
