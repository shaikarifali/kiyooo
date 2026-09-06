"""Prompt file loading (the design doc: "versioned prompt files, not string literals
in code"). The prompt version is stored on every `Verdict` row so a prompt
change can be A/B tested and rolled back like a model change (invariant #8).
"""

from __future__ import annotations

from pathlib import Path

ADJUDICATE_PROMPT_VERSION = "v3"

_PROMPTS_DIR = Path(__file__).parent


def load_adjudicate_prompt(*, org_name: str) -> str:
    template = (_PROMPTS_DIR / "adjudicate.v3.md").read_text(encoding="utf-8")
    return template.replace("{{org_name}}", org_name)
