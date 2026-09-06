"""Verdict schema — the LLM's structured output. Enforced
with Pydantic + provider-native structured output: `verdict_json_schema()`
is what `llm/provider.py`'s `complete()` gets as its `schema` argument
(Anthropic's tool `input_schema`, Ollama's `format`), and `VerdictSchema`
parses/validates whatever comes back.

Every nested model forbids extra fields — besides matching what the prompt
asks for, this is what makes the generated JSON Schema carry
`"additionalProperties": false`, which providers with strict schema modes
rely on.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

VerdictValue = Literal["true_positive", "false_positive", "not_exploitable", "needs_human"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Effort = Literal["trivial", "small", "medium", "large"]


class Exploitability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    internet_reachable: bool
    authentication_required: bool
    preconditions: list[str] = Field(default_factory=list)
    realistic_attack_path: str


class CompensatingControlConsidered(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control: str
    mitigates_this: bool
    why: str


class Remediation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    steps: list[str] = Field(default_factory=list)
    verification: str
    estimated_effort: Effort


class OwnerHint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team: str | None = None
    user: str | None = None
    why: str


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    args: dict[str, object] = Field(default_factory=dict)
    why: str


class VerdictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: VerdictValue
    confidence: float = Field(ge=0.0, le=1.0)
    adjusted_severity: Severity
    reasoning: str = Field(min_length=1)
    citations: list[str] = Field(default_factory=list)
    exploitability: Exploitability
    compensating_controls_considered: list[CompensatingControlConsidered] = Field(
        default_factory=list
    )
    business_impact_hypothesis: str
    remediation: Remediation
    owner_hint: OwnerHint | None = None
    requires_verification: list[VerificationRequest] = Field(default_factory=list)


def verdict_json_schema() -> dict[str, object]:
    return VerdictSchema.model_json_schema()
