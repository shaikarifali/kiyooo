"""Single-template nuclei verification — exactly one
allowlisted, non-intrusive template against one target. `-etags
dos,intrusive,fuzz` is passed unconditionally, the same non-negotiable
invariant #1 enforcement as Stage 1's `NucleiAdapter`, belt-and-suspenders
alongside `verify/safety.py`'s template-id allowlist (a template can't
reach this function at all unless it's already on that allowlist).
"""

from __future__ import annotations

import json
import shutil
from typing import TYPE_CHECKING

from kiyooo.recon.adapters._subprocess import run_subprocess
from kiyooo.verify.safety import DENIED_NUCLEI_TAGS

if TYPE_CHECKING:
    from kiyooo.verify.safety import ValidatedRequest


class NucleiUnavailable(Exception):
    """The `nuclei` binary isn't on PATH — a verification-time environment
    problem, not a rejected request.
    """


def parse_output(raw: bytes) -> dict[str, object]:
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        return {
            "matched": True,
            "template_id": record.get("template-id"),
            "info": record.get("info", {}),
            "matched_at": record.get("matched-at"),
        }
    return {"matched": False}


def build_argv(binary: str, target: str, template_id: str) -> list[str]:
    return [
        binary,
        "-silent",
        "-jsonl",
        "-target",
        target,
        "-id",
        template_id,
        "-etags",
        ",".join(sorted(DENIED_NUCLEI_TAGS)),
    ]


async def run(validated: ValidatedRequest, *, binary: str = "nuclei") -> dict[str, object]:
    if shutil.which(binary) is None:
        raise NucleiUnavailable(f"{binary} not found on PATH")
    template_id = str(validated.args["template_id"])
    argv = build_argv(binary, validated.target, template_id)
    _returncode, stdout, _stderr = await run_subprocess(argv)
    return parse_output(stdout)
