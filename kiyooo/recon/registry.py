"""Adapter registry — the one place that knows every `ToolAdapter` kiyooo ships.

Adapters register themselves via the `@register` decorator at import time.
Nothing imports `kiyooo.recon.adapters` implicitly — `orchestrator.py` (or
whatever needs the full set) does `import kiyooo.recon.adapters` once to
trigger every adapter module's registration side effect, so importing
`registry` alone never silently pulls in subprocess/HTTP-capable code.

Stage -> profile mapping is intentionally a strict superset chain: passive
targets only DISCOVER/RESOLVE (nothing is_active), standard adds PROBE,
deep adds PORTSCAN/CRAWL/SCAN. Going up a profile tier only ever adds contact
with the target, never changes the kind of contact passive already made.
"""

from __future__ import annotations

from kiyooo.recon.base import ReconStage, ScanProfile, ToolAdapter

_REGISTRY: dict[str, type[ToolAdapter]] = {}

_PROFILE_STAGES: dict[ScanProfile, frozenset[ReconStage]] = {
    ScanProfile.PASSIVE: frozenset({ReconStage.DISCOVER, ReconStage.RESOLVE}),
    ScanProfile.STANDARD: frozenset({ReconStage.DISCOVER, ReconStage.RESOLVE, ReconStage.PROBE}),
    ScanProfile.DEEP: frozenset(
        {
            ReconStage.DISCOVER,
            ReconStage.RESOLVE,
            ReconStage.PORTSCAN,
            ReconStage.PROBE,
            ReconStage.CRAWL,
            ReconStage.SCAN,
        }
    ),
}


def register(adapter_cls: type[ToolAdapter]) -> type[ToolAdapter]:
    _REGISTRY[adapter_cls.name] = adapter_cls
    return adapter_cls


def get(name: str) -> type[ToolAdapter]:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = sorted(_REGISTRY)
        raise KeyError(f"no recon adapter registered as {name!r}; known: {known}") from None


def all_adapters() -> list[type[ToolAdapter]]:
    return list(_REGISTRY.values())


def adapters_for_profile(profile: ScanProfile) -> list[type[ToolAdapter]]:
    stages = _PROFILE_STAGES[profile]
    return [cls for cls in _REGISTRY.values() if cls.stage in stages]


def stages_for_profile(profile: ScanProfile) -> frozenset[ReconStage]:
    return _PROFILE_STAGES[profile]
