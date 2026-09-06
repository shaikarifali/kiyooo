from pathlib import Path

import pytest

FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "org-context"


@pytest.fixture
def valid_org_context_root() -> Path:
    return FIXTURES_ROOT / "valid"


@pytest.fixture
def malformed_org_context_root() -> Path:
    return FIXTURES_ROOT / "malformed"
