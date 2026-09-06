from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from kiyooo.db.models import AssetType
from kiyooo.enrich.ownership.sources import git_blame_owner
from tests.enrich.factories import make_asset


def _run(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "infra"
    repo.mkdir()
    _run("init", "-q", cwd=repo)
    _run("config", "user.email", "alice@example.com", cwd=repo)
    _run("config", "user.name", "Alice", cwd=repo)
    (repo / "main.tf").write_text('resource "aws_instance" "web" {}\n')
    _run("add", "main.tf", cwd=repo)
    _run("commit", "-q", "-m", "add web instance", cwd=repo)
    return repo


@pytest.mark.asyncio
async def test_git_blame_owner_resolves_via_email_map(git_repo: Path) -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    candidate = await git_blame_owner(
        asset,
        repo_path=git_repo,
        manifest_file="main.tf",
        email_to_owner={"alice@example.com": "infra-team"},
    )
    assert candidate is not None
    assert candidate.owner_ref == "infra-team"
    assert candidate.confidence == 0.75


@pytest.mark.asyncio
async def test_git_blame_owner_unknown_committer_returns_none(git_repo: Path) -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    candidate = await git_blame_owner(
        asset,
        repo_path=git_repo,
        manifest_file="main.tf",
        email_to_owner={"someone-else@example.com": "other-team"},
    )
    assert candidate is None


@pytest.mark.asyncio
async def test_git_blame_owner_missing_manifest_returns_none(git_repo: Path) -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    candidate = await git_blame_owner(
        asset,
        repo_path=git_repo,
        manifest_file="nonexistent.tf",
        email_to_owner={"alice@example.com": "infra-team"},
    )
    assert candidate is None


@pytest.mark.asyncio
async def test_git_blame_owner_non_git_directory_returns_none(tmp_path: Path) -> None:
    asset = make_asset(AssetType.IP, "93.184.216.34")
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()
    candidate = await git_blame_owner(
        asset,
        repo_path=not_a_repo,
        manifest_file="main.tf",
        email_to_owner={"alice@example.com": "infra-team"},
    )
    assert candidate is None
