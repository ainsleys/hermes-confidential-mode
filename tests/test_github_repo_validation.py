"""Regression tests for GitHub repository URL validation (issue #48)."""

import pytest

from confidential_mode.review import github_repo


@pytest.mark.parametrize("url", [
    "https://github.com/./.",
    "https://github.com/a/.",
    "https://github.com/./repo",
    "https://github.com/.hidden/repo",
    "https://github.com/owner/.hidden",
    "https://github.com/../repo",
    "https://github.com/owner/..",
])
def test_rejects_dot_prefixed_repository_segments(url: str) -> None:
    assert github_repo(url) is None


@pytest.mark.parametrize("url, expected", [
    ("https://github.com/owner/repo", "owner/repo"),
    ("https://github.com/owner/repo.git", "owner/repo"),
    ("https://github.com/owner/repo/", "owner/repo"),
    ("https://github.com/my-org/my.repo", "my-org/my.repo"),
])
def test_accepts_valid_repository_urls(url: str, expected: str) -> None:
    assert github_repo(url) == expected
