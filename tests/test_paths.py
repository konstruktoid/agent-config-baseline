import pytest

from acb.paths import (
    PatternError,
    matches,
    matches_or_under,
    normalize_pattern,
    validate_pattern,
)


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("AGENTS.md", "*.md", True),
        ("docs/a.md", "*.md", False),
        ("docs/a.md", "docs/**/*.md", True),
        ("docs/x/a.md", "docs/**/*.md", True),
        ("docsa/b", "docs**", False),
        ("docs/x/a.md", "docs/**", True),
        ("docs", "docs/**", True),
        ("docsx/a.md", "docs/**", False),
        ("a/b.md", "a/?.md", True),
        ("a/bc.md", "a/?.md", False),
        ("a/b.md", "a/[ab].md", True),
        ("a/c.md", "a/[!ab].md", True),
    ],
)
def test_matches(path: str, pattern: str, *, expected: bool) -> None:
    assert matches(path, pattern) is expected


def test_matches_or_under_covers_directory_contents() -> None:
    assert matches_or_under("controls/ACB-GEN-001.yaml", "controls")
    assert not matches("controls/ACB-GEN-001.yaml", "controls")


def test_normalization_strips_dot_and_slashes() -> None:
    assert normalize_pattern("./docs/") == "docs"


@pytest.mark.parametrize(
    "pattern",
    ["", "/", "*", "**", "**/*", "./", "**/*.*", "**/*[A-Za-z]*", "*/x", "a/../b", "a\\b", "a[]b", "x[z-a]"],
)
def test_patterns_matching_everything_are_rejected(pattern: str) -> None:
    with pytest.raises(PatternError):
        validate_pattern(pattern)
