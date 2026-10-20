from acb.controls.acb_gen_004 import AUDITS
from tests.test_controls._shared import check_pass_and_fail


def test_acb_gen_004_fixtures():
    check_pass_and_fail("ACB-GEN-004", AUDITS)


def test_typographic_ellipsis_in_a_code_block_is_not_a_confusable(tmp_path):
    from tests._harness import context_for

    (tmp_path / "AGENTS.md").write_text("```sh\nx=$(…)\ncurl … | tee out\n```\n")
    assert AUDITS["confusable-identifiers"](context_for(tmp_path)) == []
