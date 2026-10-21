"""Load YAML strictly for untrusted frontmatter.

PyYAML's SafeLoader already refuses unknown tags and non-scalar anchor targets are just
ordinary (safe) aliasing, but it silently accepts duplicate mapping keys
(last one wins). This loader raises on duplicates instead.
"""

from __future__ import annotations

from typing import Any

import yaml
import yaml.resolver


class DuplicateKeyError(yaml.YAMLError, ValueError):
    """Raised when a YAML mapping repeats a key."""


class _StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, *, deep: bool = False) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            msg = f"duplicate key {key!r}"
            raise DuplicateKeyError(msg)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)

# YAML merge keys (`<<: *anchor`) are intentionally unsupported: honoring them
# would require deciding how a merged-in key interacts with this loader's
# duplicate-key rejection (does a key from the merge collide with a literal
# key, and which "wins"?), and skill frontmatter has no legitimate use for
# anchors/merges in the first place. Frontmatter using `<<` fails to parse
# here, which callers already treat as a FAIL finding rather than a crash.


# YAML documents are dynamically typed, and every caller validates the shape it receives.
def safe_load_strict(text: str) -> Any:  # noqa: ANN401
    """Parse YAML with PyYAML's safe tag set, rejecting duplicate keys.

    Raises yaml.YAMLError (including DuplicateKeyError) on anything that
    does not parse cleanly.
    """
    return yaml.load(text, Loader=_StrictSafeLoader)  # noqa: S506
