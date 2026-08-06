"""
Unit tests for the Tanium (Signal / Intel-doc) format adapter.

The adapter mirrors the contract documented in
`app/features/rule/rule_format/abstract_rule_type/rule_type_abstract.py`
and is structured to match the existing `atr_format`/`kql_format` tests for
consistency.

Tanium rules can be authored two ways, both accepted by the adapter:
  - JSON objects: metadata fields (name, description, platform, category,
    mitre_technique_ids, ...) plus the boolean detection expression as a
    string field.
  - Raw text: just the boolean expression, optionally preceded by a
    `// Key: Value` metadata header (same convention as kql_format.py).
Content is treated as JSON if it parses as one; otherwise as raw text.
"""
from __future__ import annotations

import json
from textwrap import dedent

import pytest

from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import ValidationResult
from app.features.rule.rule_format.available_format.tanium_format import TaniumRule


# -------------------------------------------------------------------------
#                           Sample rule fixtures
# -------------------------------------------------------------------------

_VALID_TANIUM_RULE = json.dumps(
    {
        "id": "TAN-0001",
        "name": "Certutil decode download",
        "description": "Detects certutil.exe being used to decode/download payloads",
        "author": "Contoso SOC",
        "license": "MIT",
        "severity": "high",
        "platform": ["Windows"],
        "category": "Defense Evasion",
        "mitre_technique_ids": ["T1140"],
        "expression": (
            "process.path ends with 'certutil.exe' AND "
            "(process.command_line contains '-decode' OR process.command_line contains '-urlcache')"
        ),
    },
    indent=2,
)

_VALID_TANIUM_RULE_WITH_CVE = json.dumps(
    {
        "name": "SmartScreen bypass exploitation",
        "description": "Detects exploitation attempts for CVE-2024-21412 in SmartScreen bypass campaigns",
        "expression": "process.command_line contains '.url'",
    }
)

_VALID_TANIUM_RULE_MINIMAL = json.dumps(
    {
        "name": "Bare minimal signal",
        "expression": "process.path is 'evil.exe'",
    }
)

_NOT_JSON_AND_NOT_A_VALID_EXPRESSION = "not json at all {"

_INVALID_NOT_OBJECT = json.dumps(["just", "a", "list"])

# ---- Raw-text (no JSON wrapper) fixtures ---------------------------------

_VALID_RAW_TANIUM_RULE = dedent(
    """\
    // Name: Certutil decode download
    // Description: Detects certutil.exe being used to decode/download payloads
    // Author: Contoso SOC
    // License: MIT
    // Severity: Medium
    // Tags: initial-access, defense-evasion
    process.path ends with 'certutil.exe' AND (process.command_line contains '-decode' OR process.command_line contains '-urlcache')
    """
)

_VALID_RAW_TANIUM_RULE_WITH_CVE = dedent(
    """\
    // Name: SmartScreen bypass exploitation
    // Description: Detects exploitation attempts for CVE-2024-21412 in SmartScreen bypass campaigns
    process.command_line contains '.url'
    """
)

_VALID_RAW_NO_HEADER = "process.path is 'evil.exe'"

_INVALID_RAW_EMPTY = ""

_INVALID_RAW_COMMENT_ONLY = dedent(
    """\
    // Name: Nothing here
    // just comments, no expression body
    """
)

_INVALID_RAW_NO_OPERATOR = "process.path certutil.exe"

_INVALID_RAW_UNBALANCED = "process.path contains ('evil.exe'"

_INVALID_MISSING_NAME = json.dumps({"expression": "process.path is 'evil.exe'"})

_INVALID_MISSING_EXPRESSION = json.dumps({"name": "No expression here"})

_INVALID_UNBALANCED_EXPRESSION = json.dumps(
    {"name": "Bad expression", "expression": "process.path contains ('evil.exe'"}
)

_INVALID_NO_OPERATOR = json.dumps(
    {"name": "No operator", "expression": "process.path certutil.exe"}
)

_INVALID_BAD_TECHNIQUE_ID = json.dumps(
    {
        "name": "Bad technique id",
        "expression": "process.path is 'evil.exe'",
        "mitre_technique_ids": ["NOT-A-TECHNIQUE"],
    }
)

_UNKNOWN_PLATFORM = json.dumps(
    {
        "name": "Unknown platform",
        "expression": "process.path is 'evil.exe'",
        "platform": ["BeOS"],
    }
)

_BULK_FEED_EXPORT = json.dumps(
    {
        "signals": [
            json.loads(_VALID_TANIUM_RULE_MINIMAL),
            json.loads(_VALID_TANIUM_RULE_WITH_CVE),
        ]
    }
)


# -------------------------------------------------------------------------
#                                Tests
# -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tanium() -> TaniumRule:
    return TaniumRule()


def test_format_identifier(tanium: TaniumRule) -> None:
    assert tanium.format == "tanium"
    assert tanium.get_class() == "TaniumRule"


# ---- validate() ------------------------------------------------------------


def test_validate_accepts_canonical_tanium_rule(tanium: TaniumRule) -> None:
    result = tanium.validate(_VALID_TANIUM_RULE)
    assert isinstance(result, ValidationResult)
    assert result.ok is True, result.errors
    assert result.errors == []
    assert result.normalized_content == _VALID_TANIUM_RULE


def test_validate_accepts_minimal_rule(tanium: TaniumRule) -> None:
    result = tanium.validate(_VALID_TANIUM_RULE_MINIMAL)
    assert result.ok is True, result.errors


def test_validate_falls_back_to_raw_and_rejects_if_not_a_valid_expression(tanium: TaniumRule) -> None:
    # Content that fails JSON parsing is treated as raw text, not a JSON error.
    result = tanium.validate(_NOT_JSON_AND_NOT_A_VALID_EXPRESSION)
    assert result.ok is False
    assert any("recognized comparison operator" in e for e in result.errors)


def test_validate_rejects_non_object_json(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_NOT_OBJECT)
    assert result.ok is False
    assert any("single JSON object" in e for e in result.errors)


def test_validate_rejects_missing_name(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_MISSING_NAME)
    assert result.ok is False
    assert any("name" in e for e in result.errors)


def test_validate_rejects_missing_expression(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_MISSING_EXPRESSION)
    assert result.ok is False
    assert any("expression" in e for e in result.errors)


def test_validate_rejects_unbalanced_expression(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_UNBALANCED_EXPRESSION)
    assert result.ok is False
    assert any("Unclosed" in e for e in result.errors)


def test_validate_rejects_expression_without_operator(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_NO_OPERATOR)
    assert result.ok is False
    assert any("recognized comparison operator" in e for e in result.errors)


def test_validate_rejects_bad_mitre_technique_id(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_BAD_TECHNIQUE_ID)
    assert result.ok is False
    assert any("MITRE ATT&CK technique id" in e for e in result.errors)


def test_validate_warns_on_unknown_platform(tanium: TaniumRule) -> None:
    result = tanium.validate(_UNKNOWN_PLATFORM)
    assert result.ok is True
    assert any("BeOS" in w for w in result.warnings)


# ---- parse_metadata() ----------------------------------------------------


def test_parse_metadata_reads_fields(tanium: TaniumRule) -> None:
    validation_result = tanium.validate(_VALID_TANIUM_RULE)
    meta = tanium.parse_metadata(_VALID_TANIUM_RULE, {}, validation_result)
    assert meta["format"] == "tanium"
    assert meta["title"] == "Certutil decode download"
    assert meta["description"] == "Detects certutil.exe being used to decode/download payloads"
    assert meta["author"] == "Contoso SOC"
    assert meta["license"] == "MIT"
    assert meta["severity"] == "high"
    assert meta["original_uuid"] == "TAN-0001"
    assert "category:Defense Evasion" in meta["tags"]
    assert "platform:Windows" in meta["tags"]
    assert "attack:T1140" in meta["tags"]
    assert meta["to_string"] == _VALID_TANIUM_RULE


def test_parse_metadata_detects_cve_in_description(tanium: TaniumRule) -> None:
    validation_result = tanium.validate(_VALID_TANIUM_RULE_WITH_CVE)
    meta = tanium.parse_metadata(_VALID_TANIUM_RULE_WITH_CVE, {}, validation_result)
    cves = json.loads(meta["cve_id"])
    assert "CVE-2024-21412" in cves


def test_parse_metadata_uses_info_defaults(tanium: TaniumRule) -> None:
    validation_result = tanium.validate(_VALID_TANIUM_RULE_MINIMAL)
    meta = tanium.parse_metadata(
        _VALID_TANIUM_RULE_MINIMAL,
        {"license": "Apache-2.0", "author": "Jane Doe", "repo_url": "https://example/repo"},
        validation_result,
    )
    assert meta["license"] == "Apache-2.0"
    assert meta["author"] == "Jane Doe"
    assert meta["source"] == "https://example/repo"
    assert meta["original_uuid"] == "Unknown"


def test_parse_metadata_falls_back_to_raw_when_not_json(tanium: TaniumRule) -> None:
    # Non-JSON content still gets metadata via the raw-text header parser,
    # not the JSON "Metadata Error" fallback shape.
    meta = tanium.parse_metadata(
        _NOT_JSON_AND_NOT_A_VALID_EXPRESSION, {"repo_url": "x"}, ValidationResult(ok=False, errors=["x"])
    )
    assert meta["format"] == "tanium"
    assert meta["title"] == "Untitled Tanium Signal"
    assert meta["cve_id"] == "[]"
    assert meta["to_string"] == _NOT_JSON_AND_NOT_A_VALID_EXPRESSION


# ---- get_rule_files() ----------------------------------------------------


def test_get_rule_files_accepts_tanium_extensions(tanium: TaniumRule) -> None:
    assert tanium.get_rule_files("rules/foo.tanium") is True
    assert tanium.get_rule_files("rules/foo.tanium.json") is True


def test_get_rule_files_rejects_other_extensions(tanium: TaniumRule) -> None:
    assert tanium.get_rule_files("rules/foo.json") is False
    assert tanium.get_rule_files("rules/foo.yaml") is False


# ---- extract_rules_from_file() -------------------------------------------


def test_extract_rules_from_single_rule_file(tanium: TaniumRule, tmp_path) -> None:
    p = tmp_path / "rule.tanium"
    p.write_text(_VALID_TANIUM_RULE, encoding="utf-8")
    rules = tanium.extract_rules_from_file(str(p))
    assert len(rules) == 1
    # Single-rule files return raw content verbatim — no re-dump.
    assert rules[0] == _VALID_TANIUM_RULE


def test_extract_rules_from_bulk_signals_wrapper(tanium: TaniumRule, tmp_path) -> None:
    p = tmp_path / "feed.tanium.json"
    p.write_text(_BULK_FEED_EXPORT, encoding="utf-8")
    rules = tanium.extract_rules_from_file(str(p))
    assert len(rules) == 2
    names = {json.loads(r)["name"] for r in rules}
    assert names == {"Bare minimal signal", "SmartScreen bypass exploitation"}


def test_extract_rules_from_top_level_list(tanium: TaniumRule, tmp_path) -> None:
    p = tmp_path / "list.tanium"
    p.write_text(
        json.dumps([json.loads(_VALID_TANIUM_RULE_MINIMAL), {"name": "no expression here"}]),
        encoding="utf-8",
    )
    rules = tanium.extract_rules_from_file(str(p))
    assert len(rules) == 1
    assert json.loads(rules[0])["name"] == "Bare minimal signal"


def test_extract_rules_from_non_json_file_falls_back_to_raw(tanium: TaniumRule, tmp_path) -> None:
    p = tmp_path / "broken.tanium"
    p.write_text(_NOT_JSON_AND_NOT_A_VALID_EXPRESSION, encoding="utf-8")
    rules = tanium.extract_rules_from_file(str(p))
    assert rules == [_NOT_JSON_AND_NOT_A_VALID_EXPRESSION.strip()]


def test_extract_rules_from_missing_file_is_empty(tanium: TaniumRule, tmp_path) -> None:
    missing = tmp_path / "does-not-exist.tanium"
    rules = tanium.extract_rules_from_file(str(missing))
    assert rules == []


# =========================================================================
#                    Raw-text (no JSON wrapper) signals
# =========================================================================


# ---- validate() ------------------------------------------------------------


def test_validate_accepts_raw_rule_with_header(tanium: TaniumRule) -> None:
    result = tanium.validate(_VALID_RAW_TANIUM_RULE)
    assert isinstance(result, ValidationResult)
    assert result.ok is True, result.errors
    assert result.normalized_content == _VALID_RAW_TANIUM_RULE


def test_validate_accepts_raw_rule_without_header(tanium: TaniumRule) -> None:
    result = tanium.validate(_VALID_RAW_NO_HEADER)
    assert result.ok is True, result.errors


def test_validate_rejects_empty_raw_content(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_RAW_EMPTY)
    assert result.ok is False
    assert any("empty" in e.lower() for e in result.errors)


def test_validate_rejects_comment_only_raw_content(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_RAW_COMMENT_ONLY)
    assert result.ok is False
    assert any("comments" in e.lower() for e in result.errors)


def test_validate_rejects_raw_expression_without_operator(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_RAW_NO_OPERATOR)
    assert result.ok is False
    assert any("recognized comparison operator" in e for e in result.errors)


def test_validate_rejects_unbalanced_raw_expression(tanium: TaniumRule) -> None:
    result = tanium.validate(_INVALID_RAW_UNBALANCED)
    assert result.ok is False
    assert any("Unclosed" in e for e in result.errors)


# ---- parse_metadata() ----------------------------------------------------


def test_parse_metadata_reads_raw_header_fields(tanium: TaniumRule) -> None:
    validation_result = tanium.validate(_VALID_RAW_TANIUM_RULE)
    meta = tanium.parse_metadata(_VALID_RAW_TANIUM_RULE, {}, validation_result)
    assert meta["format"] == "tanium"
    assert meta["title"] == "Certutil decode download"
    assert meta["description"] == "Detects certutil.exe being used to decode/download payloads"
    assert meta["author"] == "Contoso SOC"
    assert meta["license"] == "MIT"
    assert meta["severity"] == "Medium"
    assert meta["tags"] == ["initial-access", "defense-evasion"]
    assert meta["to_string"] == _VALID_RAW_TANIUM_RULE


def test_parse_metadata_raw_falls_back_to_filename_title(tanium: TaniumRule) -> None:
    validation_result = tanium.validate(_VALID_RAW_NO_HEADER)
    meta = tanium.parse_metadata(
        _VALID_RAW_NO_HEADER, {"filepath": "evil-exe-detect.tanium"}, validation_result
    )
    assert meta["title"] == "Evil Exe Detect"
    assert meta["description"] == "No description provided"


def test_parse_metadata_raw_falls_back_to_default_title_without_filepath(tanium: TaniumRule) -> None:
    validation_result = tanium.validate(_VALID_RAW_NO_HEADER)
    meta = tanium.parse_metadata(_VALID_RAW_NO_HEADER, {}, validation_result)
    assert meta["title"] == "Untitled Tanium Signal"


def test_parse_metadata_raw_detects_cve_in_description(tanium: TaniumRule) -> None:
    validation_result = tanium.validate(_VALID_RAW_TANIUM_RULE_WITH_CVE)
    meta = tanium.parse_metadata(_VALID_RAW_TANIUM_RULE_WITH_CVE, {}, validation_result)
    cves = json.loads(meta["cve_id"])
    assert "CVE-2024-21412" in cves


def test_parse_metadata_raw_uses_info_defaults(tanium: TaniumRule) -> None:
    validation_result = tanium.validate(_VALID_RAW_NO_HEADER)
    meta = tanium.parse_metadata(
        _VALID_RAW_NO_HEADER,
        {"license": "Apache-2.0", "author": "Jane Doe", "repo_url": "https://example/repo"},
        validation_result,
    )
    assert meta["license"] == "Apache-2.0"
    assert meta["author"] == "Jane Doe"
    assert meta["source"] == "https://example/repo"


# ---- extract_rules_from_file() -------------------------------------------


def test_extract_rules_from_single_raw_rule_file(tanium: TaniumRule, tmp_path) -> None:
    p = tmp_path / "rule.tanium"
    p.write_text(_VALID_RAW_TANIUM_RULE, encoding="utf-8")
    rules = tanium.extract_rules_from_file(str(p))
    assert len(rules) == 1
    assert rules[0] == _VALID_RAW_TANIUM_RULE.strip()


def test_extract_rules_from_comment_only_raw_file_is_empty(tanium: TaniumRule, tmp_path) -> None:
    p = tmp_path / "empty.tanium"
    p.write_text(_INVALID_RAW_COMMENT_ONLY, encoding="utf-8")
    rules = tanium.extract_rules_from_file(str(p))
    assert rules == []
