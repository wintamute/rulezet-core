import json
import os
import re
from typing import Any, Dict, List, Optional

from app.features.rule.rule_core import get_rule
from app.features.rule.rule_format.abstract_rule_type.rule_type_abstract import RuleType, ValidationResult
from app.core.utils.utils import detect_cve


###############################################################################
#   Tanium class                                                             #
#                                                                             #
#   Tanium Signal / Intel-doc rules can be authored two ways, both accepted  #
#   here:                                                                    #
#     - JSON: metadata fields (name, description, platform, category,       #
#       mitre_technique_ids, ...) plus the boolean detection expression as   #
#       a string field — the shape Tanium's own signal feed exports (a      #
#       single object, or a bulk export as a list / `{"signals": [...]}`).  #
#     - Raw text: just the boolean detection expression, optionally         #
#       preceded by a `// Key: Value` metadata header — same convention as   #
#       kql_format.py, for hand-written / console-copied signals that never #
#       had a JSON wrapper.                                                 #
#   Content is JSON if it parses as one; otherwise it's treated as raw text. #
###############################################################################


_PLATFORMS = frozenset({"windows", "linux", "mac", "chromeos"})
_TECHNIQUE_ID_RE = re.compile(r'^T\d{4}(\.\d{3})?$')

# Recognized Tanium expression operators: word-based (is / contains / ...)
# and symbolic (=, !=, >=, <=, >, <).
_OPERATOR_RE = re.compile(
    r'\b(is not|is|does not contain|contains|starts with|ends with|not matches|matches)\b'
    r'|(!=|==|>=|<=|=|>|<)',
    re.IGNORECASE,
)

# Optional `// Key: Value` header lines at the top of a raw-text rule file.
_HEADER_LINE_RE = re.compile(r'^//\s*([A-Za-z][\w \-]*?)\s*:\s*(.+)$')


def _try_json(content: str) -> Any:
    """Return the parsed JSON value, or None if content isn't valid JSON."""
    try:
        return json.loads(content)
    except Exception:
        return None


def _check_balanced(expression: str) -> Optional[str]:
    """Return an error message if parens/quotes in the expression are unbalanced, else None."""
    stack: List[str] = []
    in_string = False
    string_char = ""
    escaped = False
    for ch in expression:
        if in_string:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == string_char:
                in_string = False
            continue
        if ch in ("'", '"'):
            in_string = True
            string_char = ch
            continue
        if ch == '(':
            stack.append(ch)
        elif ch == ')':
            if not stack:
                return "Unbalanced ')' in expression."
            stack.pop()
    if in_string:
        return "Unterminated string literal in expression."
    if stack:
        return "Unclosed '(' in expression."
    return None


def _strip_comments(content: str) -> str:
    """Return the content with blank and `//` comment lines removed."""
    body_lines = [
        line for line in content.splitlines()
        if line.strip() and not line.strip().startswith('//')
    ]
    return "\n".join(body_lines).strip()


def _parse_header(content: str) -> Dict[str, str]:
    """Parse the leading contiguous block of `// Key: Value` comment lines."""
    meta: Dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith('//'):
            break
        match = _HEADER_LINE_RE.match(stripped)
        if match:
            key = match.group(1).strip().lower().replace(' ', '_')
            meta[key] = match.group(2).strip()
    return meta


def _title_from_filename(filepath: Optional[str]) -> Optional[str]:
    if not filepath:
        return None
    name = os.path.splitext(os.path.basename(filepath))[0]
    name = re.sub(r'[-_]+', ' ', name).strip()
    return name.title() if name else None


class TaniumRule(RuleType):
    """
    Concrete implementation of RuleType for Tanium Signal / Intel-doc rules.
    """

    @property
    def format(self) -> str:
        return "tanium"

    def get_class(self) -> str:
        return "TaniumRule"

    # ---------------------#
    #   Abstract section   #
    # ---------------------#

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate a Tanium signal, accepting either shape:

          - JSON object: `name` and `expression` are required, `expression`
            must have balanced parens/quotes and a recognized comparison
            operator, and optional `platform` / `mitre_technique_ids` values
            must be well-formed.
          - Raw text: just the boolean expression (optionally preceded by a
            `// Key: Value` header), checked the same way as the JSON
            `expression` field.

        Content is treated as JSON if it parses as one; otherwise as raw text.
        """
        doc = _try_json(content)
        if doc is not None:
            return self._validate_json(doc, content)
        return self._validate_raw(content)

    def _validate_json(self, doc: Any, content: str) -> ValidationResult:
        if not isinstance(doc, dict):
            return ValidationResult(
                ok=False,
                errors=["Content must be a single JSON object (one signal)."],
                normalized_content=content,
            )

        errors: List[str] = []
        warnings: List[str] = []

        name = doc.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append("Missing or empty required field: name")

        expression = doc.get("expression")
        if not isinstance(expression, str) or not expression.strip():
            errors.append("Missing or empty required field: expression")
        else:
            bracket_error = _check_balanced(expression)
            if bracket_error:
                errors.append(bracket_error)
            elif not _OPERATOR_RE.search(expression):
                errors.append(
                    "Expression does not contain a recognized comparison operator "
                    "(is / contains / starts with / ends with / matches / =, !=, >, <, ...)."
                )

        platform = doc.get("platform")
        if platform is not None:
            if not isinstance(platform, list) or not all(isinstance(p, str) for p in platform):
                errors.append("Field 'platform' must be a list of strings.")
            else:
                unknown = [p for p in platform if p.lower() not in _PLATFORMS]
                if unknown:
                    warnings.append(f"Unrecognized platform(s) {unknown} — accepting but flagging.")

        technique_ids = doc.get("mitre_technique_ids")
        if technique_ids is not None:
            if not isinstance(technique_ids, list) or not all(isinstance(t, str) for t in technique_ids):
                errors.append("Field 'mitre_technique_ids' must be a list of strings.")
            else:
                bad = [t for t in technique_ids if not _TECHNIQUE_ID_RE.match(t)]
                if bad:
                    errors.append(
                        f"Invalid MITRE ATT&CK technique id(s) {bad} (expected e.g. 'T1140' or 'T1140.001')."
                    )

        ok = len(errors) == 0
        return ValidationResult(ok=ok, errors=errors, warnings=warnings, normalized_content=content)

    def _validate_raw(self, content: str) -> ValidationResult:
        if not content or not content.strip():
            return ValidationResult(ok=False, errors=["Rule content is empty."], normalized_content=content)

        body = _strip_comments(content)
        if not body:
            return ValidationResult(
                ok=False,
                errors=["No expression body found (file only contains comments)."],
                normalized_content=content,
            )

        errors: List[str] = []
        bracket_error = _check_balanced(body)
        if bracket_error:
            errors.append(bracket_error)
        elif not _OPERATOR_RE.search(body):
            errors.append(
                "Expression does not contain a recognized comparison operator "
                "(is / contains / starts with / ends with / matches / =, !=, >, <, ...)."
            )

        ok = len(errors) == 0
        return ValidationResult(ok=ok, errors=errors, warnings=[], normalized_content=content)

    def parse_metadata(self, content: str, info: Dict, validation_result: ValidationResult) -> Dict[str, Any]:
        """Extract rulezet-canonical metadata from a Tanium signal, JSON or raw text."""
        info = info or {}
        doc = _try_json(content)
        if isinstance(doc, dict):
            return self._parse_metadata_json(doc, content, info)
        return self._parse_metadata_raw(content, info)

    def _parse_metadata_json(self, doc: Dict[str, Any], content: str, info: Dict) -> Dict[str, Any]:
        title_fallback = "Untitled Tanium Signal"
        try:
            title = doc.get("name") or title_fallback
            description = doc.get("description") or "No description provided"
            _, cve = detect_cve(description)

            # Flatten platform / category / MITRE technique ids into rulezet's
            # flat tag-list shape, same convention as the ATR adapter.
            tags: List[str] = []
            category = doc.get("category")
            if isinstance(category, str) and category:
                tags.append(f"category:{category}")
            for p in doc.get("platform") or []:
                if isinstance(p, str):
                    tags.append(f"platform:{p}")
            for t in doc.get("mitre_technique_ids") or []:
                if isinstance(t, str):
                    tags.append(f"attack:{t}")

            return {
                "format": "tanium",
                "title": title,
                "license": doc.get("license") or info.get("license", "unknown"),
                "description": description,
                "source": doc.get("source") or info.get("repo_url", "Unknown"),
                "version": str(doc.get("version", "1.0")),
                "original_uuid": doc.get("id") or doc.get("uuid") or "Unknown",
                "author": doc.get("author") or info.get("author", "Unknown"),
                "to_string": content,
                "cve_id": cve,
                "severity": doc.get("severity", "unknown"),
                "tags": tags,
            }
        except Exception as exc:
            return {
                "format": "tanium",
                "title": f"{title_fallback} (Metadata Error)",
                "license": info.get("license", "unknown"),
                "description": f"Error parsing metadata: {exc}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid": "Unknown",
                "author": info.get("author", "Unknown"),
                "cve_id": [],
                "to_string": content,
            }

    def _parse_metadata_raw(self, content: str, info: Dict) -> Dict[str, Any]:
        """Extract metadata from a raw-text signal's optional `// Key: Value` header."""
        title_fallback = _title_from_filename(info.get("filepath")) or "Untitled Tanium Signal"
        try:
            meta = _parse_header(content)

            title = meta.get('title') or meta.get('name') or title_fallback
            description = meta.get('description') or "No description provided"
            _, cve = detect_cve(description)

            tags: List[str] = []
            for key in ('tags', 'category', 'platform', 'mitre', 'mitre_technique_ids', 'attack'):
                if meta.get(key):
                    tags.extend(t.strip() for t in meta[key].split(',') if t.strip())

            return {
                "format": "tanium",
                "title": title,
                "license": meta.get("license") or info.get("license", "unknown"),
                "description": description,
                "source": meta.get("source") or info.get("repo_url", "Unknown"),
                "version": meta.get("version", "1.0"),
                "original_uuid": meta.get("id") or meta.get("uuid") or "Unknown",
                "author": meta.get("author") or info.get("author", "Unknown"),
                "to_string": content,
                "cve_id": cve,
                "severity": meta.get("severity", "unknown"),
                "tags": tags,
            }
        except Exception as exc:
            return {
                "format": "tanium",
                "title": f"{title_fallback} (Metadata Error)",
                "license": info.get("license", "unknown"),
                "description": f"Error parsing metadata: {exc}",
                "version": "N/A",
                "source": info.get("repo_url", "Unknown"),
                "original_uuid": "Unknown",
                "author": info.get("author", "Unknown"),
                "cve_id": [],
                "to_string": content,
            }

    def get_rule_files(self, file: str) -> bool:
        return file.endswith(('.tanium', '.tanium.json'))

    def extract_rules_from_file(self, filepath: str) -> List[str]:
        """
        Extract individual Tanium signals from a file, JSON or raw text.

        JSON handles the canonical single-signal object (returned verbatim,
        no re-dump, to preserve formatting) plus Tanium's bulk feed export
        shapes: a top-level list of signals, or `{"signals": [...]}`. A file
        that isn't valid JSON is treated as a single raw-text signal (whole
        file is the rule, unless it's comment-only).
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        parsed = _try_json(content)
        if parsed is not None:
            if isinstance(parsed, dict) and "expression" in parsed:
                return [content]

            if isinstance(parsed, dict) and isinstance(parsed.get("signals"), list):
                candidates = parsed["signals"]
            elif isinstance(parsed, list):
                candidates = parsed
            else:
                return []

            return [
                json.dumps(signal, indent=2)
                for signal in candidates
                if isinstance(signal, dict) and "expression" in signal
            ]

        if not _strip_comments(content):
            return []
        return [content.strip()]

    def get_rule_files_update(self, repo_dir: str) -> List[str]:
        """Retrieve all Tanium rule files from a repository."""
        rule_files = []
        if not os.path.exists(repo_dir):
            return rule_files
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('_')]
            for file in files:
                if file.startswith('.') or file.startswith('_'):
                    continue
                if self.get_rule_files(file):
                    rule_files.append(os.path.join(root, file))
        return rule_files

    def find_rule_in_repo(self, repo_dir: str, rule_id: int) -> tuple[str, bool]:
        """
        Search for a Tanium signal inside a locally cloned repo, matching by
        the stable id/uuid field first, falling back to the signal name —
        read from the JSON object, or from the raw-text header, whichever
        the file turns out to be.
        """
        rule = get_rule(rule_id)
        if not rule:
            return "No rule found in the database.", False

        for filepath in self.get_rule_files_update(repo_dir):
            for raw in self.extract_rules_from_file(filepath):
                doc = _try_json(raw)
                if isinstance(doc, dict):
                    candidate_uuid = doc.get("id") or doc.get("uuid")
                    candidate_title = doc.get("name")
                else:
                    meta = _parse_header(raw)
                    candidate_uuid = meta.get("id") or meta.get("uuid")
                    candidate_title = meta.get("title") or meta.get("name") or _title_from_filename(filepath)

                if candidate_uuid and rule.original_uuid and str(candidate_uuid) == str(rule.original_uuid):
                    return raw, True

                if candidate_title and candidate_title == rule.title:
                    return raw, True

        return f"Tanium signal '{rule.title}' not found inside local repo.", False
