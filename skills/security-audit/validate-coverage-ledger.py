#!/usr/bin/env python3

"""
Validates coverage-ledger.json and its canonical coverage IDs.
Usage: python3 validate-coverage-ledger.py <path-to-coverage-ledger.json>

The checks reproduce JavaScript semantics where Python's differ: string
length and ordering count UTF-16 code units, numbers are IEEE doubles printed
the way JavaScript prints them, and object keys keep JSON.parse's order.
"""

import bisect
import errno
import json
import math
import os
import re
import stat
import sys
import unicodedata
from decimal import Decimal
from types import MappingProxyType

# Conservative bounds apply before parsing and again to the parsed document.
LIMITS = MappingProxyType({
    "input_bytes": 5 * 1024 * 1024,
    "units": 10000,
    "collection_items": 1000,
    "object_fields": 1000,
    "nesting_depth": 64,
    "preflight_values": 500000,
    "validation_errors": 100,
})
MAX_INPUT_BYTES = LIMITS["input_bytes"]
MAX_UNITS = LIMITS["units"]
MAX_LIST_ITEMS = LIMITS["collection_items"]
MAX_TEXT_LENGTH = 4096
REQUIRED_FIELDS = (
    "coverage_id",
    "canonical_refs",
    "surface",
    "boundary",
    "subsystem",
    "attack_class",
    "starting_paths",
    "ordinary_attack_class_block",
    "selected_companion_blocks",
    "excluded_blocks",
    "prior_status",
    "attempts",
    "wave",
    "status",
    "agent_id",
    "reviewed_paths",
    "local_checks",
    "result_fingerprints",
    "unresolved",
)
REF_FIELDS = ("surface", "boundary", "subsystem", "attack_class")
STATUSES = frozenset([
    "planned",
    "not_applicable",
    "out_of_scope",
    "in_progress",
    "covered",
    "candidate",
    "blocked",
    "deferred",
])
ATTEMPT_STATUSES = frozenset(["covered", "candidate", "blocked"])
ATTEMPT_FIELDS = (
    "wave",
    "status",
    "agent_id",
    "reviewed_paths",
    "local_checks",
    "result_fingerprints",
    "unresolved",
    "reassignment_reason",
)
PRIOR_STATUSES = frozenset([
    "new",
    "prior_confirmed_same_source",
    "prior_confirmed_changed_source",
    "prior_needs_validation",
    "prior_deferred",
    "prior_blocked",
    "prior_out_of_scope",
    "prior_covered_same_source",
    "prior_covered_changed_source",
    "prior_rejected_claim_changed",
    "none",
])
FINGERPRINT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]*")
AGENT_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
WINDOWS_RESERVED_AGENT_ID = re.compile(r"con|prn|aux|nul|com[1-9]|lpt[1-9]")

# Unicode White_Space (PropList.txt) and Default_Ignorable_Code_Point
# (DerivedCoreProperties.txt); Python's unicodedata exposes neither property.
WHITE_SPACE = frozenset(
    [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680]
    + list(range(0x2000, 0x200B))
    + [0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
)
DEFAULT_IGNORABLE_CODE_POINTS = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
VISIBLE_CONTENT_CATEGORIES = frozenset(["Cc", "Cf"])
PATH_FORBIDDEN_CATEGORIES = frozenset(["Cc", "Cf", "Zl", "Zp"])
UNSAFE_DIAGNOSTIC_CATEGORIES = frozenset(["Cc", "Cf", "Cs", "Zl", "Zp"])
# JavaScript's /iu folds K (U+212A KELVIN SIGN) to k and nothing else in these
# names; Python's IGNORECASE would also fold dotless i, so fold ASCII only.
WINDOWS_RESERVED_COMPONENT = re.compile(
    "^(?:con|prn|aux|nul|cloc[k\u212a]\\$|conin\\$|conout\\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\\.|\\Z)",
    re.IGNORECASE | re.ASCII,
)
# String.prototype.trim: WhiteSpace plus LineTerminator.
JS_WHITESPACE = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")
DRIVE_PREFIX = re.compile(r"[A-Za-z]:")
MAX_DIAGNOSTIC_STRING_LENGTH = 256
_DEFAULT_IGNORABLE_STARTS = [start for start, _ in DEFAULT_IGNORABLE_CODE_POINTS]


class JsonStructureError(Exception):
    pass


class SafeInputError(Exception):
    pass


class _Undefined:
    def __repr__(self):
        return "undefined"


UNDEFINED = _Undefined()


def _is_default_ignorable(code_point):
    index = bisect.bisect_right(_DEFAULT_IGNORABLE_STARTS, code_point) - 1
    return index >= 0 and code_point <= DEFAULT_IGNORABLE_CODE_POINTS[index][1]


def is_visible_character(character):
    code_point = ord(character)
    return not (code_point in WHITE_SPACE or
                unicodedata.category(character) in VISIBLE_CONTENT_CATEGORIES or
                _is_default_ignorable(code_point))


def is_path_forbidden_character(character):
    return (unicodedata.category(character) in PATH_FORBIDDEN_CATEGORIES or
            _is_default_ignorable(ord(character)))


def is_unsafe_diagnostic_character(character):
    return (unicodedata.category(character) in UNSAFE_DIAGNOSTIC_CATEGORIES or
            _is_default_ignorable(ord(character)))


def escape_unsafe_diagnostic_characters(value):
    escaped = []
    for character in value:
        if is_unsafe_diagnostic_character(character):
            code_point = ord(character)
            escaped.append(f"\\u{code_point:04x}" if code_point <= 0xFFFF else f"\\u{{{code_point:x}}}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _utf16_length(value):
    return len(value) + sum(1 for character in value if ord(character) > 0xFFFF)


def _utf16_slice(value, limit):
    units = 0
    for index, character in enumerate(value):
        width = 2 if ord(character) > 0xFFFF else 1
        if units + width > limit:
            if units < limit:
                # JavaScript slices between the halves of a surrogate pair.
                return value[:index] + chr(0xD800 + ((ord(character) - 0x10000) >> 10))
            return value[:index]
        units += width
    return value


def _utf16_key(value):
    return value.encode("utf-16-be", "surrogatepass")


def _js_number(value):
    if isinstance(value, int):
        return str(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    exponent += len(digit_tuple) - len(digits)
    k = len(digits)
    n = exponent + k
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = f"{digits[:n]}.{digits[n:]}"
    elif -6 < n <= 0:
        text = f"0.{'0' * -n}{digits}"
    else:
        mantissa = digits if k == 1 else f"{digits[0]}.{digits[1:]}"
        text = f"{mantissa}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
    return sign + text


def _js_stringify_string(value):
    out = ['"']
    for character in value:
        code_point = ord(character)
        if character == '"':
            out.append('\\"')
        elif character == "\\":
            out.append("\\\\")
        elif character in "\b\f\n\r\t":
            out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[character])
        elif code_point < 0x20 or 0xD800 <= code_point <= 0xDFFF:
            out.append(f"\\u{code_point:04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_integer(value):
    return _is_number(value) and math.isfinite(value) and value == int(value)


def safe_quote(value):
    if isinstance(value, str):
        clipped = (f"{_utf16_slice(value, MAX_DIAGNOSTIC_STRING_LENGTH)}..."
                   if _utf16_length(value) > MAX_DIAGNOSTIC_STRING_LENGTH else value)
        serialized = _js_stringify_string(clipped)
    elif value is None:
        serialized = "null"
    elif isinstance(value, bool):
        serialized = "true" if value else "false"
    elif _is_number(value) and math.isfinite(value):
        serialized = _js_number(value)
    elif isinstance(value, list):
        serialized = '"<array>"'
    elif _is_number(value):
        serialized = '"<number>"'
    elif value is UNDEFINED:
        serialized = '"<undefined>"'
    else:
        serialized = '"<object>"'
    return escape_unsafe_diagnostic_characters(serialized)


class ErrorList(list):
    def push(self, *messages):
        remaining = LIMITS["validation_errors"] - len(self)
        if remaining > 0:
            self.extend(escape_unsafe_diagnostic_characters(message) for message in messages[:remaining])
        return len(self)


def _is_object(value):
    return isinstance(value, dict)


def _get(value, key):
    return value.get(key, UNDEFINED) if isinstance(value, dict) else UNDEFINED


def _in(collection, value):
    # A JavaScript Set of strings never contains a non-string.
    return isinstance(value, str) and value in collection


_STRING_BODY = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_TOKEN_REST = re.compile(r'[^ \t\r\n,:\[\]{}"]*')


def preflight_json_text(contents):
    containers = []
    root_state = "value"
    total_values = 0

    def fail(message):
        raise JsonStructureError(f"input {message}")

    def count_value():
        nonlocal total_values
        total_values += 1
        if total_values > LIMITS["preflight_values"]:
            fail(f"exceeds {LIMITS['preflight_values']} total value limit")

    def begin_value():
        nonlocal root_state
        container = containers[-1] if containers else None
        if container is None:
            if root_state != "value":
                fail("has malformed JSON structure")
            root_state = "end"
        elif container["type"] == "array":
            if container["state"] not in ("firstValueOrEnd", "value"):
                fail("has malformed JSON array structure")
            container["items"] += 1
            limit = MAX_UNITS if container["top_level"] else LIMITS["collection_items"]
            if container["items"] > limit:
                fail(f"exceeds {limit} top-level unit limit" if container["top_level"]
                     else f"exceeds {limit} item array limit")
            container["state"] = "commaOrEnd"
        else:
            if container["state"] != "value":
                fail("has malformed JSON object structure")
            container["state"] = "commaOrEnd"
        count_value()

    def begin_string():
        container = containers[-1] if containers else None
        if (container is not None and container["type"] == "object" and
                container["state"] in ("firstKeyOrEnd", "key")):
            container["fields"] += 1
            if container["fields"] > LIMITS["object_fields"]:
                fail(f"exceeds {LIMITS['object_fields']} field object limit")
            container["state"] = "colon"
        else:
            begin_value()

    def begin_container(kind):
        begin_value()
        if len(containers) >= LIMITS["nesting_depth"]:
            fail(f"exceeds nesting depth limit {LIMITS['nesting_depth']}")
        if kind == "array":
            containers.append({"type": kind, "state": "firstValueOrEnd", "items": 0, "top_level": not containers})
        else:
            containers.append({"type": kind, "state": "firstKeyOrEnd", "fields": 0})

    def close_container(kind):
        container = containers[-1] if containers else None
        if container is None or container["type"] != kind:
            fail("has mismatched JSON containers")
        opening = "firstValueOrEnd" if kind == "array" else "firstKeyOrEnd"
        if container["state"] not in (opening, "commaOrEnd"):
            fail(f"has malformed JSON {kind} structure")
        containers.pop()

    index = 0
    length = len(contents)
    while index < length:
        character = contents[index]
        index += 1
        if character in " \t\r\n":
            continue

        if character == '"':
            begin_string()
            match = _STRING_BODY.match(contents, index)
            if match is None:
                fail("has an unterminated JSON string")
            index = match.end()
        elif character == "[":
            begin_container("array")
        elif character == "{":
            begin_container("object")
        elif character == "]":
            close_container("array")
        elif character == "}":
            close_container("object")
        elif character == ":":
            container = containers[-1] if containers else None
            if container is None or container["type"] != "object" or container["state"] != "colon":
                fail("has malformed JSON object structure")
            container["state"] = "value"
        elif character == ",":
            container = containers[-1] if containers else None
            if container is None or container["state"] != "commaOrEnd":
                fail("has malformed JSON collection structure")
            container["state"] = "value" if container["type"] == "array" else "key"
        else:
            begin_value()
            index = _TOKEN_REST.match(contents, index).end()

    if containers:
        fail("has truncated JSON structure")
    if root_state != "end":
        fail("has no JSON value")


def _preflight_document(root):
    errors = ErrorList()
    stack = [(root, 0, "$")]
    visited = 0

    while stack:
        value, depth, location = stack.pop()
        visited += 1
        if visited > LIMITS["preflight_values"]:
            errors.push(f"$: exceeds {LIMITS['preflight_values']} total values")
            return errors
        if not isinstance(value, (dict, list)):
            continue
        if depth >= LIMITS["nesting_depth"]:
            errors.push(f"{location}: exceeds nesting depth limit {LIMITS['nesting_depth']}")
            return errors

        if isinstance(value, list):
            limit = MAX_UNITS if location == "$" else MAX_LIST_ITEMS
            if len(value) > limit:
                errors.push(f"{location}: exceeds {limit} entries")
                return errors
            for index in range(len(value) - 1, -1, -1):
                stack.append((value[index], depth + 1, f"{location}[{index}]"))
            continue

        keys = list(value)
        if len(keys) > LIMITS["object_fields"]:
            errors.push(f"{location}: exceeds {LIMITS['object_fields']} object fields")
            return errors
        for index in range(len(keys) - 1, -1, -1):
            stack.append((value[keys[index]], depth + 1, f"{location}{{{index}}}"))

    return errors


def _has_valid_unicode_scalar_values(value):
    return not any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def has_visible_prose(value):
    return _has_valid_unicode_scalar_values(value) and any(is_visible_character(c) for c in value)


def _is_visible_text(value, max_length=MAX_TEXT_LENGTH):
    return (isinstance(value, str) and
            0 < _utf16_length(value) <= max_length and
            value.strip(JS_WHITESPACE) == value and
            has_visible_prose(value))


def _is_canonical_ref(value):
    return (_is_visible_text(value, 1024) and
            not any(is_path_forbidden_character(c) for c in value) and
            unicodedata.normalize("NFC", value) == value)


def encode_canonical_ref(value):
    if not _is_canonical_ref(value):
        raise TypeError("invalid canonical reference")
    encoded = []
    for byte in value.encode("utf-8"):
        unreserved = (0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A or 0x30 <= byte <= 0x39 or
                      byte in (0x2D, 0x2E, 0x5F, 0x7E))
        encoded.append(chr(byte) if unreserved else f"%{byte:02X}")
    return "".join(encoded)


def canonical_coverage_id(refs):
    if not _is_object(refs):
        raise TypeError("canonical_refs must be an object")
    fields = (*REF_FIELDS, "lifecycle") if "lifecycle" in refs else REF_FIELDS
    if len(refs) != len(fields) or any(field not in refs for field in fields):
        raise TypeError("canonical_refs has missing or unexpected fields")
    return "::".join(encode_canonical_ref(refs[field]) for field in fields)


def is_safe_relative_path(value):
    if (not isinstance(value, str) or len(value) == 0 or not _has_valid_unicode_scalar_values(value) or
            value.strip(JS_WHITESPACE) != value or any(is_path_forbidden_character(c) for c in value) or
            "\\" in value or ":" in value):
        return False
    if value.startswith(("/", "\\")) or DRIVE_PREFIX.match(value) or value.startswith("~"):
        return False
    return all(
        segment not in ("", ".", "..") and
        not segment.endswith((" ", ".")) and
        not WINDOWS_RESERVED_COMPONENT.match(segment)
        for segment in value.split("/"))


def is_safe_agent_id(value):
    return (isinstance(value, str) and
            AGENT_ID_PATTERN.fullmatch(value) is not None and
            WINDOWS_RESERVED_AGENT_ID.fullmatch(value) is None)


def _is_owned_artifact_path(value, agent_id):
    if not is_safe_agent_id(agent_id) or not is_safe_relative_path(value):
        return False
    prefix = f"agents/{agent_id}/artifacts/"
    return value.startswith(prefix) and len(value) > len(prefix)


def _validate_string_array(value, location, errors, allow_empty=True, fingerprint=False, path_value=False):
    if not isinstance(value, list):
        errors.push(f"{location}: expected array")
        return
    if not allow_empty and len(value) == 0:
        errors.push(f"{location}: must not be empty")
    if len(value) > MAX_LIST_ITEMS:
        errors.push(f"{location}: exceeds {MAX_LIST_ITEMS} entries")
    seen = set()
    for index, entry in enumerate(value[:MAX_LIST_ITEMS]):
        entry_location = f"{location}[{index}]"
        valid = is_safe_relative_path(entry) if path_value else _is_visible_text(entry)
        if not valid:
            errors.push(f"{entry_location}: invalid {'repository-relative path' if path_value else 'text'}")
        if fingerprint and isinstance(entry, str) and not FINGERPRINT_PATTERN.fullmatch(entry):
            errors.push(f"{entry_location}: invalid fingerprint")
        if isinstance(entry, str) and entry in seen:
            errors.push(f"{entry_location}: duplicate entry")
        if isinstance(entry, str):
            seen.add(entry)


def _validate_checks(value, location, errors):
    if not isinstance(value, list):
        errors.push(f"{location}: expected array")
        return
    if len(value) > MAX_LIST_ITEMS:
        errors.push(f"{location}: exceeds {MAX_LIST_ITEMS} entries")
    for index, check in enumerate(value[:MAX_LIST_ITEMS]):
        base = f"{location}[{index}]"
        if not _is_object(check):
            errors.push(f"{base}: expected object")
            continue
        for field in ("agent_id", "reviewed_paths", "invariant", "method", "result", "artifact"):
            if field not in check:
                errors.push(f"{base}: missing required field {safe_quote(field)}")
        agent_id = _get(check, "agent_id")
        method = _get(check, "method")
        artifact = _get(check, "artifact")
        if not is_safe_agent_id(agent_id):
            errors.push(f"{base}.agent_id: expected a canonical lowercase agent ID")
        _validate_string_array(_get(check, "reviewed_paths"), f"{base}.reviewed_paths", errors,
                               allow_empty=False, path_value=True)
        if not _is_visible_text(_get(check, "invariant")):
            errors.push(f"{base}.invariant: invalid text")
        if method != "source" and method != "local":
            errors.push(f'{base}.method: expected "source" or "local"')
        if not _is_visible_text(_get(check, "result")):
            errors.push(f"{base}.result: invalid text")
        if method == "source" and artifact is not None:
            errors.push(f"{base}.artifact: source-only check must use null")
        elif method == "local":
            if not _is_owned_artifact_path(artifact, agent_id):
                owner = agent_id if is_safe_agent_id(agent_id) else "<agent-id>"
                errors.push(f"{base}.artifact: local check requires an artifact owned by agent {safe_quote(owner)}")
        elif method != "source" and method != "local" and artifact is not None and not is_safe_relative_path(artifact):
            errors.push(f"{base}.artifact: expected null or a safe output-relative path")


def _validate_reviewed_path_ownership(unit, base, errors):
    reviewed_paths = _get(unit, "reviewed_paths")
    local_checks = _get(unit, "local_checks")
    if not isinstance(reviewed_paths, list) or not isinstance(local_checks, list):
        return
    # Dicts stand in for JavaScript Sets, which iterate in insertion order.
    aggregate_paths = dict.fromkeys(value for value in reviewed_paths if isinstance(value, str))
    owned_paths = {}
    for check in local_checks:
        check_paths = _get(check, "reviewed_paths")
        if not _is_object(check) or not isinstance(check_paths, list):
            continue
        for reviewed_path in check_paths:
            if isinstance(reviewed_path, str):
                owned_paths[reviewed_path] = None
    for reviewed_path in aggregate_paths:
        if reviewed_path not in owned_paths:
            errors.push(f"{base}.reviewed_paths: {safe_quote(reviewed_path)} has no check owner")
    for reviewed_path in owned_paths:
        if reviewed_path not in aggregate_paths:
            errors.push(f"{base}.local_checks: owned path {safe_quote(reviewed_path)} is absent from aggregate reviewed_paths")


def _validate_excluded_blocks(value, location, errors):
    if not isinstance(value, list):
        errors.push(f"{location}: expected array")
        return
    if len(value) > MAX_LIST_ITEMS:
        errors.push(f"{location}: exceeds {MAX_LIST_ITEMS} entries")
    seen = set()
    for index, entry in enumerate(value[:MAX_LIST_ITEMS]):
        base = f"{location}[{index}]"
        if not _is_object(entry):
            errors.push(f"{base}: expected object")
            continue
        block = _get(entry, "block")
        if not _is_visible_text(block):
            errors.push(f"{base}.block: invalid text")
        if not _is_visible_text(_get(entry, "reason")):
            errors.push(f"{base}.reason: invalid text")
        if isinstance(block, str) and block in seen:
            errors.push(f"{base}.block: duplicate entry")
        if isinstance(block, str):
            seen.add(block)


def _semantic_key(unit):
    fields = [unit[field] for field in REF_FIELDS]
    fields.append(unit["lifecycle"] if "lifecycle" in unit else None)
    return "[" + ",".join("null" if field is None else _js_stringify_string(field) for field in fields) + "]"


def _has_valid_semantic_fields(unit):
    return (all(_is_visible_text(_get(unit, field)) for field in REF_FIELDS) and
            ("lifecycle" not in unit or _is_visible_text(unit["lifecycle"])))


def _require_empty_array(unit, field, base, errors):
    value = _get(unit, field)
    if isinstance(value, list) and len(value) > 0:
        errors.push(f"{base}.{field}: unit with status {safe_quote(_get(unit, 'status'))} must keep this array empty")


def _require_nonempty_array(unit, field, base, errors):
    value = _get(unit, field)
    if not isinstance(value, list) or len(value) == 0:
        errors.push(f"{base}.{field}: unit with status {safe_quote(_get(unit, 'status'))} requires entries")


def _validate_state_invariants(unit, base, errors):
    status = _get(unit, "status")
    agent_id = _get(unit, "agent_id")

    def empty_evidence():
        _require_empty_array(unit, "reviewed_paths", base, errors)
        _require_empty_array(unit, "local_checks", base, errors)

    def require_owner():
        if not is_safe_agent_id(agent_id):
            errors.push(f"{base}.agent_id: unit with status {safe_quote(status)} requires a canonical lowercase agent ID")

    if status != "candidate":
        _require_empty_array(unit, "result_fingerprints", base, errors)

    if status == "planned":
        if agent_id is not None:
            errors.push(f"{base}.agent_id: planned unit must be unassigned")
        empty_evidence()
        _require_empty_array(unit, "unresolved", base, errors)
    elif status in ("not_applicable", "out_of_scope", "deferred"):
        if agent_id is not None:
            errors.push(f"{base}.agent_id: unit with status {safe_quote(status)} must be unassigned")
        empty_evidence()
        _require_nonempty_array(unit, "unresolved", base, errors)
    elif status == "in_progress":
        require_owner()
        empty_evidence()
        _require_empty_array(unit, "unresolved", base, errors)
    elif status == "blocked":
        require_owner()
        _require_nonempty_array(unit, "reviewed_paths", base, errors)
        _require_nonempty_array(unit, "local_checks", base, errors)
        _require_nonempty_array(unit, "unresolved", base, errors)
    elif status == "covered":
        require_owner()
        _require_nonempty_array(unit, "reviewed_paths", base, errors)
        _require_nonempty_array(unit, "local_checks", base, errors)
        _require_empty_array(unit, "unresolved", base, errors)
    elif status == "candidate":
        require_owner()
        _require_nonempty_array(unit, "reviewed_paths", base, errors)
        _require_nonempty_array(unit, "local_checks", base, errors)
        _require_nonempty_array(unit, "result_fingerprints", base, errors)


def _validate_attempts(value, unit, base, errors):
    if not isinstance(value, list):
        errors.push(f"{base}.attempts: expected array")
        return
    if len(value) > MAX_LIST_ITEMS:
        errors.push(f"{base}.attempts: exceeds {MAX_LIST_ITEMS} entries")

    unit_wave = _get(unit, "wave")
    prior_owners = set()
    prior_artifacts = set()
    previous_wave = 0
    for index, attempt in enumerate(value[:MAX_LIST_ITEMS]):
        attempt_base = f"{base}.attempts[{index}]"
        if not _is_object(attempt):
            errors.push(f"{attempt_base}: expected object")
            continue
        for field in ATTEMPT_FIELDS:
            if field not in attempt:
                errors.push(f"{attempt_base}: missing required field {safe_quote(field)}")
        wave = _get(attempt, "wave")
        if not _is_integer(wave) or wave < 1:
            errors.push(f"{attempt_base}.wave: expected a positive integer")
        else:
            if wave <= previous_wave:
                errors.push(f"{attempt_base}.wave: archived attempt waves must be strictly increasing")
            if _is_integer(unit_wave) and wave >= unit_wave:
                errors.push(f"{attempt_base}.wave: archived attempt wave must precede current wave {safe_quote(unit_wave)}")
            previous_wave = wave
        if not _in(ATTEMPT_STATUSES, _get(attempt, "status")):
            errors.push(f'{attempt_base}.status: expected "covered", "candidate", or "blocked"')
        agent_id = _get(attempt, "agent_id")
        has_fresh_owner = False
        if not is_safe_agent_id(agent_id):
            errors.push(f"{attempt_base}.agent_id: archived attempt requires a canonical lowercase agent ID")
        elif agent_id in prior_owners:
            errors.push(f"{attempt_base}.agent_id: assignment owner must be fresh for each attempt")
        else:
            has_fresh_owner = True
        _validate_string_array(_get(attempt, "reviewed_paths"), f"{attempt_base}.reviewed_paths", errors, path_value=True)
        _validate_checks(_get(attempt, "local_checks"), f"{attempt_base}.local_checks", errors)
        _validate_reviewed_path_ownership(attempt, attempt_base, errors)
        _validate_string_array(_get(attempt, "result_fingerprints"), f"{attempt_base}.result_fingerprints", errors,
                               fingerprint=True)
        _validate_string_array(_get(attempt, "unresolved"), f"{attempt_base}.unresolved", errors)
        if not _is_visible_text(_get(attempt, "reassignment_reason")):
            errors.push(f"{attempt_base}.reassignment_reason: invalid text")
        _validate_state_invariants(attempt, attempt_base, errors)

        local_checks = _get(attempt, "local_checks")
        if isinstance(local_checks, list):
            for check_index, check in enumerate(local_checks):
                if not _is_object(check):
                    continue
                artifact = _get(check, "artifact")
                if _in(prior_owners, _get(check, "agent_id")):
                    errors.push(f"{attempt_base}.local_checks[{check_index}].agent_id: prior assignment owner evidence must remain in its earlier attempt")
                if _in(prior_artifacts, artifact):
                    errors.push(f"{attempt_base}.local_checks[{check_index}].artifact: artifact from an earlier attempt cannot be reused")
                if _get(check, "method") == "local" and isinstance(artifact, str):
                    prior_artifacts.add(artifact)
        if has_fresh_owner:
            prior_owners.add(agent_id)

    if is_safe_agent_id(_get(unit, "agent_id")) and unit["agent_id"] in prior_owners:
        errors.push(f"{base}.agent_id: current assignment owner must be fresh after reassignment")
    local_checks = _get(unit, "local_checks")
    if isinstance(local_checks, list):
        for index, check in enumerate(local_checks):
            if not _is_object(check):
                continue
            if _in(prior_owners, _get(check, "agent_id")):
                errors.push(f"{base}.local_checks[{index}].agent_id: prior assignment owner evidence must remain in its archived attempt")
            if _in(prior_artifacts, _get(check, "artifact")):
                errors.push(f"{base}.local_checks[{index}].artifact: artifact from an archived attempt cannot be reused")


def _js_set_key(value):
    # SameValueZero over the values a JavaScript Set can hold; objects compare
    # by identity, and true is never equal to 1.
    if isinstance(value, (dict, list)):
        return ("object", id(value))
    if isinstance(value, bool):
        return ("boolean", value)
    if _is_number(value):
        return ("number", float(value))
    return (type(value).__name__, value)


def _collect_unit_errors(unit, index):
    errors = ErrorList()
    base = f"$[{index}]"
    if not _is_object(unit):
        return [f"{base}: expected object"]

    for field in REQUIRED_FIELDS:
        if field not in unit:
            errors.push(f"{base}: missing required field {safe_quote(field)}")
    for field in REF_FIELDS:
        if not _is_visible_text(_get(unit, field)):
            errors.push(f"{base}.{field}: invalid text")
    if "lifecycle" in unit and not _is_visible_text(unit["lifecycle"]):
        errors.push(f"{base}.lifecycle: invalid text")

    expected_id = None
    refs = _get(unit, "canonical_refs")
    if not _is_object(refs):
        errors.push(f"{base}.canonical_refs: expected object")
    else:
        expected_fields = (*REF_FIELDS, "lifecycle") if "lifecycle" in refs else REF_FIELDS
        for field in expected_fields:
            if field not in refs:
                errors.push(f"{base}.canonical_refs: missing required field {safe_quote(field)}")
            elif not _is_canonical_ref(refs[field]):
                errors.push(f"{base}.canonical_refs.{field}: invalid canonical reference")
        if any(field not in expected_fields for field in refs):
            errors.push(f"{base}.canonical_refs: contains unexpected fields")
        if ("lifecycle" in unit) != ("lifecycle" in refs):
            errors.push(f"{base}: lifecycle and canonical_refs.lifecycle must appear together")
        try:
            expected_id = canonical_coverage_id(refs)
        except TypeError:
            pass  # The specific reference errors above are more useful.
    coverage_id = _get(unit, "coverage_id")
    if not _is_visible_text(coverage_id, 65536):
        errors.push(f"{base}.coverage_id: invalid text")
    elif expected_id is not None and coverage_id != expected_id:
        errors.push(f"{base}.coverage_id: expected canonical ID {safe_quote(expected_id)}")

    _validate_string_array(_get(unit, "starting_paths"), f"{base}.starting_paths", errors,
                           allow_empty=False, path_value=True)
    ordinary_block = _get(unit, "ordinary_attack_class_block")
    if ordinary_block is not None and not _is_visible_text(ordinary_block):
        errors.push(f"{base}.ordinary_attack_class_block: expected null or non-empty text")
    selected_blocks = _get(unit, "selected_companion_blocks")
    excluded_blocks = _get(unit, "excluded_blocks")
    _validate_string_array(selected_blocks, f"{base}.selected_companion_blocks", errors)
    _validate_excluded_blocks(excluded_blocks, f"{base}.excluded_blocks", errors)
    if isinstance(selected_blocks, list) and isinstance(excluded_blocks, list):
        selected = {_js_set_key(block) for block in selected_blocks}
        for block_index, entry in enumerate(excluded_blocks):
            if _is_object(entry) and _js_set_key(_get(entry, "block")) in selected:
                errors.push(f"{base}.excluded_blocks[{block_index}].block: block is also selected")

    if not _in(PRIOR_STATUSES, _get(unit, "prior_status")):
        errors.push(f"{base}.prior_status: invalid value {safe_quote(_get(unit, 'prior_status'))}")
    if not _in(STATUSES, _get(unit, "status")):
        errors.push(f"{base}.status: invalid value {safe_quote(_get(unit, 'status'))}")
    wave = _get(unit, "wave")
    if not _is_integer(wave) or wave < 1:
        errors.push(f"{base}.wave: expected a positive integer")
    agent_id = _get(unit, "agent_id")
    if agent_id is not None and not is_safe_agent_id(agent_id):
        errors.push(f"{base}.agent_id: expected null or a safe agent ID")

    _validate_attempts(_get(unit, "attempts"), unit, base, errors)
    _validate_string_array(_get(unit, "reviewed_paths"), f"{base}.reviewed_paths", errors, path_value=True)
    _validate_checks(_get(unit, "local_checks"), f"{base}.local_checks", errors)
    _validate_reviewed_path_ownership(unit, base, errors)
    _validate_string_array(_get(unit, "result_fingerprints"), f"{base}.result_fingerprints", errors, fingerprint=True)
    _validate_string_array(_get(unit, "unresolved"), f"{base}.unresolved", errors)

    _validate_state_invariants(unit, base, errors)

    return errors


def read_file_within_limit(file):
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    non_block = getattr(os, "O_NONBLOCK", 0)
    if not no_follow or not non_block:
        # There is no race-safe fallback on these platforms, so reject all inputs.
        raise SafeInputError("OS no-follow and nonblocking input protection is unavailable")

    try:
        descriptor = os.open(file, os.O_RDONLY | no_follow | non_block)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise SafeInputError("input must not be a symlink") from None
        raise
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise SafeInputError("input must be a regular file")
        if status.st_size > MAX_INPUT_BYTES:
            raise SafeInputError(f"input exceeds {MAX_INPUT_BYTES} byte limit")

        chunks = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > MAX_INPUT_BYTES:
                raise SafeInputError(f"input exceeds {MAX_INPUT_BYTES} byte limit")
            chunks.append(chunk)
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError:
            raise SafeInputError("input is not valid UTF-8") from None
    finally:
        os.close(descriptor)


def validate_document(ledger):
    errors = ErrorList()
    if not isinstance(ledger, list):
        errors.push("$: expected a top-level array")
        return errors
    if len(ledger) > MAX_UNITS:
        errors.push(f"$: exceeds {MAX_UNITS} coverage units")
        return errors

    errors.push(*_preflight_document(ledger))
    if errors:
        return errors

    ids = {}
    semantics = {}
    previous_id = None
    for index, unit in enumerate(ledger):
        if len(errors) >= LIMITS["validation_errors"]:
            break
        errors.push(*_collect_unit_errors(unit, index))
        if len(errors) >= LIMITS["validation_errors"]:
            break
        coverage_id = _get(unit, "coverage_id")
        if not _is_object(unit) or not isinstance(coverage_id, str):
            continue

        key = _semantic_key(unit) if _has_valid_semantic_fields(unit) else None
        if coverage_id in ids:
            previous_index, previous_key = ids[coverage_id]
            qualifier = ("canonical identity collision with different semantic fields"
                         if key is not None and previous_key is not None and previous_key != key
                         else "duplicate coverage ID")
            errors.push(f"$[{index}].coverage_id: {qualifier} at $[{previous_index}]")
        else:
            ids[coverage_id] = (index, key)
        if key is not None and key in semantics and semantics[key][0] != coverage_id:
            previous_coverage_id, previous_index = semantics[key]
            errors.push(f"$[{index}].canonical_refs: semantic tuple already uses coverage ID {safe_quote(previous_coverage_id)} at $[{previous_index}]")
        elif key is not None:
            semantics[key] = (coverage_id, index)
        if previous_id is not None and _utf16_key(previous_id) > _utf16_key(coverage_id):
            errors.push(f"$[{index}].coverage_id: units must be sorted lexicographically")
        previous_id = coverage_id
    return errors


def _is_array_index(key):
    return ARRAY_INDEX.fullmatch(key) is not None and int(key) < 2 ** 32 - 1


def _js_object(pairs):
    # JSON.parse keeps the last value for a duplicate key at its first
    # position, and enumerates array-index keys first in numeric order.
    value = dict(pairs)
    index_keys = sorted((key for key in value if _is_array_index(key)), key=int)
    if not index_keys:
        return value
    ordered = {key: value[key] for key in index_keys}
    ordered.update((key, entry) for key, entry in value.items() if key not in ordered)
    return ordered


def _reject_constant(name):
    raise ValueError(f"invalid JSON constant {name}")


def parse_json(contents):
    """Parse JSON text into the values JavaScript's JSON.parse produces."""
    return json.loads(contents, object_pairs_hook=_js_object, parse_int=float,
                      parse_float=float, parse_constant=_reject_constant)


def run(file):
    if not file:
        print("Usage: python3 validate-coverage-ledger.py <path-to-coverage-ledger.json>", file=sys.stderr)
        return 1

    try:
        contents = read_file_within_limit(file)
    except Exception as error:
        reason = str(error) if isinstance(error, SafeInputError) else "input could not be opened or read safely"
        print(f"Failed to read coverage ledger: {reason}", file=sys.stderr)
        return 1

    try:
        preflight_json_text(contents)
    except Exception as error:
        reason = str(error) if isinstance(error, JsonStructureError) else "invalid JSON structure"
        print(f"Failed to parse coverage ledger: {reason}", file=sys.stderr)
        return 1
    try:
        ledger = parse_json(contents)
    except Exception:
        print("Failed to parse coverage ledger: invalid JSON syntax", file=sys.stderr)
        return 1

    try:
        errors = validate_document(ledger)
    except Exception:
        print("Failed to validate coverage ledger: unexpected validation error", file=sys.stderr)
        return 1
    for message in errors:
        print("ERROR:", message, file=sys.stderr)
    if errors:
        cap = (f"; output capped at {LIMITS['validation_errors']}"
               if len(errors) == LIMITS["validation_errors"] else "")
        print(f"FAIL: {len(errors)} validation error(s){cap}", file=sys.stderr)
        return 1
    print(f"PASS: {len(ledger)} coverage units valid")
    return 0


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    return run(sys.argv[1] if len(sys.argv) > 1 else None)


if __name__ == "__main__":
    sys.exit(main())
