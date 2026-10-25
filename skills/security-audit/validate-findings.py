#!/usr/bin/env python3

"""
Validates findings.json against report-schema.json.
Usage: python3 validate-findings.py <path-to-findings.json>

This is a dependency-free interpreter for the JSON Schema keywords used by
report-schema.json, plus finding-specific checks that are clearer in code.

The checks reproduce JavaScript semantics where Python's differ: string
length and ordering count UTF-16 code units, numbers are IEEE doubles printed
the way JavaScript prints them, and object keys keep JSON.parse's order.
"""

import bisect
import errno
import functools
import json
import math
import os
import re
import stat
import sys
import unicodedata
from decimal import Decimal
from types import MappingProxyType

SUPPORTED_TYPES = frozenset(["object", "array", "string", "integer", "number", "boolean", "null"])
SUPPORTED_KEYWORDS = frozenset([
    "$comment",
    "additionalProperties",
    "const",
    "description",
    "enum",
    "items",
    "minimum",
    "minItems",
    "minLength",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "type",
    "uniqueItems",
    "visibleContent",
])
SEVERITY_RANK = MappingProxyType({
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
})
LIMITS = MappingProxyType({
    "input_bytes": 5 * 1024 * 1024,
    "nesting_depth": 64,
    "array_items": 1000,
    "canonical_key_bytes": 1024 * 1024,
    "unique_set_bytes": 5 * 1024 * 1024,
    "validation_errors": 100,
})

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
# String.prototype.trim and the \s class: WhiteSpace plus LineTerminator.
JS_WHITESPACE = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
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
    value = value if isinstance(value, str) else _js_string(value)
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


def _js_trim(value):
    return value.strip(JS_WHITESPACE)


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


def _js_string(value):
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _js_number(value)
    if isinstance(value, list):
        return ",".join("" if item is None or item is UNDEFINED else _js_string(item) for item in value)
    if value is UNDEFINED:
        return "undefined"
    return "[object Object]"


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_integer(value):
    return _is_number(value) and math.isfinite(value) and value == int(value)


def _truthy(value):
    if value is None or value is UNDEFINED or value is False:
        return False
    if _is_number(value):
        return value != 0 and not math.isnan(value)
    if isinstance(value, str):
        return value != ""
    return True


def _get(value, key):
    return value.get(key, UNDEFINED) if isinstance(value, dict) else UNDEFINED


def _has_own(value, key):
    return isinstance(value, dict) and key in value


def safe_quote(value):
    if isinstance(value, str):
        clipped = (f"{_utf16_slice(value, MAX_DIAGNOSTIC_STRING_LENGTH)}..."
                   if _utf16_length(value) > MAX_DIAGNOSTIC_STRING_LENGTH else value)
        serialized = _js_stringify_string(clipped)
    elif value is None or isinstance(value, bool):
        serialized = _js_string(value)
    elif _is_number(value) and math.isfinite(value):
        serialized = _js_number(value)
    else:
        kind = _type_of(value)
        serialized = f'"<{kind if kind in ("array", "number", "undefined") else "object"}>"'
    return escape_unsafe_diagnostic_characters(serialized)


def property_path(base, key):
    return f"{base}.{key}" if IDENTIFIER.fullmatch(key) else f"{base}[{safe_quote(key)}]"


class ErrorList(list):
    def push(self, *messages):
        remaining = LIMITS["validation_errors"] - len(self)
        if remaining > 0:
            self.extend(escape_unsafe_diagnostic_characters(message) for message in messages[:remaining])
        return len(self)


def _type_of(value):
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if _is_number(value):
        return "number"
    if isinstance(value, str):
        return "string"
    if value is UNDEFINED:
        return "undefined"
    return "object"


def _deep_equal(left, right):
    if left is right:
        return True
    left_type = _type_of(left)
    if left_type != _type_of(right):
        return False
    if left_type == "array":
        return len(left) == len(right) and all(_deep_equal(a, b) for a, b in zip(left, right))
    if left_type == "object":
        return len(left) == len(right) and all(key in right and _deep_equal(left[key], right[key]) for key in left)
    return left == right


def _has_valid_unicode_scalar_values(value):
    return not any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def has_visible_prose(value):
    return _has_valid_unicode_scalar_values(value) and any(is_visible_character(c) for c in value)


def _canonical_key(value):
    chunks = []
    total = 0

    def append(chunk):
        nonlocal total
        total += len(chunk.encode("utf-8", "surrogatepass"))
        if total > LIMITS["canonical_key_bytes"]:
            raise ValueError(f"canonical key exceeds {LIMITS['canonical_key_bytes']} byte limit")
        chunks.append(chunk)

    def encode(item):
        kind = _type_of(item)
        if kind == "null":
            append("null")
        elif kind == "string":
            append(f"string:{_js_stringify_string(item)}")
        elif kind == "number":
            append(f"number:{_js_number(item)}")
        elif kind == "boolean":
            append(f"boolean:{'true' if item else 'false'}")
        elif kind == "array":
            append("array:[")
            for index, entry in enumerate(item):
                if index > 0:
                    append(",")
                encode(entry)
            append("]")
        elif kind == "object":
            append("object:{")
            for index, key in enumerate(sorted(item, key=_utf16_key)):
                if index > 0:
                    append(",")
                append(_js_stringify_string(key))
                append(":")
                encode(item[key])
            append("}")
        else:
            append(f"{kind}:{_js_string(item)}")

    encode(value)
    return "".join(chunks), total


def _collect_data_limit_errors(value, location="$data"):
    is_container = isinstance(value, (dict, list))
    stack = [(value, location, 1 if is_container else 0)]
    seen = set()

    while stack:
        current, current_location, depth = stack.pop()
        if not isinstance(current, (dict, list)):
            continue
        if depth > LIMITS["nesting_depth"]:
            return [escape_unsafe_diagnostic_characters(
                f"{current_location}: exceeds {LIMITS['nesting_depth']} level nesting depth limit")]
        if id(current) in seen:
            return [escape_unsafe_diagnostic_characters(
                f"{current_location}: input must not contain repeated or cyclic object references")]
        seen.add(id(current))

        if isinstance(current, list):
            if len(current) > LIMITS["array_items"]:
                return [escape_unsafe_diagnostic_characters(
                    f"{current_location}: exceeds {LIMITS['array_items']} item array limit")]
            for index in range(len(current) - 1, -1, -1):
                child = current[index]
                if isinstance(child, (dict, list)):
                    stack.append((child, f"{current_location}[{index}]", depth + 1))
        else:
            for key in reversed(list(current)):
                child = current[key]
                if isinstance(child, (dict, list)):
                    stack.append((child, property_path(current_location, key), depth + 1))

    return []


def _translate_pattern(pattern):
    # JavaScript's $ (without the m flag) matches only at the end of input;
    # Python's also matches before a trailing newline, so use \Z.
    translated = []
    in_class = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            translated.append(pattern[index:index + 2])
            index += 2
            continue
        if in_class:
            in_class = character != "]"
        elif character == "[":
            in_class = True
        elif character == "$":
            character = r"\Z"
        translated.append(character)
        index += 1
    return "".join(translated)


@functools.lru_cache(maxsize=64)
def _compile_pattern(pattern):
    return re.compile(_translate_pattern(pattern))


def collect_schema_errors(schema, location="schema"):
    errors = ErrorList()

    def check(node, p):
        if not isinstance(node, dict):
            errors.push(f"{p}: schema must be an object")
            return

        for key in node:
            if key not in SUPPORTED_KEYWORDS:
                errors.push(f"{p}: unsupported schema keyword {safe_quote(key)}")

        if "$comment" in node and not isinstance(node["$comment"], str):
            errors.push(f"{p}.$comment: expected string")
        if "description" in node and not isinstance(node["description"], str):
            errors.push(f"{p}.description: expected string")
        if "type" in node and not (isinstance(node["type"], str) and node["type"] in SUPPORTED_TYPES):
            errors.push(f"{p}.type: unsupported type {safe_quote(node['type'])}")
        if "properties" in node:
            if not isinstance(node["properties"], dict):
                errors.push(f"{p}.properties: expected object")
            else:
                for key in node["properties"]:
                    check(node["properties"][key], property_path(f"{p}.properties", key))
        if "required" in node:
            required = node["required"]
            if not isinstance(required, list) or any(not isinstance(key, str) for key in required):
                errors.push(f"{p}.required: expected an array of strings")
            elif len(set(required)) != len(required):
                errors.push(f"{p}.required: entries must be unique")
        if "additionalProperties" in node and not isinstance(node["additionalProperties"], bool):
            errors.push(f"{p}.additionalProperties: only boolean values are supported")
        if "enum" in node:
            if not isinstance(node["enum"], list) or len(node["enum"]) == 0:
                errors.push(f"{p}.enum: expected a non-empty array")
            else:
                seen = set()
                for value in node["enum"]:
                    try:
                        key = _canonical_key(value)[0]
                    except ValueError as error:
                        errors.push(f"{p}.enum: {error}")
                        break
                    if key in seen:
                        errors.push(f"{p}.enum: entries must be unique")
                        break
                    seen.add(key)
        if "items" in node:
            check(node["items"], f"{p}.items")
        for keyword in ("minItems", "minLength"):
            if keyword in node and (not _is_integer(node[keyword]) or node[keyword] < 0):
                errors.push(f"{p}.{keyword}: expected a non-negative integer")
        if "minimum" in node and not (_is_number(node["minimum"]) and math.isfinite(node["minimum"])):
            errors.push(f"{p}.minimum: expected a finite number")
        if "pattern" in node:
            if not isinstance(node["pattern"], str):
                errors.push(f"{p}.pattern: expected string")
            else:
                try:
                    _compile_pattern(node["pattern"])
                except re.error:
                    errors.push(f"{p}.pattern: invalid regular expression")
        if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
            errors.push(f"{p}.uniqueItems: expected boolean")
        if "visibleContent" in node:
            if not isinstance(node["visibleContent"], bool):
                errors.push(f"{p}.visibleContent: expected boolean")
            elif node["visibleContent"] is True and node.get("type") != "string":
                errors.push(f'{p}.visibleContent: requires type "string"')
        if "oneOf" in node:
            if not isinstance(node["oneOf"], list) or len(node["oneOf"]) == 0:
                errors.push(f"{p}.oneOf: expected a non-empty array")
            else:
                for index, branch in enumerate(node["oneOf"]):
                    check(branch, f"{p}.oneOf[{index}]")

    check(schema, location)
    return errors


def _find_discriminator(schema):
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(properties, dict):
        entries = properties.items()
    elif isinstance(properties, list):
        entries = ((str(index), value) for index, value in enumerate(properties))
    else:
        return None
    for key, sub_schema in entries:
        if isinstance(sub_schema, dict) and "const" in sub_schema:
            return key, sub_schema["const"]
    return None


def _validate(value, schema, p, errors):
    if len(errors) >= LIMITS["validation_errors"]:
        return
    if "oneOf" in schema:
        results = [_collect_unchecked(value, branch, p) for branch in schema["oneOf"]]
        passing = [index for index, branch_errors in enumerate(results) if len(branch_errors) == 0]

        if len(passing) != 1:
            errors.push(f"{p}: must match exactly one schema in oneOf; matched {len(passing)}")
            if len(passing) == 0 and isinstance(value, dict):
                matching = []
                for index, branch in enumerate(schema["oneOf"]):
                    discriminator = _find_discriminator(branch)
                    if (discriminator and discriminator[0] in value and
                            _deep_equal(value[discriminator[0]], discriminator[1])):
                        matching.append(index)
                if len(matching) == 1:
                    errors.push(*results[matching[0]])

    if "const" in schema and not _deep_equal(value, schema["const"]):
        errors.push(f"{p}: must equal {safe_quote(schema['const'])}, got {safe_quote(value)}")
    if "enum" in schema and not any(_deep_equal(value, allowed) for allowed in schema["enum"]):
        allowed = ", ".join(safe_quote(entry) for entry in schema["enum"])
        errors.push(f"{p}: invalid value {safe_quote(value)} (expected one of {allowed})")

    value_type = _type_of(value)
    if ("type" in schema and value_type != schema["type"] and
            not (schema["type"] == "integer" and value_type == "number" and _is_integer(value))):
        errors.push(f"{p}: expected {_js_string(schema['type'])}, got {value_type}")
        return

    if value_type == "object":
        for required in schema.get("required", []):
            if required not in value:
                errors.push(f"{p}: missing required field {safe_quote(required)}")
        properties = schema.get("properties")
        for key in value:
            if isinstance(properties, dict) and key in properties:
                _validate(value[key], properties[key], property_path(p, key), errors)
            elif schema.get("additionalProperties", UNDEFINED) is False:
                errors.push(f"{p}: unexpected field {safe_quote(key)}")

    if value_type == "array":
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.push(f"{p}: must have at least {_js_string(schema['minItems'])} item(s), got {len(value)}")
        if schema.get("uniqueItems") is True:
            seen = set()
            set_bytes = 0
            for index, item in enumerate(value):
                try:
                    key, key_bytes = _canonical_key(item)
                except ValueError as error:
                    errors.push(f"{p}[{index}]: {error}")
                    break
                if key in seen:
                    errors.push(f"{p}: items must be unique; duplicate at index {index}")
                    continue
                set_bytes += key_bytes
                if set_bytes > LIMITS["unique_set_bytes"]:
                    errors.push(f"{p}: canonical uniqueness set exceeds {LIMITS['unique_set_bytes']} byte limit")
                    break
                seen.add(key)
        if "items" in schema:
            for index, item in enumerate(value):
                _validate(item, schema["items"], f"{p}[{index}]", errors)

    if value_type == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.push(f"{p}: must have at least {_js_string(schema['minLength'])} character(s)")
        if schema.get("visibleContent") is True:
            if not _has_valid_unicode_scalar_values(value):
                errors.push(f"{p}: must contain only valid Unicode scalar values")
            elif not any(is_visible_character(character) for character in value):
                errors.push(f"{p}: must contain a visible character")
        if "pattern" in schema and not _compile_pattern(schema["pattern"]).search(value):
            errors.push(f"{p}: must match pattern {_js_stringify_string(schema['pattern'])}")

    if value_type == "number" and "minimum" in schema and value < schema["minimum"]:
        errors.push(f"{p}: must be at least {_js_string(schema['minimum'])}, got {_js_number(value)}")


def _collect_unchecked(value, schema, p):
    errors = ErrorList()
    _validate(value, schema, p, errors)
    return errors


def collect(value, schema, p="$data"):
    limit_errors = _collect_data_limit_errors(value, p)
    if limit_errors:
        return limit_errors
    return _collect_unchecked(value, schema, p)


def is_safe_relative_source_path(value):
    if (not isinstance(value, str) or len(value) == 0 or not _has_valid_unicode_scalar_values(value) or
            _js_trim(value) != value or any(is_path_forbidden_character(c) for c in value) or
            "\\" in value or ":" in value):
        return False
    if value.startswith(("/", "\\")) or DRIVE_PREFIX.match(value) or value.startswith("~"):
        return False
    return all(
        segment not in ("", ".", "..") and
        not segment.endswith((" ", ".")) and
        not WINDOWS_RESERVED_COMPONENT.match(segment)
        for segment in value.split("/"))


def collect_finding_semantic_errors(findings):
    errors = ErrorList()
    if not isinstance(findings, list):
        return errors

    fingerprints = {}
    previous_fingerprint = None
    for index, finding in enumerate(findings):
        if len(errors) >= LIMITS["validation_errors"]:
            continue
        if not isinstance(finding, dict):
            continue
        base = f"$[{index}]"

        fingerprint = _get(finding, "fingerprint")
        if isinstance(fingerprint, str):
            if fingerprint in fingerprints:
                errors.push(f"{base}.fingerprint: duplicate of $[{fingerprints[fingerprint]}].fingerprint")
            else:
                fingerprints[fingerprint] = index
            if previous_fingerprint is not None and _utf16_key(previous_fingerprint) > _utf16_key(fingerprint):
                errors.push(f"{base}.fingerprint: findings must be sorted lexicographically")
            previous_fingerprint = fingerprint

        for field in ("trace", "evidence"):
            entries = _get(finding, field)
            if not isinstance(entries, list):
                continue
            for entry_index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                if "line" in entry and (not _is_integer(entry["line"]) or entry["line"] < 1):
                    errors.push(f"{base}.{field}[{entry_index}].line: must be a positive integer")
                if "file" in entry and not is_safe_relative_source_path(entry["file"]):
                    errors.push(f"{base}.{field}[{entry_index}].file: must be a safe repository-relative source path")
        remediation = _get(finding, "remediation")
        code_changes = _get(remediation, "code_changes")
        if _truthy(remediation) and isinstance(code_changes, list):
            for change_index, change in enumerate(code_changes):
                if _truthy(change) and _has_own(change, "file_name") and not is_safe_relative_source_path(change["file_name"]):
                    errors.push(f"{base}.remediation.code_changes[{change_index}].file_name: must be a safe repository-relative source path")

        trace = _get(finding, "trace")
        if isinstance(trace, list) and len(trace) == 1:
            kind = _get(trace[0], "kind") if _truthy(trace[0]) else trace[0]
            if not (isinstance(kind, str) and kind in ("entrypoint", "sink")):
                errors.push(f'{base}.trace[0].kind: a one-line trace must be "entrypoint" or "sink"')
        elif isinstance(trace, list) and len(trace) > 1:
            last = len(trace) - 1
            if _truthy(trace[0]) and _get(trace[0], "kind") != "entrypoint":
                errors.push(f'{base}.trace[0].kind: must be "entrypoint", got {safe_quote(_get(trace[0], "kind"))}')
            if _truthy(trace[last]) and _get(trace[last], "kind") != "sink":
                errors.push(f'{base}.trace[{last}].kind: must be "sink", got {safe_quote(_get(trace[last], "kind"))}')
            for trace_index in range(1, last):
                if _truthy(trace[trace_index]) and _get(trace[trace_index], "kind") != "propagation":
                    errors.push(f'{base}.trace[{trace_index}].kind: must be "propagation", got {safe_quote(_get(trace[trace_index], "kind"))}')

        verdict = _get(finding, "verdict")
        if verdict == "confirmed":
            for forbidden in ("claimed_root_cause", "blockers", "validation_plan", "reason"):
                if forbidden in finding:
                    errors.push(f"{base}: confirmed finding must not contain {safe_quote(forbidden)}")
            execution = _get(finding, "execution")
            observed = _get(execution, "observed_result")
            if not (_truthy(execution) and isinstance(execution, (dict, list)) and
                    isinstance(observed, str) and has_visible_prose(observed)):
                errors.push(f"{base}: confirmed finding requires a visible execution observed_result")
            strategy = _get(remediation, "strategy")
            if not (_truthy(remediation) and isinstance(remediation, (dict, list)) and
                    isinstance(strategy, str) and has_visible_prose(strategy)):
                errors.push(f"{base}: confirmed finding requires visible remediation")
            severity = _get(finding, "severity")
            overall = _get(severity, "overall_severity") if _truthy(severity) else severity
            impact = severity
            if _truthy(impact):
                impact = _get(severity, "impact")
                if _truthy(impact):
                    impact = _get(impact, "score")
            if (isinstance(overall, str) and overall in SEVERITY_RANK and
                    isinstance(impact, str) and impact in SEVERITY_RANK and
                    SEVERITY_RANK[overall] > SEVERITY_RANK[impact]):
                errors.push(f"{base}.severity.overall_severity: cannot exceed demonstrated impact {safe_quote(impact)}")
        elif verdict == "needs_validation":
            if "severity" in finding:
                errors.push(f'{base}: needs_validation finding must not contain "severity"')
            for forbidden in ("execution", "remediation", "reason", "root_cause"):
                if forbidden in finding:
                    errors.push(f"{base}: needs_validation finding must not contain {safe_quote(forbidden)}")
            plan = _get(finding, "validation_plan")
            local = _get(plan, "local")
            deployment = _get(plan, "deployment")
            has_local_plan = _truthy(plan) and isinstance(local, str) and has_visible_prose(local)
            has_deployment_plan = _truthy(plan) and isinstance(deployment, str) and has_visible_prose(deployment)
            if not has_local_plan and not has_deployment_plan:
                errors.push(f"{base}.validation_plan: requires at least one visible local or deployment plan")
        elif verdict == "rejected":
            for forbidden in ("severity", "execution", "remediation", "blockers", "validation_plan", "root_cause"):
                if forbidden in finding:
                    errors.push(f"{base}: rejected finding must not contain {safe_quote(forbidden)}")

    return errors


def validate_document(findings, schema):
    schema_errors = collect_schema_errors(schema)
    if schema_errors:
        return schema_errors
    limit_errors = _collect_data_limit_errors(findings, "$")
    if limit_errors:
        return limit_errors
    errors = _collect_unchecked(findings, schema, "$")
    if len(errors) < LIMITS["validation_errors"]:
        errors.push(*collect_finding_semantic_errors(findings))
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


def _load_schema(schema_path):
    with open(schema_path, encoding="utf-8") as handle:
        schema = parse_json(handle.read())
    errors = collect_schema_errors(schema)
    if errors:
        raise ValueError("unsupported or invalid report schema:\n" + "\n".join(errors))
    return schema


def read_file_within_limit(file):
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    non_block = getattr(os, "O_NONBLOCK", 0)
    if not no_follow or not non_block:
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
        if status.st_size > LIMITS["input_bytes"]:
            raise SafeInputError(f"input exceeds {LIMITS['input_bytes']} byte limit")

        chunks = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > LIMITS["input_bytes"]:
                raise SafeInputError(f"input exceeds {LIMITS['input_bytes']} byte limit")
            chunks.append(chunk)
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError:
            raise SafeInputError("input is not valid UTF-8") from None
    finally:
        os.close(descriptor)


_STRING_BODY = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)


def _enforce_json_text_limits(contents):
    containers = []

    def mark_array_item():
        if not containers or containers[-1][0] != "array" or not containers[-1][1]:
            return
        container = containers[-1]
        container[1] = False
        container[2] += 1
        if container[2] > LIMITS["array_items"]:
            raise JsonStructureError(f"input exceeds {LIMITS['array_items']} item array limit")

    index = 0
    length = len(contents)
    while index < length:
        character = contents[index]
        index += 1
        if character == '"':
            mark_array_item()
            match = _STRING_BODY.match(contents, index)
            if match is None:
                return
            index = match.end()
        elif character in "[{":
            mark_array_item()
            if len(containers) >= LIMITS["nesting_depth"]:
                raise JsonStructureError(f"input exceeds {LIMITS['nesting_depth']} level nesting depth limit")
            containers.append(["array" if character == "[" else "object", character == "[", 0])
        elif character in "]}":
            if containers:
                containers.pop()
        elif character == ",":
            if containers and containers[-1][0] == "array":
                containers[-1][1] = True
        elif character not in JS_WHITESPACE:
            mark_array_item()


def run(file):
    if not file:
        print("Usage: python3 validate-findings.py <path-to-findings.json>", file=sys.stderr)
        return 1

    try:
        schema = _load_schema(os.path.join(os.path.dirname(os.path.abspath(__file__)), "report-schema.json"))
    except Exception as error:
        print("Failed to load report-schema.json:", error, file=sys.stderr)
        return 1

    try:
        contents = read_file_within_limit(file)
    except Exception as error:
        reason = str(error) if isinstance(error, SafeInputError) else "input could not be opened or read safely"
        print(f"Failed to read findings JSON: {reason}", file=sys.stderr)
        return 1

    try:
        _enforce_json_text_limits(contents)
    except Exception as error:
        reason = str(error) if isinstance(error, JsonStructureError) else "invalid JSON structure"
        print(f"Failed to parse findings JSON: {reason}", file=sys.stderr)
        return 1

    try:
        findings = parse_json(contents)
    except Exception:
        print("Failed to parse findings JSON: invalid JSON syntax", file=sys.stderr)
        return 1

    try:
        errors = validate_document(findings, schema)
    except Exception:
        print("Failed to validate findings JSON: unexpected validation error", file=sys.stderr)
        return 1
    for message in errors:
        print("ERROR:", escape_unsafe_diagnostic_characters(message), file=sys.stderr)
    if errors:
        cap = (f"; output capped at {LIMITS['validation_errors']}"
               if len(errors) == LIMITS["validation_errors"] else "")
        print(f"FAIL: {len(errors)} validation error(s){cap}", file=sys.stderr)
        return 1
    print(f"PASS: {len(findings)} findings valid")
    return 0


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    return run(sys.argv[1] if len(sys.argv) > 1 else None)


if __name__ == "__main__":
    sys.exit(main())
