#!/usr/bin/env python3

import importlib.util
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATOR_PATH = os.path.join(HERE, "validate-findings.py")
LEDGER_VALIDATOR_PATH = os.path.join(HERE, "validate-coverage-ledger.py")


def load_module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


findings_module = load_module("validate_findings", VALIDATOR_PATH)
LIMITS = findings_module.LIMITS
collect = findings_module.collect
collect_schema_errors = findings_module.collect_schema_errors
validate_document = findings_module.validate_document

with open(os.path.join(HERE, "report-schema.json"), encoding="utf-8") as schema_file:
    schema = json.load(schema_file)

CLI_TIMEOUT = 5
HOSTILE_CLI_TIMEOUT = 15
HAS_SAFE_INPUT_OPEN = bool(getattr(os, "O_NOFOLLOW", 0)) and bool(getattr(os, "O_NONBLOCK", 0))
TERMINAL_CONTROL_PAYLOAD = "\u001b\u0007\u0085\u202e\u034f\ufe0f"
TERMINAL_CONTROL_BYTES = [
    bytes([0x1B]),
    bytes([0x07]),
    "\u0085".encode(),
    "\u202e".encode(),
    "\u034f".encode(),
    "\ufe0f".encode(),
]
LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def stringify(value):
    """JSON.stringify: compact, raw non-ASCII, lone surrogates escaped."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return LONE_SURROGATE.sub(lambda match: f"\\u{ord(match.group()):04x}", text)


def source(kind="entrypoint", file="src/handler.c", line=10):
    return {"kind": kind, "file": file, "line": line, "scope": "handle", "description": "Attacker data reaches the operation."}


def evidence(file="src/handler.c", line=10):
    return {"file": file, "line": line, "description": "The source performs the operation without the required check."}


def confirmed():
    return {
        "verdict": "confirmed",
        "fingerprint": "src-handler-missing-check",
        "title": "Missing ownership check",
        "description": "An attacker can reach an operation without the intended ownership check.",
        "root_cause": "handle omits the ownership check before changing the object.",
        "intended_behavior": "Only the object's owner can change it.",
        "trace": [source("entrypoint"), source("propagation", "src/model.c", 20), source("sink", "src/store.c", 30)],
        "evidence": [evidence()],
        "conditions": [],
        "execution": {
            "attacker_perspective": "An unprivileged remote user with their own account.",
            "payloads": ["An object identifier owned by another user."],
            "instructions": ["Submit the identifier through the public operation."],
            "observed_result": "The other user's object changes.",
        },
        "remediation": {"strategy": "Check ownership before the state change."},
        "severity": {
            "likelihood": {"score": "medium", "reason": "The operation is directly reachable."},
            "impact": {"score": "medium", "reason": "The attacker changes one protected object."},
            "overall_severity": "medium",
        },
        "confidence": {"score": "high", "reason": "The source path and result were reproduced."},
    }


def needs_validation():
    return {
        "verdict": "needs_validation",
        "fingerprint": "src-parser-size-hypothesis",
        "title": "Unchecked parsed size",
        "description": "A parsed size may reach an allocation without a limit.",
        "claimed_root_cause": "parse_size may pass an unbounded value to allocate.",
        "trace": [source()],
        "evidence": [evidence()],
        "blockers": ["The generated parser source is absent from this checkout."],
        "validation_plan": {
            "local": "Generate the parser and submit the smallest input that exceeds the documented limit.",
            "deployment": "In an approved test deployment, confirm the request reaches the generated parser and record the bounded observable result.",
        },
    }


def rejected():
    return {
        "verdict": "rejected",
        "fingerprint": "src-router-auth-bypass",
        "title": "Authorization bypass in router",
        "description": "The candidate claimed a route bypassed authorization.",
        "claimed_root_cause": "dispatch was claimed to skip the authorization wrapper.",
        "trace": [source("sink")],
        "evidence": [evidence()],
        "reason": "All routes pass through the authorization wrapper before dispatch.",
    }


def errors_for(value):
    return validate_document(value, schema)


def spawn(args, timeout=CLI_TIMEOUT):
    return subprocess.run([sys.executable, *args], capture_output=True, encoding="utf-8", timeout=timeout)


def run_cli(contents, timeout=CLI_TIMEOUT):
    directory = tempfile.mkdtemp(prefix="validate-findings-")
    findings_path = os.path.join(directory, "findings.json")
    try:
        with open(findings_path, "wb") as handle:
            handle.write(contents.encode() if isinstance(contents, str) else contents)
        return spawn([VALIDATOR_PATH, findings_path], timeout)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def cli_output(result):
    return f"{result.stdout}{result.stderr}"


def producer_shaped_findings():
    demonstrated = confirmed()
    demonstrated["conditions"] = [{
        "kind": "authentication_level",
        "description": "The attacker needs a normal account.",
    }]
    demonstrated["execution"]["payloads"] = ["", " \t\r\n", "\u0000\u001f\u007f", "\u034f", "\ufe0f", "\ud800", "\udc00", "[{,}]\\\""]
    demonstrated["remediation"]["code_changes"] = [{
        "file_name": "src/handler.c",
        "fixed_code": "",
    }]

    blocked = needs_validation()
    del blocked["validation_plan"]["deployment"]

    return [demonstrated, blocked, rejected()]


class FindingsValidatorTest(unittest.TestCase):
    def assert_no_injected_control_bytes(self, output):
        data = output if isinstance(output, bytes) else output.encode("utf-8", "surrogatepass")
        for marker in TERMINAL_CONTROL_BYTES:
            self.assertEqual(data.find(marker), -1, f"found raw control bytes {marker.hex()}")

    def reject_mutation(self, factory, mutate):
        value = factory()
        mutate(value)
        self.assertNotEqual(len(errors_for([value])), 0)

    def assert_no_trace(self, output, pattern=r"Traceback|RecursionError|MemoryError"):
        self.assertIsNone(re.search(pattern, output, re.IGNORECASE), output)

    def test_schema_is_an_actual_top_level_array_with_exactly_three_branches(self):
        self.assertEqual(schema["type"], "array")
        self.assertEqual(len(schema["items"]["oneOf"]), 3)
        self.assertEqual([branch["properties"]["verdict"]["const"] for branch in schema["items"]["oneOf"]], [
            "confirmed", "needs_validation", "rejected",
        ])
        confirmed_schema = schema["items"]["oneOf"][0]["properties"]
        self.assertIs(confirmed_schema["title"]["visibleContent"], True)
        self.assertNotIn("minLength", confirmed_schema["execution"]["properties"]["payloads"]["items"])
        self.assertNotIn("visibleContent", confirmed_schema["execution"]["properties"]["payloads"]["items"])
        self.assertNotIn("minLength", confirmed_schema["remediation"]["properties"]["code_changes"]["items"]["properties"]["fixed_code"])

    def test_accepts_a_producer_shaped_findings_document_through_the_cli(self):
        result = run_cli(stringify(producer_shaped_findings()))
        self.assertEqual(result.returncode, 0, cli_output(result))
        self.assertRegex(result.stdout, r"PASS: 3 findings valid")

    def test_accepts_empty_output_and_each_complete_branch(self):
        self.assertEqual(errors_for([]), [])
        self.assertEqual(errors_for([confirmed(), needs_validation(), rejected()]), [])
        local_only = needs_validation()
        del local_only["validation_plan"]["deployment"]
        self.assertEqual(errors_for([local_only]), [])
        deployment_only = needs_validation()
        del deployment_only["validation_plan"]["local"]
        self.assertEqual(errors_for([deployment_only]), [])

    def test_allows_a_one_line_finding_trace(self):
        finding = confirmed()
        finding["trace"] = [source("entrypoint")]
        self.assertEqual(errors_for([finding]), [])

    def test_rejects_empty_required_content(self):
        def setter(*keys, value):
            def mutate(finding):
                target = finding
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
            return mutate

        cases = [
            (confirmed, setter("title", value="")),
            (confirmed, setter("title", value="   ")),
            (confirmed, setter("evidence", value=[])),
            (confirmed, setter("execution", "payloads", value=[])),
            (confirmed, setter("execution", "instructions", value=[])),
            (confirmed, setter("execution", "observed_result", value="")),
            (confirmed, setter("remediation", "strategy", value="")),
            (needs_validation, setter("blockers", value=[])),
            (needs_validation, setter("validation_plan", value={})),
            (needs_validation, setter("validation_plan", value={"local": " "})),
            (rejected, setter("claimed_root_cause", value="")),
        ]
        for factory, mutate in cases:
            self.reject_mutation(factory, mutate)

    def test_preserves_exact_payload_and_replacement_code_strings(self):
        finding = confirmed()
        payloads = ["", " \t\r\n", "\u0000\u001f\u007f", "\u034f", "\ufe0f", "\ud800", "\udc00"]
        fixed_code = "\u0000 \t\r\n\u001f\u007f\u034f\ufe0f\ud800x\udc00"
        finding["execution"]["payloads"] = list(payloads)
        finding["remediation"]["code_changes"] = [{"file_name": "src/handler.c", "fixed_code": fixed_code}]

        self.assertEqual(errors_for([finding]), [])
        self.assertEqual(finding["execution"]["payloads"], payloads)
        self.assertEqual(finding["remediation"]["code_changes"][0]["fixed_code"], fixed_code)

    def test_rejects_invalid_scalars_and_whitespace_control_format_or_default_ignorable_prose(self):
        for invisible in ["\u0000\t\r\n\u001f\u007f\u200b", "\u034f", "\ufe0f", "\ud800", "\udc00", "visible\ud800"]:
            cases = [
                (confirmed, lambda f: f.__setitem__("title", invisible)),
                (confirmed, lambda f: f["trace"][0].__setitem__("scope", invisible)),
                (confirmed, lambda f: f["evidence"][0].__setitem__("description", invisible)),
                (confirmed, lambda f: f["execution"].__setitem__("instructions", [invisible])),
                (confirmed, lambda f: f["remediation"].__setitem__("strategy", invisible)),
                (confirmed, lambda f: f["severity"]["impact"].__setitem__("reason", invisible)),
                (confirmed, lambda f: f["confidence"].__setitem__("reason", invisible)),
                (needs_validation, lambda f: f.__setitem__("blockers", [invisible])),
                (needs_validation, lambda f: f.__setitem__("validation_plan", {"local": invisible})),
                (rejected, lambda f: f.__setitem__("reason", invisible)),
            ]
            for factory, mutate in cases:
                self.reject_mutation(factory, mutate)

    def test_quotes_input_derived_controls_in_direct_validation_values_and_paths(self):
        finding = confirmed()
        finding["trace"][0]["kind"] = f"invalid-{TERMINAL_CONTROL_PAYLOAD}"
        finding["execution"][f"extra-{TERMINAL_CONTROL_PAYLOAD}"] = "value"

        cyclic = {}
        cyclic[f"path-{TERMINAL_CONTROL_PAYLOAD}"] = cyclic
        output = "\n".join([
            *errors_for([finding]),
            *collect(cyclic, {"type": "object"}, "$input"),
        ])

        for escaped in ["\\u001b", "\\u0007", "\\u0085", "\\u202e", "\\u034f", "\\ufe0f"]:
            self.assertIn(escaped, output, f"missing escaped diagnostic {escaped}")
        self.assert_no_injected_control_bytes(output)

    def test_rejects_line_zero(self):
        self.reject_mutation(confirmed, lambda f: f["trace"][0].__setitem__("line", 0))
        self.reject_mutation(rejected, lambda f: f["evidence"][0].__setitem__("line", 0))

    def test_does_not_treat_inherited_or_object_prototype_properties_as_schema_properties(self):
        # JavaScript objects inherit properties such as constructor; a Python
        # dict has no prototype chain, so the inherited-object cases reduce to
        # an object whose own properties are empty.
        for name in ("constructor", "__proto__", "hasOwnProperty", "toString"):
            self.reject_mutation(confirmed, lambda f: f.__setitem__(name, "not allowed"))
        inherited = {}
        self.assertTrue(any("exactly one" in error for error in errors_for([inherited])))
        self.assertTrue(any("missing required" in error for error in collect({}, {
            "type": "object",
            "properties": {"constructor": {"type": "string"}},
            "required": ["constructor"],
            "additionalProperties": False,
        })))

    def test_one_of_requires_exactly_one_passing_branch(self):
        self.assertTrue(any("matched 2" in error for error in
                            collect("value", {"oneOf": [{"type": "string"}, {"minLength": 1}]}, "$test")))
        self.assertTrue(any("matched 0" in error for error in
                            collect(7, {"oneOf": [{"type": "string"}, {"minimum": 10}]}, "$test")))

    def test_rejects_duplicate_fingerprints_and_unique_array_entries(self):
        first = confirmed()
        second = rejected()
        second["fingerprint"] = first["fingerprint"]
        self.assertTrue(any("duplicate of" in error for error in errors_for([first, second])))
        self.reject_mutation(needs_validation, lambda f: f.__setitem__("blockers", [f["blockers"][0], f["blockers"][0]]))

    def test_uses_canonical_set_uniqueness_for_structured_entries_at_the_array_limit(self):
        entries = [{"id": index, "label": str(index)} for index in range(LIMITS["array_items"])]
        self.assertEqual(collect(entries, {"type": "array", "uniqueItems": True}), [])

        duplicate = entries[:-1]
        duplicate.append({"label": "0", "id": 0})
        self.assertTrue(any(f"duplicate at index {LIMITS['array_items'] - 1}" in error
                            for error in collect(duplicate, {"type": "array", "uniqueItems": True})))

    def test_bounds_canonical_uniqueness_keys_and_set_storage(self):
        oversized_key = "x" * (LIMITS["canonical_key_bytes"] + 1)
        self.assertTrue(any("canonical key exceeds" in error
                            for error in collect([oversized_key], {"type": "array", "uniqueItems": True})))

        item_length = LIMITS["unique_set_bytes"] // 6
        large_unique_items = [f"{index}{'x' * item_length}" for index in range(6)]
        self.assertTrue(any("canonical uniqueness set exceeds" in error
                            for error in collect(large_unique_items, {"type": "array", "uniqueItems": True})))

    def test_requires_findings_to_be_sorted_by_fingerprint(self):
        first = confirmed()
        second = rejected()
        self.assertTrue(any("sorted lexicographically" in error for error in errors_for([second, first])))

    def test_rejects_severity_above_demonstrated_impact(self):
        def mutate(finding):
            finding["severity"]["overall_severity"] = "high"
            finding["severity"]["impact"]["score"] = "medium"
        self.reject_mutation(confirmed, mutate)

    def test_rejects_unsafe_source_paths(self):
        bad_paths = [
            "/etc/passwd",
            "../src/file.c",
            "src/../file.c",
            "src//file.c",
            "C:\\src\\file.c",
            "src/file:name.c",
            "src/file\nname.c",
            "src/file\u0001name.c",
            "src/file\u0085name.c",
            "src/file\u2028name.c",
            "src/file\u202ename.c",
            "src/file\u2066name.c",
            "src/file\u200dname.c",
            "src/file\u034fname.c",
            "src/file\ufe0fname.c",
            "src/file\ud800name.c",
            "src/file\udc00name.c",
            "CON",
            "src/con.txt",
            "src/PRN",
            "src/AUX.c",
            "src/NUL",
            "src/COM1.log",
            "src/lpt9",
            "src/CONIN$",
            "src/CONOUT$.txt",
            "src/CLOCK$.txt",
            "src/COM\u00b9.log",
            "src/LPT\u00b2.log",
            "src /file.c",
            "src./file.c",
            "src/file.c ",
            "src/file.c.",
        ]
        for bad_path in bad_paths:
            self.reject_mutation(confirmed, lambda f: f["trace"][0].__setitem__("file", bad_path))
        self.reject_mutation(rejected, lambda f: f["evidence"][0].__setitem__("file", "NUL.txt"))
        self.reject_mutation(confirmed, lambda f: f["remediation"].__setitem__(
            "code_changes", [{"file_name": "src/file:name.c", "fixed_code": "replacement"}]))

    def test_accepts_legitimate_unicode_source_paths_and_prose(self):
        finding = confirmed()
        finding["title"] = "Finding \U0001f600 cafe\u0301"
        finding["trace"][0]["file"] = "src/日本語/cafe\u0301-\U0001f600.ts"
        finding["evidence"][0]["file"] = "src/mañana/файл.ts"
        finding["remediation"]["code_changes"] = [{
            "file_name": "src/修正/éxito.ts",
            "fixed_code": "replacement",
        }]
        self.assertEqual(errors_for([finding]), [])

    def test_cli_rejects_input_above_the_byte_limit_without_an_exception_trace(self):
        result = run_cli(b" " * (LIMITS["input_bytes"] + 1))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, f"input exceeds {LIMITS['input_bytes']} byte limit")
        self.assert_no_trace(output)

    def test_cli_rejects_invalid_utf8_without_replacement_or_an_exception_trace(self):
        findings = producer_shaped_findings()
        findings[0]["execution"]["payloads"] = ["INVALID_UTF8"]
        encoded = stringify(findings).encode()
        marker = b"INVALID_UTF8"
        marker_offset = encoded.find(marker)
        self.assertNotEqual(marker_offset, -1)
        malformed = encoded[:marker_offset] + bytes([0x80]) + encoded[marker_offset + len(marker):]

        result = run_cli(malformed)
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"input is not valid UTF-8")
        self.assert_no_trace(output, r"Traceback|TypeError|validate-findings\.py")

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "requires O_NOFOLLOW and O_NONBLOCK")
    def test_quotes_input_derived_controls_in_cli_validation_errors(self):
        finding = confirmed()
        finding["trace"][0]["kind"] = f"invalid-{TERMINAL_CONTROL_PAYLOAD}"
        finding["execution"][f"extra-{TERMINAL_CONTROL_PAYLOAD}"] = "value"
        result = run_cli(stringify([finding]))

        self.assertEqual(result.returncode, 1, cli_output(result))
        self.assertRegex(result.stderr, r"\$\[0\]\.trace\[0\]\.kind")
        self.assertRegex(result.stderr, r"\\u001b")
        self.assertRegex(result.stderr, r"\\u202e")
        self.assert_no_injected_control_bytes(result.stderr)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "requires O_NOFOLLOW and O_NONBLOCK")
    def test_returns_a_generic_syntax_error_without_parser_supplied_controls(self):
        malformed = b"[" + TERMINAL_CONTROL_PAYLOAD.encode() + b"]"
        result = run_cli(malformed)

        self.assertEqual(result.returncode, 1, cli_output(result))
        self.assertEqual(result.stderr, "Failed to parse findings JSON: invalid JSON syntax\n")
        self.assert_no_injected_control_bytes(result.stderr)

    def test_does_not_reflect_controls_from_a_failed_cli_input_path(self):
        directory = tempfile.mkdtemp(prefix="validate-findings-path-")
        missing_path = os.path.join(directory, f"missing-{TERMINAL_CONTROL_PAYLOAD}.json")
        try:
            result = spawn([VALIDATOR_PATH, missing_path])
            self.assertEqual(result.returncode, 1, cli_output(result))
            self.assertRegex(result.stderr, r"Failed to read findings JSON:")
            self.assert_no_injected_control_bytes(result.stderr)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_cli_rejects_lone_surrogate_prose_without_changing_payload_semantics(self):
        findings = producer_shaped_findings()
        findings[0]["title"] = "\ud800"
        result = run_cli(stringify(findings))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"must contain only valid Unicode scalar values")
        self.assert_no_trace(output, r"Traceback|validate-findings\.py")

    def test_cli_rejects_unicode_format_controls_in_source_paths(self):
        findings = producer_shaped_findings()
        findings[0]["trace"][0]["file"] = "src/file\u202ename.c"
        result = run_cli(stringify(findings))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"must be a safe repository-relative source path")
        self.assert_no_trace(output, r"Traceback|validate-findings\.py")

    @unittest.skipIf(sys.platform == "win32" or not HAS_SAFE_INPUT_OPEN, "requires POSIX FIFOs and safe input open")
    def test_cli_rejects_a_fifo_without_blocking(self):
        directory = tempfile.mkdtemp(prefix="validate-findings-fifo-")
        fifo_path = os.path.join(directory, "findings.json")
        try:
            os.mkfifo(fifo_path)
            result = spawn([VALIDATOR_PATH, fifo_path])
            output = cli_output(result)
            self.assertEqual(result.returncode, 1, output)
            self.assertRegex(output, r"input must be a regular file")
            self.assert_no_trace(output, r"Traceback|validate-findings\.py")
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    @unittest.skipIf(sys.platform == "win32" or not HAS_SAFE_INPUT_OPEN, "requires POSIX symlinks and safe input open")
    def test_cli_rejects_a_symlink_without_following_it(self):
        directory = tempfile.mkdtemp(prefix="validate-findings-symlink-")
        target_path = os.path.join(directory, "target.json")
        symlink_path = os.path.join(directory, "findings.json")
        try:
            with open(target_path, "w", encoding="utf-8") as handle:
                handle.write(stringify(producer_shaped_findings()))
            os.symlink(target_path, symlink_path)
            result = spawn([VALIDATOR_PATH, symlink_path])
            output = cli_output(result)
            self.assertEqual(result.returncode, 1, output)
            self.assertRegex(output, r"input must not be a symlink")
            self.assert_no_trace(output, r"Traceback|validate-findings\.py")
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_cli_rejects_input_above_the_nesting_depth_limit_without_an_exception_trace(self):
        levels = LIMITS["nesting_depth"] + 1
        result = run_cli(f"{'[' * levels}0{']' * levels}")
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, f"{LIMITS['nesting_depth']} level nesting depth limit")
        self.assert_no_trace(output)

    def test_cli_rejects_an_oversized_array_without_an_exception_trace(self):
        result = run_cli(stringify([None] * (LIMITS["array_items"] + 1)))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, f"{LIMITS['array_items']} item array limit")
        self.assert_no_trace(output)

    def test_checks_pattern_and_branch_invariants(self):
        self.reject_mutation(rejected, lambda f: f.__setitem__("fingerprint", "not stable"))
        self.reject_mutation(needs_validation, lambda f: f.__setitem__(
            "severity", {"impact": {"score": "low"}, "overall_severity": "low"}))

    def test_rejects_unsupported_and_malformed_schema_keywords(self):
        self.assertTrue(any("format" in error for error in collect_schema_errors({"type": "string", "format": "uuid"})))
        self.assertTrue(any("regular expression" in error for error in collect_schema_errors({"type": "string", "pattern": "["})))
        self.assertTrue(any("expected boolean" in error for error in collect_schema_errors({"type": "string", "visibleContent": "yes"})))
        self.assertTrue(any("requires type" in error for error in collect_schema_errors({"type": "array", "visibleContent": True})))
        self.assertNotEqual(len(validate_document([], {"type": "array", "maxItems": 1})), 0)

    def test_caps_malformed_1000_finding_validation_output(self):
        self.assertEqual(len(errors_for([None] * LIMITS["array_items"])), LIMITS["validation_errors"])
        if not HAS_SAFE_INPUT_OPEN:
            return

        result = run_cli(stringify([None] * LIMITS["array_items"]))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"output capped at 100")
        self.assertLess(len(output), 20000, f"unexpected output length {len(output)}")
        self.assert_no_trace(output, r"Traceback|RecursionError|validate-findings\.py")

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "requires O_NOFOLLOW and O_NONBLOCK")
    def test_caps_amplified_in_limit_findings_output(self):
        # The Node suite also capped the V8 heap at 64 MiB for this run;
        # CPython has no portable equivalent, so only time and output are bounded.
        findings = [{
            "verdict": "confirmed",
            "trace": [0] * LIMITS["array_items"],
            "evidence": [0] * LIMITS["array_items"],
        } for _ in range(750)]
        contents = stringify(findings)
        self.assertGreater(len(contents), 3 * 1000 * 1000, f"hostile input too small: {len(contents)}")
        self.assertLessEqual(len(contents), LIMITS["input_bytes"], f"hostile input over limit: {len(contents)}")

        result = run_cli(contents, timeout=HOSTILE_CLI_TIMEOUT)
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"output capped at 100")
        self.assertLess(len(output), 20000, f"unexpected output length {len(output)}")
        self.assert_no_trace(output, r"Traceback|MemoryError|RecursionError")

    def test_keeps_shared_helpers_aligned_with_the_coverage_ledger_validator(self):
        ledger_module = load_module("validate_coverage_ledger", LEDGER_VALIDATOR_PATH)

        for name in [
            "WHITE_SPACE",
            "DEFAULT_IGNORABLE_CODE_POINTS",
            "VISIBLE_CONTENT_CATEGORIES",
            "PATH_FORBIDDEN_CATEGORIES",
            "UNSAFE_DIAGNOSTIC_CATEGORIES",
            "JS_WHITESPACE",
        ]:
            self.assertEqual(getattr(findings_module, name), getattr(ledger_module, name), name)
        for name in ["WINDOWS_RESERVED_COMPONENT"]:
            self.assertEqual(getattr(findings_module, name).pattern, getattr(ledger_module, name).pattern, f"{name} source")
            self.assertEqual(getattr(findings_module, name).flags, getattr(ledger_module, name).flags, f"{name} flags")
        for name in [
            "is_visible_character",
            "is_path_forbidden_character",
            "is_unsafe_diagnostic_character",
            "has_visible_prose",
        ]:
            self.assertEqual(inspect.getsource(getattr(findings_module, name)),
                             inspect.getsource(getattr(ledger_module, name)), f"{name} source")

        shared_limit_keys = sorted(key for key in findings_module.LIMITS if key in ledger_module.LIMITS)
        self.assertEqual(shared_limit_keys, ["input_bytes", "nesting_depth", "validation_errors"])
        for key in shared_limit_keys:
            self.assertEqual(findings_module.LIMITS[key], ledger_module.LIMITS[key], f"LIMITS.{key}")

        path_corpus = [
            "src/handler.js",
            "src/caf\u00e9/handler.js",
            "src/\u65e5\u672c\u8a9e/\u0444\u0430\u0439\u043b.ts",
            "src/cloc\u212a$.txt",
            "src/CLOCK$.txt",
            "src/con.txt",
            "CON",
            "src/COM\u00b9.log",
            "src/lpt\u00b3",
            "/etc/passwd",
            "../src/file.c",
            "src/../file.c",
            "src//file.c",
            "src\\file.c",
            "src/file:name.c",
            "~home/file.c",
            "C:/file.c",
            "src/file.c ",
            "src/file.c.",
            "src/file\u202ename.c",
            "src/file\u200b.js",
            "src/file\u034f.js",
            "src/file\ufe0f.js",
            "src/file\ud800name.c",
            "src/file\udc00name.c",
        ]
        for value in path_corpus:
            self.assertEqual(
                findings_module.is_safe_relative_source_path(value),
                ledger_module.is_safe_relative_path(value),
                f"path verdict diverges for {value!r}",
            )
        self.assertFalse(findings_module.is_safe_relative_source_path("src/cloc\u212a$.txt"))
        self.assertFalse(ledger_module.is_safe_relative_path("src/cloc\u212a$.txt"))

        prose_corpus = [
            "Valid prose.",
            "caf\u00e9",
            "",
            " \t\r\n",
            "\u200b",
            "\u034f",
            "\ufe0f",
            "\ud800",
            "\udc00",
            "visible\ud800",
        ]
        for value in prose_corpus:
            self.assertEqual(
                findings_module.has_visible_prose(value),
                ledger_module.has_visible_prose(value),
                f"prose verdict diverges for {value!r}",
            )


if __name__ == "__main__":
    unittest.main()
