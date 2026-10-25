#!/usr/bin/env python3

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATOR_PATH = os.path.join(HERE, "validate-coverage-ledger.py")

_spec = importlib.util.spec_from_file_location("validate_coverage_ledger", VALIDATOR_PATH)
ledger_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ledger_module)
LIMITS = ledger_module.LIMITS
canonical_coverage_id = ledger_module.canonical_coverage_id
encode_canonical_ref = ledger_module.encode_canonical_ref
is_safe_agent_id = ledger_module.is_safe_agent_id
is_safe_relative_path = ledger_module.is_safe_relative_path
preflight_json_text = ledger_module.preflight_json_text
validate_document = ledger_module.validate_document

CLI_TIMEOUT = 5
HOSTILE_CLI_TIMEOUT = 15
HAS_SAFE_INPUT_OPEN = bool(getattr(os, "O_NOFOLLOW", 0)) and bool(getattr(os, "O_NONBLOCK", 0))
LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def stringify(value):
    """JSON.stringify: compact, raw non-ASCII, lone surrogates escaped."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return LONE_SURROGATE.sub(lambda match: f"\\u{ord(match.group()):04x}", text)


def unit(**overrides):
    canonical_refs = overrides.get("canonical_refs") or {
        "surface": "src/router.ts#POST /users/:id",
        "boundary": "src/authz.ts#requireOwner",
        "subsystem": "packages/api",
        "attack_class": "ATTACK-CLASSES.md#Access control",
    }
    value = {
        "coverage_id": canonical_coverage_id(canonical_refs),
        "canonical_refs": canonical_refs,
        "surface": "Update-user route",
        "boundary": "Object ownership",
        "subsystem": "API",
        "attack_class": "Access control",
        "starting_paths": ["src/router.ts", "src/authz.ts"],
        "ordinary_attack_class_block": "ATTACK-CLASSES.md#Access control",
        "selected_companion_blocks": [],
        "excluded_blocks": [{"block": "WEB-PROTOCOL-AND-AUTH.md#Cache behavior", "reason": "The route is not cached."}],
        "prior_status": "new",
        "attempts": [],
        "wave": 1,
        "status": "planned",
        "agent_id": None,
        "reviewed_paths": [],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": [],
    }
    value.update(overrides)
    value["canonical_refs"] = canonical_refs
    return value


def errors_for(value):
    return validate_document(value)


def spawn(args, timeout=CLI_TIMEOUT):
    return subprocess.run([sys.executable, *args], capture_output=True, encoding="utf-8", timeout=timeout)


def run_cli(contents, timeout=CLI_TIMEOUT):
    directory = tempfile.mkdtemp(prefix="validate-coverage-ledger-")
    ledger_path = os.path.join(directory, "coverage-ledger.json")
    try:
        with open(ledger_path, "wb") as handle:
            handle.write(contents.encode() if isinstance(contents, str) else contents)
        return spawn([VALIDATOR_PATH, ledger_path], timeout)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def cli_output(result):
    return f"{result.stdout}{result.stderr}"


TERMINAL_CONTROL_PAYLOAD = "\u001b\u0007\u0085\u202e"
TERMINAL_CONTROL_BYTES = [
    bytes([0x1B]),
    bytes([0x07]),
    "\u0085".encode(),
    "\u202e".encode(),
]


def source_check(agent_id="hunter-1", **overrides):
    return {
        "agent_id": agent_id,
        "reviewed_paths": ["src/router.ts"],
        "invariant": "The route checks object ownership.",
        "method": "source",
        "result": "The owner check applies before the update.",
        "artifact": None,
        **overrides,
    }


def local_check(agent_id="hunter-1", **overrides):
    return source_check(agent_id, **{
        "method": "local",
        "result": "The bounded fixture accepted the other owner's object.",
        "artifact": f"agents/{agent_id}/artifacts/result.txt",
        **overrides,
    })


def archived_attempt(**overrides):
    value = {
        "wave": 1,
        "status": "blocked",
        "agent_id": "hunter-1",
        "reviewed_paths": ["src/router.ts"],
        "local_checks": [source_check()],
        "result_fingerprints": [],
        "unresolved": ["The deployed policy is unavailable."],
        "reassignment_reason": "The critic found an unchecked parallel path.",
    }
    value.update(overrides)
    return value


def has_error(errors, text):
    return any(text in error for error in errors)


class CoverageLedgerValidatorTest(unittest.TestCase):
    def assert_no_injected_control_bytes(self, output):
        data = output if isinstance(output, bytes) else output.encode("utf-8", "surrogatepass")
        for marker in TERMINAL_CONTROL_BYTES:
            self.assertEqual(data.find(marker), -1, f"found raw control bytes {marker.hex()}")

    def assert_no_trace(self, output, pattern=r"Traceback|RecursionError|MemoryError|validate-coverage-ledger\.py"):
        self.assertIsNone(re.search(pattern, output, re.IGNORECASE), output)

    def test_accepts_an_empty_ledger_and_complete_units(self):
        self.assertEqual(errors_for([]), [])
        self.assertEqual(errors_for([unit()]), [])

        missing_attempts = unit()
        del missing_attempts["attempts"]
        self.assertTrue(has_error(errors_for([missing_attempts]), 'missing required field "attempts"'))

        covered = unit(
            status="covered",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check()],
        )
        self.assertEqual(errors_for([covered]), [])

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "requires O_NOFOLLOW and O_NONBLOCK")
    def test_accepts_a_complete_ledger_through_the_cli(self):
        result = run_cli(stringify([unit()]))
        self.assertEqual(result.returncode, 0, cli_output(result))
        self.assertRegex(result.stdout, r"PASS: 1 coverage units valid")

    def test_text_preflight_ignores_structural_characters_and_escapes_inside_strings(self):
        value = unit(
            surface='Route \\ slash [list] {object}, colon: quoted "value"',
            excluded_blocks=[{
                "block": "COMPANION.md#Literal [brackets] {braces}",
                "reason": 'The text contains a backslash \\ before an escaped "quote".',
            }],
        )
        contents = stringify([value])
        preflight_json_text(contents)
        self.assertEqual(json.loads(contents), [value])
        if HAS_SAFE_INPUT_OPEN:
            result = run_cli(contents)
            self.assertEqual(result.returncode, 0, cli_output(result))

    def test_text_preflight_enforces_structural_cardinality_limits(self):
        depth_limit = LIMITS["nesting_depth"]
        preflight_json_text(f"{'[' * depth_limit}0{']' * depth_limit}")
        with self.assertRaisesRegex(Exception, r"exceeds nesting depth limit 64"):
            preflight_json_text(f"{'[' * (depth_limit + 1)}0{']' * (depth_limit + 1)}")

        too_many_units = f"[{'null,' * LIMITS['units']}null]"
        with self.assertRaisesRegex(Exception, r"exceeds 10000 top-level unit limit"):
            preflight_json_text(too_many_units)

        too_many_items = f"[[{'null,' * LIMITS['collection_items']}null]]"
        with self.assertRaisesRegex(Exception, r"exceeds 1000 item array limit"):
            preflight_json_text(too_many_items)

        object_fields = ",".join(f'"field{index}":null' for index in range(LIMITS["object_fields"] + 1))
        with self.assertRaisesRegex(Exception, r"exceeds 1000 field object limit"):
            preflight_json_text(f"[{{{object_fields}}}]")

        full_array = f"[{'null,' * (LIMITS['collection_items'] - 1)}null]"
        arrays_needed = LIMITS["preflight_values"] // (LIMITS["collection_items"] + 1) + 1
        too_many_values = "[" + ",".join([full_array] * arrays_needed) + "]"
        with self.assertRaisesRegex(Exception, r"exceeds 500000 total value limit"):
            preflight_json_text(too_many_values)

    def test_text_preflight_rejects_malformed_structural_truncation_cleanly(self):
        with self.assertRaisesRegex(Exception, r"truncated JSON structure"):
            preflight_json_text("[")
        with self.assertRaisesRegex(Exception, r"unterminated JSON string"):
            preflight_json_text('["unterminated')
        with self.assertRaisesRegex(Exception, r"mismatched JSON containers"):
            preflight_json_text('[{"field":1]')

    def test_derives_collision_free_canonical_ids_from_exact_utf8_references(self):
        self.assertEqual(encode_canonical_ref("route:POST /users"), "route%3APOST%20%2Fusers")
        self.assertNotEqual(encode_canonical_ref("route name"), encode_canonical_ref("route-name"))
        self.assertEqual(
            canonical_coverage_id({"surface": "a", "boundary": "b", "subsystem": "c", "attack_class": "d", "lifecycle": "retry"}),
            "a::b::c::d::retry",
        )
        for invalid in ["e\u0301", "bad\u0000ref", "hidden\u200bref"]:
            with self.assertRaisesRegex(TypeError, r"invalid canonical reference"):
                encode_canonical_ref(invalid)

    def test_rejects_noncanonical_duplicate_and_colliding_ids(self):
        wrong = unit(coverage_id="display-label-slug")
        self.assertTrue(has_error(errors_for([wrong]), "expected canonical ID"))

        duplicate = unit()
        self.assertTrue(has_error(errors_for([duplicate, unit()]), "duplicate coverage ID"))

        collision = unit()
        different_meaning = unit(surface="Delete-user route")
        self.assertTrue(has_error(errors_for([collision, different_meaning]), "canonical identity collision"))

    def test_requires_canonical_references_to_be_own_properties(self):
        # A JavaScript object can inherit the references through its prototype;
        # a Python dict has no prototype chain, so its own properties are empty.
        value = unit()
        value["canonical_refs"] = {}
        self.assertTrue(has_error(errors_for([value]), "missing required field"))

    def test_rejects_aliases_for_one_semantic_tuple(self):
        first = unit()
        refs = {**first["canonical_refs"], "surface": "src/alias.ts#updateUser"}
        alias = unit(canonical_refs=refs)
        ledger = sorted([first, alias], key=lambda entry: entry["coverage_id"])
        self.assertTrue(has_error(errors_for(ledger), "semantic tuple already uses coverage ID"))

    def test_requires_lexicographic_order(self):
        second_refs = {
            "surface": "zzz",
            "boundary": "src/authz.ts#requireOwner",
            "subsystem": "packages/api",
            "attack_class": "ATTACK-CLASSES.md#Access control",
        }
        self.assertTrue(has_error(errors_for([unit(canonical_refs=second_refs), unit()]), "sorted lexicographically"))

    def test_validates_assignment_block_maps(self):
        overlap = unit(
            selected_companion_blocks=["AI-AND-LLM.md#Tool calls"],
            excluded_blocks=[{"block": "AI-AND-LLM.md#Tool calls", "reason": "Claimed irrelevant."}],
        )
        self.assertTrue(has_error(errors_for([overlap]), "also selected"))

        no_reason = unit(excluded_blocks=[{"block": "AI-AND-LLM.md#Tool calls", "reason": ""}])
        self.assertTrue(has_error(errors_for([no_reason]), "reason"))

    def test_requires_owned_artifacts_for_local_checks_and_null_artifacts_for_source_checks(self):
        local = unit(
            status="covered",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[local_check()],
        )
        self.assertEqual(errors_for([local]), [])

        independently_verified = unit(
            status="covered",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts", "src/authz.ts"],
            local_checks=[source_check(), local_check("verifier-1", reviewed_paths=["src/authz.ts"])],
        )
        self.assertEqual(errors_for([independently_verified]), [])

        unowned_path = unit(
            status="covered",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts", "src/authz.ts"],
            local_checks=[source_check()],
        )
        self.assertTrue(has_error(errors_for([unowned_path]), "has no check owner"))

        for check_agent_id, artifact in [
            (None, "agents/hunter-1/artifacts/result.txt"),
            ("hunter-1", None),
            ("hunter-1", "result.txt"),
            ("hunter-1", "agents/hunter-2/artifacts/result.txt"),
            ("../hunter", "agents/../hunter/artifacts/result.txt"),
        ]:
            value = unit(
                status="covered",
                agent_id="hunter-1",
                reviewed_paths=["src/router.ts"],
                local_checks=[local_check(check_agent_id, artifact=artifact)],
            )
            self.assertNotEqual(len(errors_for([value])), 0, f"{check_agent_id}: {artifact}")

        unowned_source = unit(
            status="blocked",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check()],
            unresolved=["The boundary behavior is not source-visible."],
        )
        self.assertTrue(has_error(errors_for([unowned_source]),
                                  'unit with status "blocked" requires a canonical lowercase agent ID'))

        source_with_artifact = unit(
            status="covered",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check("hunter-1", artifact="agents/hunter-1/artifacts/source.txt")],
        )
        self.assertTrue(has_error(errors_for([source_with_artifact]), "source-only check must use null"))

    def test_requires_canonical_lowercase_filesystem_safe_agent_ids(self):
        for value in ["hunter-1", "verifier_2", "a0"]:
            self.assertIs(is_safe_agent_id(value), True, value)
        for value in ["Hunter-1", "hunter.1", "hunter-1.", "hunter ", "con", "prn", "aux", "nul", "com1", "lpt9", "../hunter"]:
            self.assertIs(is_safe_agent_id(value), False, value)

        case_alias = unit(status="in_progress", agent_id="Hunter-1")
        self.assertTrue(has_error(errors_for([case_alias]), "canonical lowercase agent ID"))

    def test_enforces_state_evidence(self):
        self.assertTrue(has_error(errors_for([unit(status="in_progress")]), 'unit with status "in_progress" requires'))
        self.assertTrue(has_error(errors_for([unit(status="blocked")]), "unresolved"))
        self.assertTrue(has_error(errors_for([unit(status="candidate")]), "reviewed_paths"))

        self.assertEqual(errors_for([unit(status="in_progress", agent_id="hunter-1")]), [])
        in_progress_evidence = unit(
            status="in_progress",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check()],
        )
        self.assertTrue(has_error(errors_for([in_progress_evidence]), "must keep this array empty"))

        assigned_planned = unit(
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check()],
        )
        self.assertTrue(has_error(errors_for([assigned_planned]), "planned unit must be unassigned"))

        candidate = unit(
            status="candidate",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check("hunter-1", invariant="Ownership is required.", result="No check exists.")],
            result_fingerprints=["src-router-missing-owner-check"],
            unresolved=["validation_budget_exhausted"],
        )
        self.assertEqual(errors_for([candidate]), [])

        blocked = unit(
            status="blocked",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check()],
            unresolved=["The deployed policy is unavailable."],
        )
        self.assertEqual(errors_for([blocked]), [])
        blocked_fingerprint = {**blocked, "result_fingerprints": ["forbidden-fingerprint"]}
        self.assertTrue(has_error(errors_for([blocked_fingerprint]), "result_fingerprints"))

        for status in ["not_applicable", "out_of_scope", "deferred"]:
            self.assertEqual(errors_for([unit(status=status, unresolved=["Reason recorded."])]), [])
            invalid = unit(
                status=status,
                agent_id="hunter-1",
                reviewed_paths=["src/router.ts"],
                local_checks=[source_check()],
                result_fingerprints=["forbidden-fingerprint"],
                unresolved=["Reason recorded."],
            )
            errors = errors_for([invalid])
            self.assertTrue(has_error(errors, "must be unassigned"), status)
            self.assertTrue(has_error(errors, "reviewed_paths"), status)
            self.assertTrue(has_error(errors, "result_fingerprints"), status)

        covered_fingerprint = unit(
            status="covered",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check()],
            result_fingerprints=["forbidden-fingerprint"],
        )
        self.assertTrue(has_error(errors_for([covered_fingerprint]), "result_fingerprints"))

        covered_unresolved = unit(
            status="covered",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check()],
            unresolved=["Unexpected unresolved claim."],
        )
        self.assertTrue(has_error(errors_for([covered_unresolved]), "unresolved"))

    def test_archives_prior_evidence_when_a_critic_assigns_a_fresh_owner(self):
        reassigned = unit(
            attempts=[archived_attempt()],
            wave=2,
            status="in_progress",
            agent_id="hunter-2",
        )
        self.assertEqual(errors_for([reassigned]), [])

        final_closure = unit(
            attempts=[archived_attempt()],
            wave=2,
            status="covered",
            agent_id="hunter-2",
            reviewed_paths=["src/authz.ts"],
            local_checks=[source_check("hunter-2", reviewed_paths=["src/authz.ts"])],
        )
        self.assertEqual(errors_for([final_closure]), [])

    def test_preserves_candidate_provenance_when_reassignment_must_be_deferred(self):
        candidate_attempt = archived_attempt(
            status="candidate",
            result_fingerprints=["src-router-missing-owner-check"],
            unresolved=["validation_budget_exhausted"],
        )
        deferred = unit(
            attempts=[candidate_attempt],
            wave=2,
            status="deferred",
            unresolved=["quick_profile_final_critic"],
        )
        self.assertEqual(errors_for([deferred]), [])

    def test_rejects_reassignment_owner_reuse_and_evidence_mixing(self):
        reused_owner = unit(
            attempts=[archived_attempt()],
            wave=2,
            status="in_progress",
            agent_id="hunter-1",
        )
        self.assertTrue(has_error(errors_for([reused_owner]), "current assignment owner must be fresh"))

        mixed_evidence = unit(
            attempts=[archived_attempt(local_checks=[local_check()])],
            wave=2,
            status="covered",
            agent_id="hunter-2",
            reviewed_paths=["src/router.ts"],
            local_checks=[local_check()],
        )
        errors = errors_for([mixed_evidence])
        self.assertTrue(has_error(errors, "prior assignment owner evidence must remain"))
        self.assertTrue(has_error(errors, "artifact from an archived attempt cannot be reused"))

        mixed_history = unit(
            attempts=[
                archived_attempt(local_checks=[local_check()]),
                archived_attempt(
                    wave=2,
                    agent_id="hunter-2",
                    local_checks=[local_check()],
                ),
            ],
            wave=3,
            status="in_progress",
            agent_id="hunter-3",
        )
        history_errors = errors_for([mixed_history])
        self.assertTrue(has_error(history_errors, "prior assignment owner evidence must remain in its earlier attempt"))
        self.assertTrue(has_error(history_errors, "artifact from an earlier attempt cannot be reused"))

        unordered = unit(
            attempts=[archived_attempt(), archived_attempt(
                wave=1,
                agent_id="hunter-2",
                local_checks=[source_check("hunter-2")],
            )],
            wave=3,
            status="in_progress",
            agent_id="hunter-3",
        )
        self.assertTrue(has_error(errors_for([unordered]), "strictly increasing"))

    def test_rejects_unsafe_paths_and_malformed_fingerprints(self):
        for value in [
            "/etc/passwd",
            "../src/file.js",
            "src/../file.js",
            "src/con.txt",
            "src/PRN",
            "src/AUX.c",
            "src/NUL",
            "src/CLOCK$.txt",
            "src/conin$.txt",
            "src/conout$",
            "src/COM1.log",
            "src/lpt9",
            "src/COM\u00b9.log",
            "src/COM\u00b2.log",
            "src/COM\u00b3.log",
            "src/lpt\u00b9",
            "src/lpt\u00b2",
            "src/lpt\u00b3",
            "src/file.js.",
            "C:/src/file.js",
            "src/file\n.js",
            "src/file\u0085.js",
            "src/file\u2028.js",
            "src/file\u200b.js",
            "src/file\u034f.js",
            "src/file\ufe0f.js",
        ]:
            self.assertIs(is_safe_relative_path(value), False, repr(value))
        self.assertIs(is_safe_relative_path("src/handler.js"), True)
        self.assertIs(is_safe_relative_path("src/caf\u00e9/handler.js"), True)
        self.assertTrue(has_error(errors_for([unit(starting_paths=["../src/router.ts"])]), "repository-relative path"))
        self.assertTrue(has_error(errors_for([unit(
            status="candidate",
            agent_id="hunter-1",
            reviewed_paths=["src/router.ts"],
            local_checks=[source_check("hunter-1", invariant="Ownership is required.", result="No check exists.")],
            result_fingerprints=["not stable"],
        )]), "invalid fingerprint"))

    def test_rejects_format_default_ignorable_and_invalid_scalar_prose(self):
        for invisible in ["\u200b", "\u034f", "\ufe0f", "\ud800"]:
            self.assertTrue(has_error(errors_for([unit(surface=invisible)]), "surface"), repr(invisible))
            self.assertTrue(has_error(errors_for([unit(
                excluded_blocks=[{"block": "ATTACK-CLASSES.md#Access control", "reason": invisible}],
            )]), "reason"), repr(invisible))

    def test_quotes_input_derived_controls_in_direct_validation_errors(self):
        invalid_status = f"invalid-{TERMINAL_CONTROL_PAYLOAD}"
        invalid_path = f"src/{TERMINAL_CONTROL_PAYLOAD}.js"
        value = unit(
            status=invalid_status,
            agent_id="hunter-1",
            reviewed_paths=[invalid_path],
            local_checks=[source_check()],
            result_fingerprints=["force-state-error"],
        )
        output = "\n".join(errors_for([value]))

        self.assertRegex(output, r"\$\[0\]\.status")
        self.assertRegex(output, r"\$\[0\]\.reviewed_paths")
        self.assertRegex(output, r"\\u001b")
        self.assertRegex(output, r"\\u0007")
        self.assertRegex(output, r"\\u0085")
        self.assertRegex(output, r"\\u202e")
        self.assert_no_injected_control_bytes(output)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "requires O_NOFOLLOW and O_NONBLOCK")
    def test_quotes_input_derived_controls_in_cli_validation_errors(self):
        value = unit(
            status=f"invalid-{TERMINAL_CONTROL_PAYLOAD}",
            result_fingerprints=["force-state-error"],
        )
        result = run_cli(stringify([value]))

        self.assertEqual(result.returncode, 1, cli_output(result))
        self.assertRegex(result.stderr, r"\$\[0\]\.status")
        self.assertRegex(result.stderr, r"\\u001b")
        self.assert_no_injected_control_bytes(result.stderr)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "requires O_NOFOLLOW and O_NONBLOCK")
    def test_returns_a_generic_syntax_error_without_parser_supplied_controls(self):
        malformed = b"[" + TERMINAL_CONTROL_PAYLOAD.encode() + b"]"
        result = run_cli(malformed)

        self.assertEqual(result.returncode, 1, cli_output(result))
        self.assertEqual(result.stderr, "Failed to parse coverage ledger: invalid JSON syntax\n")
        self.assert_no_injected_control_bytes(result.stderr)

    def test_does_not_reflect_controls_from_a_failed_cli_input_path(self):
        directory = tempfile.mkdtemp(prefix="validate-coverage-ledger-path-")
        missing_path = os.path.join(directory, f"missing-{TERMINAL_CONTROL_PAYLOAD}.json")
        try:
            result = spawn([VALIDATOR_PATH, missing_path])
            self.assertEqual(result.returncode, 1, cli_output(result))
            self.assertRegex(result.stderr, r"Failed to read coverage ledger:")
            self.assert_no_injected_control_bytes(result.stderr)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "requires O_NOFOLLOW and O_NONBLOCK")
    def test_rejects_invalid_utf8_through_the_cli(self):
        encoded = stringify([unit()]).encode()
        marker = b"Update-user route"
        marker_offset = encoded.find(marker)
        self.assertNotEqual(marker_offset, -1)
        malformed = encoded[:marker_offset] + bytes([0x80]) + encoded[marker_offset + len(marker):]

        result = run_cli(malformed)
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"input is not valid UTF-8")
        self.assert_no_trace(output, r"Traceback|TypeError|validate-coverage-ledger\.py")

    @unittest.skipIf(sys.platform == "win32" or not HAS_SAFE_INPUT_OPEN, "requires POSIX FIFOs and safe input open")
    def test_rejects_a_fifo_through_the_cli_without_blocking(self):
        directory = tempfile.mkdtemp(prefix="validate-coverage-ledger-fifo-")
        fifo_path = os.path.join(directory, "coverage-ledger.json")
        try:
            os.mkfifo(fifo_path)
            result = spawn([VALIDATOR_PATH, fifo_path])
            output = cli_output(result)
            self.assertEqual(result.returncode, 1, output)
            self.assertRegex(output, r"input must be a regular file")
            self.assert_no_trace(output)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    @unittest.skipIf(sys.platform == "win32" or not HAS_SAFE_INPUT_OPEN, "requires POSIX symlinks and safe input open")
    def test_rejects_a_symlink_through_the_cli(self):
        directory = tempfile.mkdtemp(prefix="validate-coverage-ledger-symlink-")
        target_path = os.path.join(directory, "target.json")
        symlink_path = os.path.join(directory, "coverage-ledger.json")
        try:
            with open(target_path, "w", encoding="utf-8") as handle:
                handle.write(stringify([unit()]))
            os.symlink(target_path, symlink_path)
            result = spawn([VALIDATOR_PATH, symlink_path])
            output = cli_output(result)
            self.assertEqual(result.returncode, 1, output)
            self.assertRegex(output, r"input must not be a symlink")
            self.assert_no_trace(output)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_rejects_deeply_nested_input_without_recursion_failure(self):
        nested = 0
        for _ in range(20000):
            nested = [nested]
        self.assertTrue(has_error(errors_for(nested), "exceeds nesting depth limit 64"))
        if not HAS_SAFE_INPUT_OPEN:
            return

        result = run_cli(f"{'[' * 20000}0{']' * 20000}")
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"exceeds nesting depth limit 64")
        self.assert_no_trace(output)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "requires O_NOFOLLOW and O_NONBLOCK")
    def test_rejects_multi_megabyte_nesting(self):
        # The Node suite also capped the V8 heap at 64 MiB for these runs;
        # CPython has no portable equivalent, so only time and output are bounded.
        open_containers = "[" * 2000000
        cases = [
            open_containers,
            f"{open_containers}0{']' * 2000000}",
        ]
        for contents in cases:
            result = run_cli(contents, timeout=HOSTILE_CLI_TIMEOUT)
            output = cli_output(result)
            self.assertEqual(result.returncode, 1, output)
            self.assertRegex(output, r"exceeds nesting depth limit 64")
            self.assert_no_trace(output)

    def test_caps_malformed_10000_unit_validation_output(self):
        self.assertEqual(len(errors_for([None] * LIMITS["units"])), LIMITS["validation_errors"])
        if not HAS_SAFE_INPUT_OPEN:
            return

        result = run_cli(stringify([None] * LIMITS["units"]))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"output capped at 100")
        self.assertLess(len(output), 20000, f"unexpected output length {len(output)}")
        self.assert_no_trace(output)

    def test_rejects_malformed_top_level_data_and_excessive_unit_counts(self):
        self.assertEqual(errors_for({"units": []}), ["$: expected a top-level array"])
        too_many = [None] * 10001
        self.assertEqual(errors_for(too_many), ["$: exceeds 10000 coverage units"])

        oversized_collection = unit(extra=[None] * (LIMITS["collection_items"] + 1))
        self.assertTrue(has_error(errors_for([oversized_collection]), "exceeds 1000 entries"))

    def test_accepts_a_canonical_id_derived_from_near_maximum_multibyte_references(self):
        canonical_refs = {
            "surface": "\u6f22" * 1024,
            "boundary": "\u00e9" * 1024,
            "subsystem": "packages/api",
            "attack_class": "\u6f22" * 1023 + "\u00e9",
        }
        value = unit(canonical_refs=canonical_refs)
        self.assertGreater(len(value["coverage_id"]), 16384, f"coverage_id length {len(value['coverage_id'])}")
        self.assertLessEqual(len(value["coverage_id"]), 65536, f"coverage_id length {len(value['coverage_id'])}")
        self.assertEqual(errors_for([value]), [])

        if HAS_SAFE_INPUT_OPEN:
            result = run_cli(stringify([value]))
            self.assertEqual(result.returncode, 0, cli_output(result))


if __name__ == "__main__":
    unittest.main()
