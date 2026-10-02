"""Offline regression of evidence decisions; synthetic files only, no target traffic."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check_claim


class ClaimPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.case = self.root / "case"
        self.case.mkdir()
        data = b'{"observation": "synthetic fixture, not an exploit"}\n'
        (self.case / "raw.json").write_bytes(data)
        self.evidence = {
            "id": "raw", "path": "raw.json", "sha256": hashlib.sha256(data).hexdigest(),
            "scope": "current", "context_id": "test-environment", "complete": True,
            "form": "raw", "locator": {"json_pointer": "/observation"},
        }
        self.claim = {
            "schema_version": 2, "claim_id": "fixture", "statement": "Synthetic review claim",
            "kind": "other", "mode": "current", "disposition": "confirmed",
            "claims_current_exploit": True, "owner": "worker", "context_id": "test-environment",
            "origin": {"hint_level": "none", "independent_discovery": False},
            "evidence": [copy.deepcopy(self.evidence)],
            "checks": {name: {"result": "supported", "refs": ["raw"]} for name in
                       ("contract", "baseline", "mapping", "effect", "control", "impact", "alternatives")},
            "progress": {"no_new_information_rounds": 0, "next_action": "review", "changed_prerequisite_refs": []},
            "state_changed": False,
            "review": {"reviewer": "reviewer", "mode": "offline", "refs": ["raw"]},
            "hypothesis": {name: "Synthetic documented criterion" for name in
                           ("constraint", "failure_boundary", "minimal_observation", "negative_control", "falsifier", "evidence_threshold")},
            "contradictions": [],
            "assessment": {"demonstrated_capability": "Synthetic capability",
                           "affected_objects": "Synthetic objects only", "preconditions": "Fixture only",
                           "severity_basis": "Unrated local test fixture", "severity": "unrated", "refs": ["raw"]},
        }
        self.claim["hypothesis"]["refs"] = ["raw"]

    def tearDown(self):
        self.temp.cleanup()

    def valid(self, claim=None):
        return check_claim.validate(claim or self.claim, self.case)

    def rejected(self, code):
        with self.assertRaisesRegex(check_claim.Invalid, "^" + code.replace(".", r"\.") + "$"):
            self.valid()

    def add_evidence(self, eid="review-only", **changes):
        item = copy.deepcopy(self.evidence)
        item.update(id=eid, **changes)
        self.claim["evidence"].append(item)
        return item

    def test_metadata_success_does_not_prove_vulnerability(self):
        self.assertFalse(self.valid()["proves_vulnerability"])

    def test_legacy_schema_one_still_readable(self):
        self.claim["schema_version"] = 1
        for field in ("hypothesis", "contradictions", "assessment"):
            del self.claim[field]
        self.assertEqual(self.valid()["disposition"], "confirmed")

    def test_missing_prerequisites_can_remain_candidate(self):
        self.claim.update(disposition="candidate", claims_current_exploit=False)
        self.claim["progress"]["next_action"] = "restore_prerequisite"
        for field in self.claim["hypothesis"]:
            self.claim["hypothesis"][field] = [] if field == "refs" else None
        self.assertEqual(self.valid()["disposition"], "candidate")

    def test_probe_requires_actual_hypothesis_criteria(self):
        self.claim.update(disposition="candidate", claims_current_exploit=False)
        self.claim["progress"]["next_action"] = "probe"
        self.claim["hypothesis"]["negative_control"] = None
        self.rejected("hypothesis.negative_control")

    def test_hypothesis_requires_source_for_confirmation(self):
        self.claim["hypothesis"]["refs"] = []
        self.rejected("refs.list")

    def test_hypothesis_cannot_use_another_context(self):
        self.add_evidence("other", context_id="different-environment")
        self.claim["hypothesis"]["refs"] = ["other"]
        self.rejected("hypothesis.evidence.context")

    def test_unresolved_counterevidence_blocks_confirmation(self):
        self.claim["contradictions"] = [{"id": "c1", "refs": ["raw"], "resolution": "unresolved"}]
        self.rejected("contradiction.unresolved")

    def test_candidate_retains_unresolved_counterevidence(self):
        self.claim.update(disposition="candidate", claims_current_exploit=False)
        self.claim["contradictions"] = [{"id": "c1", "refs": ["raw"], "resolution": "unresolved"}]
        self.assertEqual(self.valid()["disposition"], "candidate")

    def test_declared_contradicted_check_blocks_confirmation(self):
        self.claim["checks"]["unexpected_side_effect"] = {"result": "contradicted", "refs": ["raw"]}
        self.rejected("check.unresolved_contradiction")

    def test_optional_supported_check_cannot_use_truncated_material(self):
        self.add_evidence("partial", complete=False)
        self.claim["checks"]["business_rule"] = {"result": "supported", "refs": ["partial"]}
        self.rejected("check.evidence.incomplete")

    def test_optional_supported_check_cannot_hide_truncated_ancestor(self):
        self.add_evidence("partial", complete=False)
        self.add_evidence("summary", form="derived", derived_from=["partial"])
        self.claim["checks"]["business_rule"] = {"result": "supported", "refs": ["summary"]}
        self.rejected("check.evidence.incomplete")

    def test_optional_supported_check_cannot_mix_environment(self):
        self.add_evidence("other", context_id="different-environment")
        self.claim["checks"]["business_rule"] = {"result": "supported", "refs": ["other"]}
        self.rejected("check.evidence.context")

    def test_counterevidence_resolution_needs_actual_material(self):
        self.claim["contradictions"] = [{"id": "c1", "refs": ["raw"], "resolution": "explained",
                                          "reason": "Synthetic explanation", "resolution_refs": []}]
        self.rejected("refs.list")

    def test_resolved_counterevidence_retains_original_reference(self):
        self.claim["contradictions"] = [{"id": "c1", "refs": ["raw"], "resolution": "explained",
                                          "reason": "Synthetic explanation", "resolution_refs": ["raw"]}]
        self.assertEqual(self.valid()["status"], "eligible_for_semantic_review")

    def test_resolution_cannot_erase_incomplete_ancestor(self):
        self.add_evidence("partial", complete=False)
        self.add_evidence("summary", form="derived", derived_from=["partial"])
        self.claim["contradictions"] = [{"id": "c1", "refs": ["raw"], "resolution": "refuted",
                                          "reason": "Synthetic explanation", "resolution_refs": ["summary"]}]
        self.rejected("contradiction.resolution.incomplete")

    def test_offline_review_cannot_use_truncated_material(self):
        self.add_evidence(complete=False)
        self.claim["review"]["refs"] = ["review-only"]
        self.rejected("review.evidence.incomplete")

    def test_offline_review_cannot_mix_environments(self):
        self.add_evidence(context_id="different-environment")
        self.claim["review"]["refs"] = ["review-only"]
        self.rejected("review.evidence.context")

    def test_legacy_review_also_requires_complete_ancestors(self):
        self.claim["schema_version"] = 1
        self.add_evidence("partial", complete=False)
        self.add_evidence("summary", form="derived", derived_from=["partial"])
        self.claim["review"]["refs"] = ["summary"]
        self.rejected("review.evidence.incomplete")

    def test_owner_cannot_self_sign_with_different_case(self):
        self.claim["review"]["reviewer"] = " WORKER "
        self.rejected("review.independence")

    def test_replay_requires_another_actors_actual_record(self):
        self.claim["review"].update(mode="independent_replay", replay_refs=["raw"])
        self.rejected("review.replay_provenance")

    def test_replay_with_complete_provenance_is_eligible(self):
        self.add_evidence("replay", actor="reviewer", role="replay")
        self.claim["review"].update(mode="independent_replay", replay_refs=["replay"])
        self.assertFalse(self.valid()["proves_vulnerability"])

    def test_impact_assessment_needs_evidence(self):
        self.claim["assessment"]["refs"] = []
        self.rejected("refs.list")

    def test_impact_assessment_cannot_use_other_environment(self):
        self.add_evidence("other", context_id="different-environment")
        self.claim["assessment"]["refs"] = ["other"]
        self.rejected("assessment.evidence.context")

    def test_state_change_requires_cleanup(self):
        self.claim["state_changed"] = True
        self.rejected("required.cleanup")

    def test_same_failure_branch_cannot_reset_through_new_probe(self):
        self.claim["progress"].update(no_new_information_rounds=2, next_action="probe")
        self.rejected("required.bounded_continuation")

    def test_new_prerequisite_allows_limited_resume(self):
        self.claim["progress"].update(no_new_information_rounds=2, next_action="probe", changed_prerequisite_refs=["raw"])
        self.claim["checks"]["prerequisite_change"] = {"result": "supported", "refs": ["raw"]}
        self.assertFalse(self.valid()["proves_vulnerability"])

    def test_sqli_requires_semantics_beyond_status_code(self):
        self.claim["kind"] = "sqli"
        self.rejected("required.sql_semantics")

    def test_response_echo_is_not_execution_witness(self):
        self.claim["kind"] = "server_execution"
        for name in ("implementation", "reachability", "execution_witness"):
            self.claim["checks"][name] = {"result": "supported", "refs": ["raw"]}
        self.claim["witness_kind"] = "response_echo"
        self.rejected("execution.witness_kind")

    def test_history_cannot_be_laundered_as_current(self):
        self.claim["evidence"][0]["scope"] = "historical"
        self.rejected("required.current.contract")

    def test_historical_claim_does_not_claim_current_exploit(self):
        self.claim.update(mode="historical", claims_current_exploit=False)
        self.claim["evidence"][0]["scope"] = "historical"
        for name in ("historical_semantics", "time_scope"):
            self.claim["checks"][name] = {"result": "supported", "refs": ["raw"]}
        self.assertEqual(self.valid()["mode"], "historical")

    def test_hints_cannot_be_called_independent_discovery(self):
        self.claim["origin"].update(hint_level="exact_location", independent_discovery=True)
        self.rejected("origin.hinted_independent")

    def test_altered_evidence_is_rejected(self):
        (self.case / "raw.json").write_text('{}', encoding="utf8")
        self.rejected("evidence.digest_mismatch")

    def test_outside_case_evidence_is_rejected(self):
        (self.root / "outside.json").write_text('{}', encoding="utf8")
        self.claim["evidence"][0]["path"] = "../outside.json"
        self.rejected("path.outside_case")

    def test_derived_cycle_is_rejected(self):
        self.add_evidence("loop", form="derived", derived_from=["loop"])
        self.rejected("evidence.ancestry_cycle")

    def test_success_and_rejection_never_mutate_files_or_claim(self):
        before_claim = copy.deepcopy(self.claim)
        before_files = {p.name: p.read_bytes() for p in self.case.iterdir()}
        self.valid()
        self.assertEqual(self.claim, before_claim)
        self.assertEqual({p.name: p.read_bytes() for p in self.case.iterdir()}, before_files)

    def test_cli_invalid_json_does_not_echo_secrets(self):
        (self.case / "bad.json").write_text('{"secret":"synthetic-private-value"', encoding="utf8")
        proc = subprocess.run([sys.executable, "-B", str(Path(check_claim.__file__)), "--case", str(self.case),
                               "--claim", "bad.json"], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("synthetic-private-value", proc.stdout + proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["code"], "input.unreadable_or_invalid")


if __name__ == "__main__":
    unittest.main()
