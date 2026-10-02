"""Read-only evidence preflight. Exit 0 permits semantic review, not confirmation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


class Invalid(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Invalid(code)


def inside(root, value):
    require(isinstance(value, str) and bool(value), "path.invalid")
    path = (root / value).resolve()
    require(path.is_relative_to(root), "path.outside_case")
    require(path.is_file(), "path.missing_file")
    return path


def object_at(value, pointer):
    require(isinstance(pointer, str) and (pointer == "" or pointer.startswith("/")), "locator.pointer")
    for segment in pointer.split("/")[1:] if pointer else []:
        require(not re.search(r"~(?![01])", segment), "locator.escape")
        key = segment.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            require(bool(re.fullmatch(r"0|[1-9][0-9]*", key)), "locator.index")
            require(int(key) < len(value), "locator.missing")
            value = value[int(key)]
        else:
            require(isinstance(value, dict) and key in value, "locator.missing")
            value = value[key]
    return value


def validate(claim, root):
    """Validate declared metadata and local bytes; never infer exploit semantics."""
    root = Path(root).resolve()
    require(root.is_dir(), "case.missing")
    require(isinstance(claim, dict) and type(claim.get("schema_version")) is int and claim["schema_version"] in {1, 2}, "schema.version")
    version = claim["schema_version"]
    for field in ("claim_id", "statement", "owner", "context_id"):
        require(isinstance(claim.get(field), str) and claim[field].strip(), "field." + field)
    require(claim.get("kind") in {"sqli", "server_execution", "authorization", "other"}, "kind.invalid")
    mode = claim.get("mode")
    require(mode in {"current", "source", "historical"}, "mode.invalid")
    confirmed = claim.get("disposition") == "confirmed"
    require(claim.get("disposition") in {"candidate", "confirmed"}, "disposition.invalid")
    require(type(claim.get("claims_current_exploit")) is bool, "current.required_boolean")
    require(not claim["claims_current_exploit"] or mode == "current", "current.mode_conflict")
    require(not claim["claims_current_exploit"] or confirmed, "current.unconfirmed_claim")
    origin = claim.get("origin", {})
    require(isinstance(origin, dict), "origin.invalid")
    require(origin.get("hint_level") in {"none", "class", "system_class", "exact_location", "reproduction"}, "origin.hint_level")
    require(type(origin.get("independent_discovery")) is bool, "origin.required_boolean")
    require(not origin["independent_discovery"] or origin["hint_level"] == "none", "origin.hinted_independent")

    items = claim.get("evidence")
    require(isinstance(items, list), "evidence.list")
    index = {}
    for item in items:
        require(isinstance(item, dict), "evidence.object")
        eid = item.get("id")
        require(isinstance(eid, str) and eid and eid not in index, "evidence.id")
        require(item.get("scope") in {"current", "source", "historical"}, "evidence.scope")
        require(type(item.get("complete")) is bool, "evidence.complete")
        require(item.get("form") in {"raw", "derived"}, "evidence.form")
        require(isinstance(item.get("context_id"), str), "evidence.context")
        path = inside(root, item.get("path"))
        data = path.read_bytes()
        digest = item.get("sha256")
        require(isinstance(digest, str) and bool(re.fullmatch(r"[a-fA-F0-9]{64}", digest)), "evidence.digest_format")
        require(hashlib.sha256(data).hexdigest() == digest.lower(), "evidence.digest_mismatch")
        loc = item.get("locator")
        require(isinstance(loc, dict) and len(loc) == 1, "locator.required")
        if "json_pointer" in loc:
            object_at(json.loads(data.decode("utf-8-sig")), loc["json_pointer"])
        elif "lines" in loc:
            bounds = loc["lines"]
            require(isinstance(bounds, list) and len(bounds) == 2 and all(type(n) is int for n in bounds), "locator.lines")
            require(1 <= bounds[0] <= bounds[1] <= len(data.decode("utf-8-sig").splitlines()), "locator.line_range")
        else:
            raise Invalid("locator.kind")
        index[eid] = item

    def refs(value, nonempty=True):
        require(isinstance(value, list) and (bool(value) or not nonempty), "refs.list")
        require(all(isinstance(eid, str) and eid in index for eid in value), "refs.unknown")
        return [index[eid] for eid in value]

    # Check ancestry for every derived attachment, including cycles and missing parents.
    def ancestry(eid, seen=None):
        seen = set() if seen is None else seen
        require(eid not in seen, "evidence.ancestry_cycle")
        item = index[eid]
        if item["form"] == "raw":
            return [item]
        parents = refs(item.get("derived_from"))
        return [item] + [ancestor for parent in parents for ancestor in ancestry(parent["id"], seen | {eid})]

    for eid in index:
        ancestry(eid)

    def valid_chain(selected, code, current=False):
        chain = [r for item in selected for r in ancestry(item["id"])]
        require(all(item["complete"] for item in chain), code + ".incomplete")
        require(all(item["context_id"] == claim["context_id"] for item in chain), code + ".context")
        if current:
            require(all(item["scope"] == "current" for item in chain), code + ".current")

    checks = claim.get("checks", {})
    require(isinstance(checks, dict), "checks.object")
    for check in checks.values():
        require(isinstance(check, dict) and check.get("result") in {"supported", "missing", "contradicted", "not_applicable"}, "check.result")
        selected = refs(check.get("refs", []), check["result"] == "supported")
        if check["result"] == "supported":
            valid_chain(selected, "check.evidence")

    def supported(name, current=False):
        check = checks.get(name, {})
        require(check.get("result") == "supported", "required." + name)
        selected = refs(check.get("refs"))
        chain = [r for item in selected for r in ancestry(item["id"])]
        require(all(item["complete"] for item in chain), "required.incomplete." + name)
        require(all(item["context_id"] == claim["context_id"] for item in chain), "required.context." + name)
        if current:
            require(all(item["scope"] == "current" for item in chain), "required.current." + name)

    progress = claim.get("progress", {})
    require(isinstance(progress, dict), "progress.object")
    rounds = progress.get("no_new_information_rounds", 0)
    require(type(rounds) is int and rounds >= 0, "progress.rounds")
    action = progress.get("next_action")
    require(action in {"probe", "restore_prerequisite", "report", "review"}, "progress.action")
    changed = progress.get("changed_prerequisite_refs", [])
    refs(changed, False)
    if changed:
        supported("prerequisite_change")
        require(set(changed) == set(checks["prerequisite_change"]["refs"]), "progress.change_refs_mismatch")
    if rounds >= 2 and action == "probe" and not changed:
        supported("bounded_continuation")

    # Version 2 records a falsifiable business hypothesis and explicit counterevidence.
    # These are attachments to the existing board, never a second task state machine.
    if version == 2:
        hypothesis = claim.get("hypothesis")
        require(isinstance(hypothesis, dict), "hypothesis.object")
        for field in ("constraint", "failure_boundary", "minimal_observation",
                      "negative_control", "falsifier", "evidence_threshold"):
            value = hypothesis.get(field)
            require(field in hypothesis and (value is None or isinstance(value, str)), "hypothesis." + field)
            if confirmed or action == "probe":
                require(isinstance(value, str) and value.strip(), "hypothesis." + field)
        hypothesis_refs = refs(hypothesis.get("refs", []), confirmed or action == "probe")
        valid_chain(hypothesis_refs, "hypothesis.evidence")
        contradictions = claim.get("contradictions")
        require(isinstance(contradictions, list), "contradictions.list")
        cids = set()
        for item in contradictions:
            require(isinstance(item, dict), "contradiction.object")
            cid = item.get("id")
            require(isinstance(cid, str) and cid.strip() and cid not in cids, "contradiction.id")
            cids.add(cid)
            refs(item.get("refs"))
            require(item.get("resolution") in {"unresolved", "explained", "refuted"}, "contradiction.resolution")
            if item["resolution"] != "unresolved":
                valid_chain(refs(item.get("resolution_refs")), "contradiction.resolution")
                require(isinstance(item.get("reason"), str) and item["reason"].strip(), "contradiction.reason")
            require(not confirmed or item["resolution"] != "unresolved", "contradiction.unresolved")
        if confirmed:
            require(all(check["result"] != "contradicted" for check in checks.values()), "check.unresolved_contradiction")
            assessment = claim.get("assessment")
            require(isinstance(assessment, dict), "assessment.object")
            for field in ("demonstrated_capability", "affected_objects", "preconditions", "severity_basis"):
                require(isinstance(assessment.get(field), str) and assessment[field].strip(), "assessment." + field)
            require(assessment.get("severity") in {"unrated", "info", "low", "medium", "high", "critical"}, "assessment.severity")
            valid_chain(refs(assessment.get("refs")), "assessment.evidence")

    if confirmed:
        for name in ("impact", "alternatives"):
            supported(name)
        if mode == "current":
            for name in ("contract", "baseline", "mapping", "effect", "control"):
                supported(name, current=True)
            if claim["kind"] == "sqli":
                supported("sql_semantics", current=True)
            if claim["kind"] == "server_execution":
                supported("implementation")
                supported("reachability", current=True)
                supported("execution_witness", current=True)
                require(claim.get("witness_kind") in {"correlated_server_telemetry", "controlled_execution_effect"}, "execution.witness_kind")
        elif mode == "source":
            for name in ("implementation", "mapping", "reachability", "version_applicability"):
                supported(name)
        else:
            for name in ("historical_semantics", "time_scope"):
                supported(name)
        require(type(claim.get("state_changed")) is bool, "change.required_boolean")
        if claim["state_changed"]:
            supported("cleanup")
        review = claim.get("review", {})
        require(isinstance(review, dict), "review.object")
        require(isinstance(review.get("reviewer"), str) and review["reviewer"].strip() and review["reviewer"].strip().casefold() != claim["owner"].strip().casefold(), "review.independence")
        require(review.get("mode") in {"offline", "independent_replay"}, "review.mode")
        valid_chain(refs(review.get("refs")), "review.evidence")
        if review["mode"] == "independent_replay":
            require(mode == "current", "review.replay_mode")
            replay = refs(review.get("replay_refs"))
            require(all(item["form"] == "raw" and item["scope"] == "current" and item["complete"] and item["context_id"] == claim["context_id"] and item.get("actor") == review["reviewer"] and item.get("role") == "replay" for item in replay), "review.replay_provenance")
    return {"status": "eligible_for_semantic_review", "disposition": claim["disposition"], "mode": mode, "evidence_count": len(index), "proves_vulnerability": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--claim", required=True)
    args = parser.parse_args()
    try:
        root = Path(args.case).resolve()
        path = inside(root, args.claim)
        claim = json.loads(path.read_text(encoding="utf-8-sig"))
        result = validate(claim, root)
    except (Invalid, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        # Do not echo arbitrary JSON values, evidence content, paths or credentials.
        code = str(exc) if isinstance(exc, Invalid) else "input.unreadable_or_invalid"
        print(json.dumps({"status": "rejected", "code": code, "proves_vulnerability": False}))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
