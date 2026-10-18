"""Review proposals from a pinned, authorized context; never a canonical writer.

The trusted host supplies ContextSnapshot, identity, policy and fresh source pins.
This detects declared/structural inconsistencies, not arbitrary prose semantics.
"""
from copy import deepcopy
from itertools import groupby

from context_access import edge_identity
from context_bundle import ContextSnapshot, encode
from knowledge_policy import fingerprint
from evidence import Evidence


class MaintenanceError(ValueError):
    pass


RULES = {
    "declared-contradiction": ("contradiction", "Review the declared conflict and its original evidence; do not choose a winner from confidence."),
    "competing-claims": ("contradiction", "Review differing active values for the same field; they may describe different conditions or times."),
    "claim-record-mismatch": ("contradiction", "Compare the record with its assertion and original evidence before proposing a correction."),
    "contradicting-evidence": ("contradiction", "Review the opposing evidence; supporting counts do not settle the claim."),
    "superseded-active-claim": ("supersession", "Review the active claim that a successor declares superseded; preserve both claims and their history."),
    "obsolete-record-value": ("supersession", "Review a current record value matching a superseded or retracted assertion; do not silently rewrite it."),
    "unlinked-record": ("orphan", "Inspect whether this record needs a cross-reference; no link is visible in this selected context."),
    "unresolved-assertion": ("cross-reference", "Resolve the permitted assertion reference through its owning source; absence from this view is not global absence."),
    "unavailable-reference": ("cross-reference", "Inspect the permitted reference and its unavailable result; do not infer deletion or permission from it."),
    "collection-gap": ("collection", "Find the owning source for this collection question and use the routine improvement workflow."),
    "evidence-gap": ("evidence", "Inspect the evidence gap or source freshness before using the claim; retain unknowns explicitly."),
}


def inspect(snapshot, request, *, max_findings=100, max_bytes=262144, log):
    """Return deterministic diagnostics/proposals, using only compiled context.

    ``log`` is an authenticated host audit sink with oplog.append's four-argument
    signature. A failed audit refuses the operation. No caller-supplied bundle,
    actor, review status, grant or source patch is accepted here. Reports must stay
    within the same read audience; they are not producer-authorized canon edits.
    """
    try:
        if (not isinstance(snapshot, ContextSnapshot) or type(max_findings) is not int or max_findings < 0 or
                type(max_bytes) is not int or max_bytes < 1 or not callable(log)):
            raise MaintenanceError("Invalid maintenance budget or audit sink")
        context = snapshot.compile(request)
        result = _inspect(context, max_findings, max_bytes)
    except (ValueError, KeyError, TypeError):
        if callable(log):
            log("maintenance.rejected", "semantic-maintenance", "context", {"reason": "invalid-or-unavailable-input"})
        raise
    log("maintenance.inspected", "semantic-maintenance", fingerprint(result), {
        "findings": len(result["proposals"]), "truncated": bool(result["truncation"]),
    })
    return result


def _inspect(context, max_findings, max_bytes):
    # ContextSnapshot already filters records, evidence, counts and references
    # before traversal. Do not inspect its underlying unfiltered input or bindings.
    result = {
        "format": "maintenance-proposals/v1", "generator": "semantic-maintenance/1.0",
        "basis": deepcopy(context["request"]), "authorization": deepcopy(context["authorization"]),
        "contextSha256": fingerprint(context),
        "coverage": {"scope": "selected-authorized-context", "semanticCompleteness": "not-assessed",
                     "contextTruncation": deepcopy(context["truncation"])},
        "proposals": [], "truncation": [],
    }
    reserve = ["maxBytes", "maxFindings"]
    if len(encode({**result, "truncation": reserve})) > max_bytes:
        raise MaintenanceError("Maintenance byte budget cannot hold the envelope")
    records = [(n["id"], n) for n in context["nodes"]]
    edge_refs = {edge_identity(e): {"edge": edge_identity(e)} for e in context["edges"]}
    if set(edge_refs).intersection(n["id"] for n in context["nodes"]):
        raise MaintenanceError("Ambiguous context record reference")
    records += [(edge_refs[edge_identity(e)], e) for e in context["edges"]]
    proposals, record_evidence = {}, {}

    def add(rule, record_ids=(), assertion_ids=(), detail=None, citations=None):
        family, action = RULES[rule]
        record_map = {fingerprint(record): deepcopy(record) for record in record_ids}
        identity = {"rule": rule, "records": [record_map[key] for key in sorted(record_map)],
                    "assertions": sorted(set(assertion_ids)), "detail": detail or {}}
        if citations is None:
            candidates = [citation for record in record_ids
                          for citation in record_evidence.get(fingerprint(record), [])
                          if not assertion_ids or citation["assertion"] in assertion_ids]
            unique = {fingerprint(citation): citation for citation in candidates}
            citations = [unique[key] for key in sorted(unique)]
        citations = deepcopy(list(citations))
        citations.sort(key=lambda c: (c["assertion"], c["attestation"]))
        # Original lineages, including ancestors of derived summaries, are a set.
        # This diagnostic never adds another supporting attestation or review.
        lineages = sorted({lineage for c in citations for lineage in c["lineages"]})
        row = {"id": "maintenance:" + fingerprint(identity), **identity,
               "family": family, "status": "proposed", "confidence": None,
               "requiresReview": True, "action": action, "citations": citations,
               "originalLineages": lineages}
        proposals[row["id"]] = row

    def inspect_records(records):
        assertions, claims, evidence = {}, {}, {}
        for record_id, record in records:
            record_evidence[fingerprint(record_id)] = []
            bundle = record.get("evidence", {})
            lineage = Evidence(bundle, partial=True) if bundle else None
            for assertion in bundle.get("assertions", []):
                identity = assertion["id"]
                if identity in assertions:
                    # Assertion IDs identify one target. Ambiguity cannot be resolved
                    # by traversal order, even when individually valid bundles exist.
                    raise MaintenanceError("Duplicate assertion identity in context")
                assertions[identity] = (record_id, assertion)
            for claim in bundle.get("claims", []):
                claims[claim["assertion"]] = claim
            observations = {o["attestation"]: o for o in bundle.get("observations", [])}
            representations = {r["id"]: r for r in bundle.get("representations", [])}
            for attestation in bundle.get("attestations", []):
                observation = observations[attestation["id"]]
                representation = representations[attestation["representation"]]
                citation = {"assertion": attestation["assertion"], "attestation": attestation["id"],
                            "representation": attestation["representation"], "href": observation["href"],
                            "locator": deepcopy(attestation["locator"]), "status": observation["status"],
                            "lineages": deepcopy(observation["lineages"]),
                            "derived": bool(representation["derivedFrom"]),
                            "sourceRevisions": [{field: lineage.sources[key][field] for field in ("id", "revision", "sha256", "lineage")} for key in
                                                sorted(lineage.origins[representation["id"]], key=str)],
                            "reviewState": attestation["review"]["state"],
                            "extractionConfidence": attestation["confidence"]}
                evidence.setdefault(attestation["assertion"], []).append(citation)
                record_evidence[fingerprint(record_id)].append(citation)

        def emit(rule, record_ids=(), assertion_ids=(), detail=None):
            citations = [citation for a in sorted(set(assertion_ids)) for citation in evidence.get(a, [])]
            add(rule, record_ids, assertion_ids, detail, citations)

        for identity, (record_id, assertion) in sorted(assertions.items()):
            for other_id in assertion["contradicts"]:
                other = assertions.get(other_id)
                emit("declared-contradiction", [record_id, *([other[0]] if other else [])],
                    [identity, other_id])
            for other_id in assertion["supersedes"]:
                other = assertions.get(other_id)
                if assertion["status"] == "active" and other and other[1]["status"] == "active":
                    emit("superseded-active-claim", [record_id, other[0]], [identity, other_id],
                        {"successor": identity, "predecessor": other_id})
            for relation in ("contradicts", "supersedes", "retracts"):
                for other_id in assertion[relation]:
                    if other_id not in assertions:
                        emit("unresolved-assertion", [record_id], [identity, other_id], {"relation": relation})
            claim = claims[identity]
            if assertion["status"] != "active" and claim["matchesRecord"] is True:
                emit("obsolete-record-value", [record_id], [identity], {"status": assertion["status"]})
            if assertion["status"] == "active" and claim["matchesRecord"] is False:
                emit("claim-record-mismatch", [record_id], [identity])
            if claim["contradictingLineages"]:
                emit("contradicting-evidence", [record_id], [identity])

        active = [(record, assertion) for record, assertion in assertions.values() if assertion["status"] == "active"]
        active.sort(key=lambda pair: (fingerprint(pair[0]), pair[1]["field"], pair[1]["id"]))
        for (_, field), group in groupby(active, key=lambda pair: (fingerprint(pair[0]), pair[1]["field"])):
            group = list(group)
            if len({fingerprint(assertion["value"]) for _, assertion in group}) > 1:
                emit("competing-claims", [group[0][0]], [a["id"] for _, a in group], {"field": field})

    inspect_records(records)
    # Resolved peers retain their scoped target and independent assertion space.
    # Never merge a peer's claim IDs into the local graph or another participant.
    for reference in context["references"]:
        if reference["status"] == "resolved":
            inspect_records([(reference["target"], reference["record"])])

    # A single selected record often has links outside its traversal recipe.
    # This is deliberately an in-view hint, never a global orphan assertion.
    if not context["truncation"]:
        linked = {endpoint for e in context["edges"] for endpoint in (e["source"], e["target"])}
        for node in context["nodes"]:
            if node["id"] not in linked:
                add("unlinked-record", [node["id"]])
    for reference in context["references"]:
        if reference["status"] != "resolved":
            add("unavailable-reference", detail={"address": reference["address"],
                                                "status": reference["status"], "reason": reference.get("reason")})
    for question in context["coverage"]["questions"]:
        if question["state"] not in ("sufficient", "not-applicable"):
            add("collection-gap", detail={"question": question["question"], "state": question["state"],
                                          "ownerRole": question["ownerRole"], "reasons": deepcopy(question["reasons"]),
                                          "criterion": question["criterion"]})
    for gap in context["gaps"]:
        if gap.get("state") == "contradiction" or "question" in gap:
            continue  # Handled above, preserving typed evidence and question IDs.
        detail = deepcopy(gap)
        if isinstance(detail.get("record"), str) and detail["record"] in edge_refs:
            detail["record"] = edge_refs[detail["record"]]
        add("evidence-gap", [detail["record"]] if "record" in detail else [],
            [gap["assertion"]] if "assertion" in gap else [], detail=detail)

    for identity in sorted(proposals):
        if len(result["proposals"]) == max_findings:
            result["truncation"].append("maxFindings")
            break
        candidate = {**result, "proposals": [*result["proposals"], proposals[identity]], "truncation": reserve}
        if len(encode(candidate)) > max_bytes:
            if "maxBytes" not in result["truncation"]:
                result["truncation"].append("maxBytes")
            continue
        result["proposals"].append(proposals[identity])
    result["truncation"].sort()
    return result
