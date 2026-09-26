"""Authorize collection questions and assessments before deriving coverage (#55).

Uses the collection-profile sufficiency/cadence semantics from #85. Operator
bindings are independent of the assessed content; changing an assessment or an
evidence row invalidates its exact-snapshot binding. A restricted assessment has
the same result as no assessment, including reasons, evidence IDs and counts.
"""
from copy import deepcopy

from brain_recipes import assess
from context_access import ContextAccessError
from knowledge_policy import fingerprint, timestamp


def _basis(boundary, as_of):
    return {"principal": boundary.actor, "authorizedAt": boundary.now,
            "scopes": sorted(boundary.scopes), "policy": deepcopy(boundary.policy.binding),
            "asOf": timestamp(as_of).isoformat()}


class CollectionView:
    def __init__(self, questions, document, *, boundary, bindings, as_of, target_id):
        if not isinstance(target_id, str) or not target_id.strip():
            raise ContextAccessError("Collection assessment needs an explicit subject")
        self._target_id = target_id
        self._basis = _basis(boundary, as_of)
        if (not isinstance(bindings, dict)
                or set(bindings) != {"questions", "assessments", "evidence", "locators"}
                or any(not isinstance(table, dict) for table in bindings.values())):
            raise ContextAccessError("Invalid collection access configuration")
        for table in bindings.values():
            if any(not isinstance(key, str) or not key or not isinstance(value, str) or not value
                   for key, value in table.items()):
                raise ContextAccessError("Invalid collection resource binding")
        bindings = deepcopy(bindings)

        def permitted(table, identity):
            return boundary.permits_resource(bindings[table].get(identity), identity)

        visible_questions = {identity: deepcopy(question) for identity, question in questions.items()
                             if permitted("questions", fingerprint(question))}
        if document is None:
            document = {"protocolVersion": "1.0", "evidence": [], "assessments": []}
        if (not isinstance(document, dict) or set(document) != {"protocolVersion", "evidence", "assessments"}
                or document["protocolVersion"] != "1.0"
                or not isinstance(document["evidence"], list) or not isinstance(document["assessments"], list)):
            raise ContextAccessError("Invalid collection assessment envelope")
        visible_evidence = {}
        for row in document["evidence"]:
            if permitted("evidence", fingerprint(row)) and permitted("locators", row["locator"]):
                if row["id"] in visible_evidence:
                    raise ContextAccessError("Duplicate visible collection evidence")
                visible_evidence[row["id"]] = deepcopy(row)
        assessments = []
        used_evidence = set()
        for row in document["assessments"]:
            if (row["question"] in visible_questions and permitted("assessments", fingerprint(row))
                    and all(identity in visible_evidence for identity in row["evidence"])):
                assessments.append(deepcopy(row))
                assessments[-1]["evidence"] = sorted(set(row["evidence"]))
                used_evidence.update(row["evidence"])
        # Unreferenced sources must not affect freshness checks or coverage.
        authorized = {"protocolVersion": "1.0", "assessments": assessments,
                      "evidence": [visible_evidence[key] for key in sorted(used_evidence)]}
        self._result = assess(visible_questions, authorized, timestamp(as_of))
        self._evidence = authorized["evidence"]
        # Input order is not knowledge. Coverage and its binding must be stable
        # across equivalent serialized stores and input permutations.
        authorized["assessments"].sort(key=lambda row: row["question"])
        self._binding = fingerprint({"questions": visible_questions, "assessment": authorized,
                                     "asOf": timestamp(as_of).isoformat(), "target": target_id})

    @property
    def binding(self):
        return self._binding

    def matches(self, boundary, as_of):
        return self._basis == _basis(boundary, as_of)

    def result(self):
        """Only visible question coverage; never implies global completeness."""
        return deepcopy({"state": "assessed", "questions": self._result, "evidence": self._evidence,
                         "basis": self._binding, "subject": self._target_id})
