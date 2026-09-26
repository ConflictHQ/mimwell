"""Collection-owned semantic declarations; no record search or inferred identity."""

from copy import deepcopy

from knowledge_policy import PolicyError


def inspect_collection(store, collection, *, actor, at):
    store._read_state()
    if collection not in store.contract.collections or not store.contract.can_read(collection, actor, at):
        raise PolicyError("Collection semantics unavailable")
    selected = store.contract.collections[collection]
    registry = store.contract.registry
    kind = registry.kinds[selected["kind"]]
    convention = registry.id_conventions[kind["id"]]
    return {
        "format": "collection-semantics/v1",
        "collection": deepcopy(selected),
        "owner": {"contract": store.contract.document["id"], "authority": store.contract.authority,
                  "participant": None, "participantState": "not-declared-by-this-authority-contract"},
        "ontology": registry.binding(),
        "kind": deepcopy(kind),
        "identity": {
            "convention": convention,
            "declaration": deepcopy(registry.declaration["contract"]["idConventions"][convention]),
            "scope": "selected-authority; federation participant must be independently resolved",
            "equivalence": "Declared aliases and matching labels do not approve same_as relationships or merge records.",
        },
        "taxonomy": deepcopy(list(registry.terms.values())),
        "taxonomyScope": "adopted-ontology-declarations; no record classification inferred",
        "relationships": deepcopy(list(registry.edges.values())),
        "writer": {
            "type": "native-authority",
            "operations": ["record.get", "record.patch-propose", "proposal.inspect", "proposal.review",
                           "proposal.dispose", "proposal.commit"],
            "instruction": "Inspect the current record in this authority, propose a correction, and use its native review and commit rules. Discovery grants do not authorize those operations.",
        },
        "taxonomyChange": {
            "type": "versioned-ontology-workflow",
            "instruction": "Propose term, alias, broader-link or kind changes in a versioned ontology overlay. Validate compatibility and explicitly adopt it through the authority contract workflow; record editing does not change the ontology.",
        },
        "executionAuthorized": False,
    }
