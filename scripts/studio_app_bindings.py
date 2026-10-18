"""Revision-pinned bindings for the opt-in Studio App ontology."""

from copy import deepcopy

MAX_APP_BINDING_RECORDS = 256
MAX_APP_BINDING_REFERENCES = 256
MAX_APP_BINDING_BYTES = 2 * 1024 * 1024


def _relation_targets(record, rel):
    return sorted(edge["target"] for edge in record.get("relations", []) if edge.get("rel") == rel)


def binding_targets(record):
    """Declared targets only; callers apply the current read policy before loading them."""
    kind = record.get("kind")
    data = record.get("content", {}).get("data", {})
    if kind == "studio.app":
        return [section.get("component") for section in data.get("layout", {}).get("sections", [])]
    if kind == "studio.component":
        return [binding.get("query") for binding in data.get("queryBindings", [])]
    if kind == "studio.app-query":
        return [data.get("metric")]
    return []


def app_binding_status(record, targets):
    """Return explicit availability; never resolve an unpinned or newest target."""
    kind = record.get("kind")
    data = record.get("content", {}).get("data", {})
    expected = {}
    if kind == "studio.app":
        expected["has_app_component"] = {
            section.get("component"): section.get("componentRevision")
            for section in data.get("layout", {}).get("sections", [])
        }
    elif kind == "studio.component":
        expected["component_uses_query"] = {
            binding.get("query"): binding.get("revision") for binding in data.get("queryBindings", [])
        }
    elif kind == "studio.app-query":
        expected["query_uses_metric"] = {data.get("metric"): data.get("metricRevision")}
    else:
        return None

    reasons = []
    if kind == "studio.app":
        sections = data.get("layout", {}).get("sections", [])
        if len({section.get("id") for section in sections}) != len(sections):
            reasons.append("duplicate-layout-section")
    if kind == "studio.component":
        bindings = data.get("queryBindings", [])
        if len({binding.get("query") for binding in bindings}) != len(bindings):
            reasons.append("duplicate-query-binding")
    for relation, pins in expected.items():
        if _relation_targets(record, relation) != sorted(pins):
            reasons.append("binding-relations-mismatch")
        for identity, revision in pins.items():
            target = targets.get(identity)
            expected_kind = "studio.component" if relation == "has_app_component" else (
                "studio.app-query" if relation == "component_uses_query" else "metric")
            if target is None:
                reasons.append("binding-target-unavailable")
            elif target.get("kind") != expected_kind:
                reasons.append("binding-target-kind-mismatch")
            elif target.get("revision") != revision:
                reasons.append("binding-target-revision-changed")
            elif target.get("kind") in ("studio.component", "studio.app-query"):
                nested = app_binding_status(target, targets)
                if nested and not nested["available"]:
                    reasons.extend("nested-" + reason for reason in nested["reasons"])
    return {"available": not reasons, "reasons": sorted(set(reasons))}


def validate_component_options(record):
    if record.get("kind") != "studio.component":
        return
    definition = record.get("content", {}).get("data", {}).get("definition", {})
    kind, options = definition.get("type"), definition.get("options", {})
    fields = {
        "table": {"pageSize", "columns"},
        "chart": {"chartType", "category", "series"},
        "text": {"text", "style"},
        "filter": {"field", "operator", "values"},
        "summary": {"format", "precision"},
    }
    if kind not in fields or set(options) != fields[kind]:
        raise ValueError("Studio Component options do not match its declared display type")


def require_current_bindings(record, targets):
    validate_component_options(record)
    result = app_binding_status(record, targets)
    if result is not None and not result["available"]:
        raise ValueError("Studio App binding is unavailable: " + ", ".join(result["reasons"]))
    return deepcopy(result)
