"""Revision-pinned bindings for the opt-in Studio App ontology."""

from copy import deepcopy
from datetime import datetime, timezone
import itertools
import json
import math

from jsonschema import Draft202012Validator, ValidationError

MAX_APP_BINDING_RECORDS = 256
MAX_APP_BINDING_REFERENCES = 256
MAX_APP_BINDING_BYTES = 2 * 1024 * 1024
MAX_EMBEDDED_BYTES = 512 * 1024
MAX_EMBEDDED_NODES = 100_000
MAX_EMBEDDED_DEPTH = 32
MAX_EMBEDDED_VISUAL_ROWS = 5_000
EMBEDDED_FORMAT = "studio-embedded/v1"
PGLITE_ROLE = "pglite-snapshot"
PGLITE_FORMAT = "pglite-snapshot"
PGLITE_METADATA_FIELDS = (
    "postgresMajor", "pgliteVersion", "compression", "expandedBytes", "expandedSha256",
)


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


def _embedded_json_bytes(value):
    """Bound an embedded envelope before the JSON Schema walker sees it."""
    pending = [(value, 1)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_EMBEDDED_NODES or depth > MAX_EMBEDDED_DEPTH:
            raise ValueError("Studio embedded component exceeds its structural limit")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("Studio embedded component has a non-text key")
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif item is None or type(item) in (str, bool, int):
            continue
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("Studio embedded component has a non-finite number")
        else:
            raise ValueError("Studio embedded component is not JSON data")
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Studio embedded component is not bounded canonical JSON") from exc
    if len(raw) > MAX_EMBEDDED_BYTES:
        raise ValueError("Studio embedded component exceeds its byte limit")
    return raw


def _validate_embedded_envelope(record, embedded, schema):
    if not isinstance(schema, dict):
        raise ValueError("Studio embedded component profile is unavailable")
    _embedded_json_bytes(embedded)

    def exact(value, keys, message):
        if not isinstance(value, dict) or set(value) != set(keys):
            raise ValueError(message)

    exact(embedded, {"format", "descriptor", "snapshot", "view"},
          "Studio embedded component has an unsupported field")
    descriptor = embedded.get("descriptor")
    exact(descriptor, {"format", "frozen_at", "source", "tables", "query", "fixtures", "counts"},
          "Studio embedded descriptor has an unsupported field")
    exact(descriptor.get("source"), {"kind", "id", "dialect", "timezone", "query_sha256"},
          "Studio embedded source has an unsupported field")
    exact(descriptor.get("query"), {"sql", "parameters", "controls"},
          "Studio embedded query has an unsupported field")
    for control in descriptor["query"]["controls"].values():
        if not isinstance(control, dict) or set(control) - {"type", "options", "default", "label"}:
            raise ValueError("Studio embedded control has an unsupported field")
        if not {"type", "options", "default"}.issubset(control):
            raise ValueError("Studio embedded control is incomplete")
    exact(descriptor.get("fixtures"), {"ordered", "columns", "cases"},
          "Studio embedded fixtures have an unsupported field")
    exact(descriptor.get("counts"), {"rows", "fixture_rows", "bytes"},
          "Studio embedded counts have an unsupported field")
    exact(embedded.get("snapshot"), {"role", "format", "sha256", *PGLITE_METADATA_FIELDS},
          "Studio embedded snapshot has an unsupported field")
    view = embedded.get("view")
    exact(view, {"kind", "title", "description", "view"},
          "Studio embedded view has an unsupported field")
    if view.get("kind") == "table":
        table_view = view.get("view")
        if (not isinstance(table_view, dict) or set(table_view) - {"page_size", "columns"}
                or "page_size" not in table_view):
            raise ValueError("Studio embedded table view is incomplete or has an unsupported field")
    elif view.get("kind") == "kpi":
        kpi = view.get("view")
        if not isinstance(kpi, dict) or set(kpi) - {"value", "label", "format", "delta", "currency"}:
            raise ValueError("Studio embedded KPI view has an unsupported field")
        if not {"value", "label", "format"}.issubset(kpi):
            raise ValueError("Studio embedded KPI view is incomplete")
    elif view.get("kind") == "chart":
        chart = view.get("view")
        if (not isinstance(chart, dict) or set(chart) - {"mark", "x", "y", "color", "stacked"}
                or not {"mark", "x", "y", "stacked"}.issubset(chart)):
            raise ValueError("Studio embedded chart view is incomplete or has an unsupported field")
        if chart["mark"] not in ("bar", "line", "area", "point", "pie"):
            raise ValueError("Studio embedded chart mark is unsupported")
        if (not isinstance(chart["x"], str) or not isinstance(chart["y"], list)
                or not 1 <= len(chart["y"]) <= 6 or any(not isinstance(column, str) for column in chart["y"])
                or type(chart["stacked"]) is not bool
                or "color" in chart and not isinstance(chart["color"], str)):
            raise ValueError("Studio embedded chart view is malformed")
        if chart["mark"] == "pie" and (len(chart["y"]) != 1 or "color" in chart):
            raise ValueError("Studio embedded pie view requires one series and no color field")
    elif view.get("kind") == "diagram":
        diagram = view.get("view")
        if (not isinstance(diagram, dict) or set(diagram) != {"edges", "direction"}
                or diagram.get("direction") not in ("LR", "TD", "RL", "BT")):
            raise ValueError("Studio embedded query diagram view is incomplete or unsupported")
        edges = diagram.get("edges")
        if (not isinstance(edges, dict) or set(edges) - {"from", "to", "label"}
                or not {"from", "to"}.issubset(edges)
                or any(not isinstance(column, str) for column in edges.values())):
            raise ValueError("Studio embedded diagram edges are malformed")
    else:
        raise ValueError("Studio embedded view kind is unsupported")
    try:
        Draft202012Validator(schema).validate(embedded)
    except (ValidationError, RecursionError, ValueError) as exc:
        raise ValueError("Studio embedded component does not match its closed profile") from exc

    frozen_at = descriptor["frozen_at"]
    if not isinstance(frozen_at, str) or not (frozen_at.endswith("Z") or frozen_at.endswith("+00:00")):
        raise ValueError("Studio embedded capture time must use an explicit UTC offset")
    try:
        parsed = datetime.fromisoformat(frozen_at.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Studio embedded capture time is unavailable") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("Studio embedded capture time must be UTC")

    query = descriptor["query"]
    controls = query["controls"]
    parameters = query["parameters"]
    if (len(parameters) != len(set(parameters)) or set(parameters) != set(controls)
            or any(not controls[name]["options"] or controls[name]["default"] not in controls[name]["options"]
                   or controls[name]["type"] != "choice" for name in parameters)):
        raise ValueError("Studio embedded controls do not match their parameter list")
    combination_count = math.prod(len(controls[name]["options"]) for name in parameters)
    if combination_count > 100:
        raise ValueError("Studio embedded control combinations exceed their limit")
    combinations = list(itertools.product(*(controls[name]["options"] for name in parameters)))
    cases = descriptor["fixtures"]["cases"]
    actual_cases = [tuple(item["params"]) for item in cases]
    if actual_cases != combinations:
        raise ValueError("Studio embedded fixtures do not cover the complete control domain")
    columns = descriptor["fixtures"]["columns"]
    if len(columns) != len(set(columns)):
        raise ValueError("Studio embedded fixture columns are invalid")
    fixture_rows = 0
    for case in cases:
        for row in case["rows"]:
            if len(row) != len(columns):
                raise ValueError("Studio embedded fixture row does not match its columns")
            for cell in row:
                if cell.get("kind") == "number":
                    try:
                        finite = math.isfinite(float(cell["value"]))
                    except (TypeError, ValueError, OverflowError):
                        finite = False
                    if not finite:
                        raise ValueError("Studio embedded fixture contains a non-finite number")
            fixture_rows += 1
            if fixture_rows > 5000:
                raise ValueError("Studio embedded fixture rows exceed their limit")
    if descriptor["counts"]["fixture_rows"] != fixture_rows:
        raise ValueError("Studio embedded fixture row count is inconsistent")

    view = embedded["view"]
    if view["kind"] in ("chart", "diagram") and descriptor["counts"]["rows"] > MAX_EMBEDDED_VISUAL_ROWS:
        raise ValueError("Studio embedded visual query exceeds its 5000-row rendering bound")
    definition = record["content"]["data"]["definition"]
    component_kind = definition["type"]
    if ((component_kind == "table" and view["kind"] != "table")
            or (component_kind == "summary" and view["kind"] != "kpi")
            or (component_kind == "chart" and view["kind"] != "chart")
            or (component_kind == "diagram" and view["kind"] != "diagram")
            or component_kind not in ("table", "summary", "chart", "diagram")):
        raise ValueError("Studio embedded view does not match its native component type")
    content = record["content"]
    if view["title"] != content.get("title") or view["description"] != content.get("text", ""):
        raise ValueError("Studio embedded view differs from its native component description")
    if view["kind"] == "table":
        if definition["options"]["pageSize"] != view["view"]["page_size"]:
            raise ValueError("Studio embedded table page size is inconsistent")
        selected = view["view"].get("columns", columns)
        if (not isinstance(selected, list) or not selected or len(selected) != len(set(selected))
                or any(column not in columns for column in selected)):
            raise ValueError("Studio embedded table selects an unavailable result column")
        expected_columns = [{"field": f"csv:col{columns.index(column) + 1}",
                             "label": column, "format": "text"} for column in selected]
        if definition["options"]["columns"] != expected_columns:
            raise ValueError("Studio embedded table columns differ from native CSV fallback mapping")
    elif view["kind"] == "kpi":
        value = view["view"]["value"]
        delta = view["view"].get("delta")
        if value not in columns or delta is not None and delta not in columns:
            raise ValueError("Studio embedded KPI selects an unavailable result column")
        expected_format = {"number": "decimal", "percent": "percent", "currency": "currency"}[view["view"]["format"]]
        precision = 1 if view["view"]["format"] == "percent" else 2
        if definition["options"] != {"format": expected_format, "precision": precision, "embedded": embedded}:
            raise ValueError("Studio embedded KPI display options are inconsistent")
    elif view["kind"] == "chart":
        chart = view["view"]
        if chart["x"] not in columns or any(column not in columns for column in chart["y"]):
            raise ValueError("Studio embedded chart selects an unavailable result column")
        if "color" in chart and chart["color"] not in columns:
            raise ValueError("Studio embedded chart color selects an unavailable result column")
        expected_options = {
            "chartType": chart["mark"],
            "category": f"csv:col{columns.index(chart['x']) + 1}",
            "series": [f"csv:col{columns.index(column) + 1}" for column in chart["y"]],
            "stacked": chart["stacked"],
            "embedded": embedded,
        }
        if "color" in chart:
            expected_options["color"] = f"csv:col{columns.index(chart['color']) + 1}"
        if definition["options"] != expected_options:
            raise ValueError("Studio embedded chart options differ from the full-result column mapping")
    else:
        diagram = view["view"]
        edges = diagram["edges"]
        if any(column not in columns for column in edges.values()):
            raise ValueError("Studio embedded diagram selects an unavailable result column")
        expected_edges = {key: f"csv:col{columns.index(column) + 1}" for key, column in edges.items()}
        expected_options = {"diagramType": "flow", "direction": diagram["direction"],
                            "edges": expected_edges, "embedded": embedded}
        if definition["options"] != expected_options:
            raise ValueError("Studio embedded diagram options differ from the full-result edge mapping")
    return embedded


def validate_component_options(record, *, embedded_schema=None, embedded_enabled=False):
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
    embedded = options.get("embedded") if isinstance(options, dict) else None
    if embedded is not None:
        embedded_fields = {
            "table": fields["table"] | {"embedded"},
            "summary": fields["summary"] | {"embedded"},
            "chart": {"chartType", "category", "series", "stacked", "color", "embedded"},
            "diagram": {"diagramType", "direction", "edges", "embedded"},
        }
        required_fields = {
            "chart": {"chartType", "category", "series", "stacked", "embedded"},
            "diagram": {"diagramType", "direction", "edges", "embedded"},
        }
        expected = embedded_fields.get(kind)
        required = required_fields.get(kind, expected)
        if not embedded_enabled or expected is None:
            raise ValueError("Studio embedded components are unavailable for the selected profile")
        if set(options) - expected or not required.issubset(options):
            raise ValueError("Studio Component options do not match its declared display type")
        _validate_embedded_envelope(record, embedded, embedded_schema)
        return
    expected = fields.get(kind)
    if kind not in fields or set(options) != expected:
        raise ValueError("Studio Component options do not match its declared display type")


def validate_embedded_attachment_refs(app_record, component_records, attachments):
    """Bind every embedded component to one exact PGlite blob in this same App."""
    if (not isinstance(app_record, dict) or not isinstance(component_records, list)
            or not isinstance(attachments, list)):
        raise ValueError("Studio embedded attachment inventory is unavailable")
    app_id = app_record.get("id")
    content = app_record.get("content", {})
    app_data = content.get("data", {}) if isinstance(content, dict) else None
    if app_record.get("kind") != "studio.app" or not isinstance(app_id, str):
        raise ValueError("Studio embedded attachment parent App is unavailable")
    if not isinstance(app_data, dict):
        raise ValueError("Studio embedded attachment parent App is unavailable")
    layout = app_data.get("layout", {})
    sections = layout.get("sections", []) if isinstance(layout, dict) else None
    if not isinstance(sections, list):
        raise ValueError("Studio embedded App component references are invalid")
    section_ids = [section.get("component") for section in sections if isinstance(section, dict)]
    if (len(section_ids) != len(sections)
            or any(not isinstance(identity, str) for identity in section_ids)
            or len(section_ids) != len(set(section_ids))):
        raise ValueError("Studio embedded App component references are invalid")
    components = {}
    for component in component_records:
        if not isinstance(component, dict):
            raise ValueError("Studio embedded App component inventory is invalid")
        if component.get("kind") == "studio.component":
            identity = component.get("id")
            if not isinstance(identity, str) or identity in components:
                raise ValueError("Studio embedded App component inventory is invalid")
            components[identity] = component
    references = []
    referenced_ids = set(section_ids)
    for identity in section_ids:
        component = components.get(identity)
        if component is None:
            continue
        content = component.get("content", {})
        data = content.get("data", {}) if isinstance(content, dict) else {}
        definition = data.get("definition", {}) if isinstance(data, dict) else {}
        options = definition.get("options", {}) if isinstance(definition, dict) else {}
        embedded = options.get("embedded") if isinstance(options, dict) else None
        if embedded is not None:
            if not isinstance(embedded, dict) or not isinstance(embedded.get("snapshot"), dict):
                raise ValueError("Studio embedded component snapshot reference is invalid")
            references.append(embedded["snapshot"])
    for identity, component in components.items():
        content = component.get("content", {})
        data = content.get("data", {}) if isinstance(content, dict) else {}
        definition = data.get("definition", {}) if isinstance(data, dict) else {}
        options = definition.get("options", {}) if isinstance(definition, dict) else {}
        if isinstance(options, dict) and options.get("embedded") is not None and identity not in referenced_ids:
            raise ValueError("Studio embedded component is not selected by its parent App")
    if any(not isinstance(item, dict) for item in attachments):
        raise ValueError("Studio embedded App attachment inventory is invalid")
    pglite = [item for item in attachments if isinstance(item, dict)
              and item.get("role") == PGLITE_ROLE and item.get("format") == PGLITE_FORMAT]
    other_pglite = [item for item in attachments if isinstance(item, dict)
                     and item.get("role") == PGLITE_ROLE]
    if len(other_pglite) != len(pglite):
        raise ValueError("Studio embedded App contains an unsupported PGlite attachment")
    if bool(references) != bool(pglite) or references and len(pglite) != 1:
        raise ValueError("Studio embedded component and App attachment must be selected together")
    if not references:
        return False
    attachment = pglite[0]
    protection = attachment.get("protection")
    locator = attachment.get("blob")
    effective_sha = (protection.get("contentSha256") if isinstance(protection, dict) else None)
    if effective_sha is None:
        effective_sha = attachment.get("sha256") or (locator.get("sha256") if isinstance(locator, dict) else None)
    pins = {key: attachment.get(key) for key in PGLITE_METADATA_FIELDS}
    for reference in references:
        if (reference.get("role") != PGLITE_ROLE or reference.get("format") != PGLITE_FORMAT
                or reference.get("sha256") != effective_sha
                or any(reference.get(key) != pins[key] for key in PGLITE_METADATA_FIELDS)):
            raise ValueError("Studio embedded snapshot does not match its same-App attachment")
    return True


def require_current_bindings(record, targets, *, embedded_schema=None, embedded_enabled=False):
    validate_component_options(record, embedded_schema=embedded_schema, embedded_enabled=embedded_enabled)
    result = app_binding_status(record, targets)
    if result is not None and not result["available"]:
        raise ValueError("Studio App binding is unavailable: " + ", ".join(result["reasons"]))
    return deepcopy(result)
