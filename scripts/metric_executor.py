"""Execute reviewed metric definitions against their bound read-only SQLite source."""
from __future__ import annotations

from datetime import date
import hashlib
import math
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import quote


class MetricExecutionError(ValueError):
    pass


def authorize_metric_reader(root, settings, authority, identity, metric, *, trusted_actor=None):
    """Check the authenticated host identity against the live native read policy.

    The mapping and authority path are operator-owned private host state. The
    identity itself is supplied by the authenticated MCP host; the request and
    compiled graph never choose a native policy actor.
    """
    from knowledge_operations import private_path
    from knowledge_store import SQLiteAuthority, StoreError, adopted_authority, resolve_store_dsn, utcnow
    from context_host import decode

    if not isinstance(identity, str) or not identity or identity != identity.strip():
        raise MetricExecutionError("metric execution requires an authenticated native reader")
    identity = identity.lower()
    try:
        if trusted_actor is None:
            mapping_path = private_path(Path(root), "_internal/metric-readers.json")
            with mapping_path.open("rb") as stream:
                raw = stream.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ValueError("host reader mapping is oversized")
            mapping = decode(raw)
            if not isinstance(mapping, dict) or set(mapping) != {"format", "principalsByIdentity"} \
                    or mapping["format"] != "metric-readers/v1" \
                    or not isinstance(mapping["principalsByIdentity"], dict) \
                    or len(mapping["principalsByIdentity"]) > 1000:
                raise ValueError("host reader mapping has an invalid shape")
            actor = mapping["principalsByIdentity"].get(identity)
        else:
            actor = trusted_actor
        if not isinstance(actor, str) or not actor.strip() or actor != actor.strip():
            raise MetricExecutionError("authenticated identity has no native metric reader mapping")
        configured = adopted_authority(settings)
        if not isinstance(configured, dict) or configured != authority:
            raise ValueError("adopted authority does not match the metric projection")
        dsn = resolve_store_dsn(settings, authority["store"])
        database = Path(dsn)
        if not database.is_absolute():
            raise ValueError("authority path must be absolute")
        relative = database.relative_to(Path(root).absolute()).as_posix()
        database = private_path(Path(root), relative)
        store = SQLiteAuthority(database, expected_binding=authority["binding"], readonly=True)
        try:
            collections = [collection for collection, spec in store.contract.collections.items()
                           if spec["kind"] == "metric"
                           and store.contract.policy.resources[spec["resource"]]["id"] == "semantic-metrics"]
            current = store.get(metric.get("id"), actor, at=utcnow()) if len(collections) == 1 else None
            if (not current or not current["record"] or current["record"]["collection"] != collections[0]
                    or current["withheldRelations"]):
                raise MetricExecutionError("native authority denies or has no current metric read access")
            content = current["record"]["content"]
            data = metric.get("data") if isinstance(metric.get("data"), dict) else {}
            projected_data = dict(data)
            projected_data.pop("governance", None)
            if any(content.get(key) != metric.get(key) for key in ("title", "text", "owner")) \
                    or content.get("data") != projected_data:
                raise MetricExecutionError("native metric revision differs from the committed projection")
        finally:
            store.close()
        return actor
    except MetricExecutionError:
        raise
    except (OSError, ValueError, KeyError, TypeError, StoreError) as exc:
        raise MetricExecutionError("native metric read authorization is unavailable") from exc


MAX_LIMIT = 500
MAX_FILTER_VALUES = 100
QUERY_SECONDS = 2.0
MAX_RESULT_VALUE_BYTES = 16 * 1024
MAX_RESULT_BYTES = 1024 * 1024
_ID = re.compile(r"^[a-z][a-z0-9_-]*$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TIME_FORMATS = {
    "day": "%Y-%m-%d",
    "week": "%Y-W%W",
    "month": "%Y-%m",
    "quarter": "%Y-Q",
    "year": "%Y",
}
_TRUST_TOKEN = object()


class _VerifiedProjection:
    __slots__ = ("metric_id", "governance", "definition_digest")

    def __init__(self, token, metric_id, governance, definition_digest):
        if token is not _TRUST_TOKEN:
            raise TypeError("verified projections are created only by receipt validation")
        self.metric_id = metric_id
        self.governance = governance
        self.definition_digest = definition_digest


def _definition_digest(metric):
    raw = json.dumps(metric, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def source_bindings(path=None):
    """Load host-private source bindings. A source's identity is never chosen by a request."""
    filename = path or os.environ.get("BRAIN_METRIC_SQLITE_SOURCES_FILE")
    if not filename:
        raise MetricExecutionError("metric execution is not configured on this host")
    try:
        value = json.loads(Path(filename).read_text())
    except (OSError, ValueError) as exc:
        raise MetricExecutionError("metric source bindings are unavailable") from exc
    if not isinstance(value, dict) or set(value) != {"format", "sources"} or value["format"] != "metric-sources/v1":
        raise MetricExecutionError("metric source bindings have an unsupported format")
    sources = value["sources"]
    if not isinstance(sources, dict):
        raise MetricExecutionError("metric source bindings must be an object")
    result = {}
    for source_id, item in sources.items():
        if not isinstance(source_id, str) or not source_id or not isinstance(item, dict) \
                or set(item) != {"driver", "database"} or item["driver"] != "sqlite" \
                or not isinstance(item["database"], str) or not Path(item["database"]).is_absolute():
            raise MetricExecutionError("each metric source binding must name an absolute SQLite database")
        result[source_id] = item["database"]
    return result


def validate_receipted_metric(root, authority, metric):
    """Bind a compiled metric back to its host-configured committed projection."""
    if not isinstance(authority, dict) or authority.get("projections") != "committed" \
            or not isinstance(authority.get("binding"), str) or not _SHA.fullmatch(authority["binding"]):
        raise MetricExecutionError("metric authority is not configured for committed projections")
    try:
        from projection_receipts import load
        projections = load(root, authority["binding"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise MetricExecutionError("metric projection receipt is unavailable or invalid") from exc
    selected = [(payload, receipt) for consumer, payload, receipt in projections
                if consumer == "semantic-layer"]
    if len(selected) != 1:
        raise MetricExecutionError("receipted semantic-layer projection is missing")
    payload, receipt = selected[0]
    graph = payload.get("graph") if isinstance(payload, dict) else None
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(nodes, list):
        raise MetricExecutionError("receipted semantic-layer projection is malformed")
    projected = [node for node in nodes if isinstance(node, dict) and node.get("id") == metric.get("id")]
    if len(projected) != 1:
        raise MetricExecutionError("metric is absent from its receipted semantic-layer projection")
    projected = dict(projected[0])
    compiled = dict(metric)
    expected_governance = {
        "consumer": "semantic-layer", "authority": receipt["authority"],
        "binding": receipt["binding"], "sequence": receipt["sequence"],
        "projectionSha256": receipt["sha256"],
    }
    data = compiled.get("data")
    projected_data = projected.get("data")
    if not isinstance(data, dict) or not isinstance(projected_data, dict) \
            or data.get("governance") != expected_governance:
        raise MetricExecutionError("metric governance does not match its verified projection receipt")
    compiled_data = dict(data)
    expected_data = dict(projected_data)
    compiled_data.pop("governance", None)
    expected_data.pop("governance", None)
    compiled["data"] = compiled_data
    projected["data"] = expected_data
    # `source` is attached by gen-brain as projection provenance and may not be
    # present in the authority record. All other claim fields must match exactly.
    compiled.pop("source", None)
    projected.pop("source", None)
    if compiled != projected:
        raise MetricExecutionError("compiled metric differs from its receipted authority record")
    try:
        digest = _definition_digest(metric)
    except (TypeError, ValueError) as exc:
        raise MetricExecutionError("metric definition is not finite JSON data") from exc
    return _VerifiedProjection(_TRUST_TOKEN, metric["id"], expected_governance, digest)


def _quoted(identifier):
    if not isinstance(identifier, str) or not identifier or "\x00" in identifier:
        raise MetricExecutionError("metric contains an invalid catalog identifier")
    return '"' + identifier.replace('"', '""') + '"'


def _typed(value, spec):
    kind = spec["type"]
    valid = False
    if kind == "string":
        valid = isinstance(value, str) and len(value) <= 1024
    elif kind == "integer":
        valid = type(value) is int
    elif kind == "number":
        valid = type(value) in (int, float) and abs(value) < 1e100
    elif kind == "boolean":
        valid = type(value) is bool
        if valid:
            value = int(value)
    elif kind == "date":
        valid = isinstance(value, str) and len(value) == 10
        if valid:
            try:
                date.fromisoformat(value)
            except ValueError:
                valid = False
    if not valid:
        raise MetricExecutionError(f"filter {spec['id']!r} has the wrong value type")
    if "enum" in spec and value not in spec["enum"]:
        raise MetricExecutionError(f"filter {spec['id']!r} value is outside its reviewed choices")
    if "minimum" in spec and value < spec["minimum"]:
        raise MetricExecutionError(f"filter {spec['id']!r} is below its reviewed minimum")
    if "maximum" in spec and value > spec["maximum"]:
        raise MetricExecutionError(f"filter {spec['id']!r} is above its reviewed maximum")
    return value


def _filter_clause(spec, value, field):
    if spec.get("operator") not in {"=", "!=", ">", ">=", "<", "<=", "in"}:
        raise MetricExecutionError("metric filter has an unsupported operator")
    if spec["operator"] == "in":
        if not isinstance(value, list) or not value or len(value) > MAX_FILTER_VALUES:
            raise MetricExecutionError(f"filter {spec['id']!r} requires 1..{MAX_FILTER_VALUES} values")
        values = [_typed(item, spec) for item in value]
        return f"{field} IN ({','.join('?' for _ in values)})", values
    return f"{field} {spec['operator']} ?", [_typed(value, spec)]


def build_query(metric, arguments, *, entity, fields, source_node, verification):
    """Compile an allowlisted metric definition; never accepts SQL or identifiers from a caller."""
    data = metric.get("data") if isinstance(metric.get("data"), dict) else {}
    if not isinstance(verification, _VerifiedProjection) or verification.metric_id != metric.get("id") \
            or data.get("governance") != verification.governance \
            or _definition_digest(metric) != verification.definition_digest:
        raise MetricExecutionError("metric is not from a receipted reviewed authority projection")
    if not isinstance(arguments, dict):
        raise MetricExecutionError("metric arguments must be an object")
    allowed = {"name", "dimensions", "filters", "grain", "limit"}
    if set(arguments) - allowed:
        raise MetricExecutionError("unknown metric argument")
    if data.get("datasource", {}).get("kind") != "sqlite" or not isinstance(data.get("datasource", {}).get("id"), str):
        raise MetricExecutionError("metric datasource is not supported")
    if not isinstance(entity, str) or entity != data.get("entity") or not isinstance(source_node, str):
        raise MetricExecutionError("metric source relationships do not match the reviewed definition")
    if not isinstance(fields, dict) or not fields:
        raise MetricExecutionError("metric source entity has no readable catalog fields")
    if not _ID.fullmatch(data.get("aggregation", "")):
        raise MetricExecutionError("metric has an unsupported aggregate")
    aggregate = data["aggregation"].upper()
    if aggregate not in {"SUM", "COUNT", "AVG", "MIN", "MAX"}:
        raise MetricExecutionError("metric has an unsupported aggregate")

    def category(name):
        node = fields.get(name)
        data = node.get("data") if isinstance(node, dict) else None
        raw = data.get("type") if isinstance(data, dict) else None
        if not isinstance(raw, str) or not raw.strip():
            return "unknown"
        value = raw.upper()
        if any(token in value for token in ("INT", "REAL", "FLOA", "DOUB", "NUM", "DEC")):
            return "number"
        if any(token in value for token in ("CHAR", "CLOB", "TEXT", "DATE", "TIME")):
            return "text"
        if "BLOB" in value:
            return "blob"
        return "other"

    measure = data.get("measure")
    if measure not in fields:
        raise MetricExecutionError("metric measure is not in its catalogued source entity")
    if aggregate in {"SUM", "AVG"} and category(measure) != "number":
        raise MetricExecutionError("sum and average metrics require a catalogued numeric measure")
    if aggregate in {"MIN", "MAX"} and category(measure) in {"blob", "unknown"}:
        raise MetricExecutionError("minimum and maximum metrics require a scalar catalogued measure")
    definitions = data.get("dimensions")
    if not isinstance(definitions, list):
        raise MetricExecutionError("metric dimensions are malformed")
    requested_dimensions = arguments.get("dimensions", [])
    if not isinstance(requested_dimensions, list) or len(requested_dimensions) > 16 \
            or any(not isinstance(item, str) for item in requested_dimensions) \
            or len(set(requested_dimensions)) != len(requested_dimensions):
        raise MetricExecutionError("dimensions must be a unique list of at most 16 reviewed ids")
    dimension_fields = {}
    for definition in definitions:
        if not isinstance(definition, dict) or not _ID.fullmatch(definition.get("id", "")) \
                or definition.get("field") not in fields or definition["id"] in dimension_fields:
            raise MetricExecutionError("metric dimension is not in its catalogued source entity")
        if category(definition["field"]) in {"blob", "unknown"}:
            raise MetricExecutionError("metric dimensions require scalar catalogued fields")
        dimension_fields[definition["id"]] = definition["field"]
    if set(requested_dimensions) - set(dimension_fields):
        raise MetricExecutionError("requested dimension is not declared by this metric")

    select = []
    group_by = []
    referenced = {measure}
    for dimension_id in requested_dimensions:
        dimension_name = dimension_fields[dimension_id]
        referenced.add(dimension_name)
        field = _quoted(dimension_name)
        select.append(f"{field} AS {_quoted(dimension_id)}")
        group_by.append(field)
    grain = data.get("grain")
    grain_value = arguments.get("grain", grain.get("default") if isinstance(grain, dict) else None)
    if "grain" in arguments and grain_value is None:
        raise MetricExecutionError("grain must be a declared time grain")
    if grain_value is not None:
        if not isinstance(grain, dict) or grain_value not in grain.get("allowed", []):
            raise MetricExecutionError("requested time grain is not declared by this metric")
        if grain.get("field") not in fields:
            raise MetricExecutionError("metric time grain is not in its catalogued source entity")
        referenced.add(grain["field"])
        expression = f"strftime('{_TIME_FORMATS[grain_value]}', {_quoted(grain['field'])})"
        if grain_value == "quarter":
            expression = f"strftime('%Y', {_quoted(grain['field'])}) || '-Q' || ((cast(strftime('%m', {_quoted(grain['field'])}) as integer) + 2) / 3)"
        select.append(f"{expression} AS \"time\"")
        group_by.append(expression)

    filters = arguments.get("filters", {})
    if not isinstance(filters, dict):
        raise MetricExecutionError("filters must be an object")
    filter_defs = data.get("filters")
    if not isinstance(filter_defs, list):
        raise MetricExecutionError("metric filters are malformed")
    filter_by_id = {}
    for spec in filter_defs:
        if not isinstance(spec, dict) or not _ID.fullmatch(spec.get("id", "")) \
                or spec.get("field") not in fields or spec["id"] in filter_by_id:
            raise MetricExecutionError("metric filter is not in its catalogued source entity")
        expected_category = "number" if spec.get("type") in {"number", "integer", "boolean"} else "text"
        if category(spec["field"]) != expected_category:
            raise MetricExecutionError("metric filter type does not match its catalogued source field")
        filter_by_id[spec["id"]] = spec
    if set(filters) - set(filter_by_id):
        raise MetricExecutionError("filter is not declared by this metric")
    where, parameters = [], []
    for filter_id, spec in filter_by_id.items():
        if filter_id not in filters:
            if spec.get("required"):
                raise MetricExecutionError(f"required filter {filter_id!r} is missing")
            continue
        clause, values = _filter_clause(spec, filters[filter_id], _quoted(spec["field"]))
        referenced.add(spec["field"])
        where.append(clause)
        parameters.extend(values)

    limit = arguments.get("limit", 100)
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise MetricExecutionError(f"limit must be between 1 and {MAX_LIMIT}")
    select.append(f"{aggregate}({_quoted(measure)}) AS \"value\"")
    sql = f"SELECT {', '.join(select)} FROM {_quoted(entity)}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    if group_by:
        sql += " GROUP BY " + ", ".join(group_by)
        sql += " ORDER BY " + ", ".join(group_by)
    sql += " LIMIT ?"
    parameters.append(limit + 1)
    return sql, parameters, limit, source_node, referenced


def execute_metric(metric, arguments, *, entity, fields, source_node, database, projection_root, authority):
    verification = validate_receipted_metric(projection_root, authority, metric)
    sql, parameters, limit, _, referenced = build_query(
        metric, arguments, entity=entity, fields=fields, source_node=source_node, verification=verification)
    path = Path(database)
    if not path.is_absolute() or not path.is_file():
        raise MetricExecutionError("bound metric database is unavailable")
    uri = "file:" + quote(str(path), safe="/:\\") + "?mode=ro"
    connection = None
    started = time.monotonic()
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=0.25)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=250")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RESULT_VALUE_BYTES)
        connection.set_progress_handler(lambda: int(time.monotonic() - started > QUERY_SECONDS), 1000)
        # Begin before inspecting sqlite_master/table_info so schema validation and
        # execution share one SQLite read snapshot.
        connection.execute("BEGIN")
        catalog = {row[1]: row for row in connection.execute(f"PRAGMA table_info({_quoted(entity)})")}
        columns = set(catalog)
        # All execution identifiers were checked against the compiled catalog; verify the used columns physically.
        if not referenced.issubset(columns) or columns != set(fields):
            raise MetricExecutionError("metric source schema has drifted from its reviewed catalog")
        for name, field_node in fields.items():
            expected = field_node.get("data") if isinstance(field_node, dict) else None
            actual = catalog[name]
            if isinstance(expected, dict) and isinstance(expected.get("type"), str) \
                    and " ".join(expected["type"].upper().split()) != " ".join(str(actual[2]).upper().split()):
                raise MetricExecutionError("metric source column types have drifted from the reviewed catalog")
            if isinstance(expected, dict) and type(expected.get("is_pk")) is bool \
                    and expected["is_pk"] != bool(actual[5]):
                raise MetricExecutionError("metric source key metadata has drifted from the reviewed catalog")
        cursor = connection.execute(sql, parameters)
        names = [column[0] for column in cursor.description]
        output_rows = []
        result_size = len(json.dumps({"metric": metric["id"], "revision": metric["data"]["governance"],
                                      "unit": metric["data"]["unit"], "format": metric["data"]["format"],
                                      "rows": []}, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        while True:
            row = cursor.fetchone()
            if row is None:
                break
            if len(output_rows) >= limit:
                raise MetricExecutionError("metric result exceeds the configured row limit")
            output = {}
            for name, value in zip(names, row):
                if isinstance(value, float) and not math.isfinite(value):
                    raise MetricExecutionError("metric result contains a non-finite number")
                if isinstance(value, str):
                    try:
                        size = len(value.encode("utf-8"))
                    except UnicodeEncodeError as exc:
                        raise MetricExecutionError("metric result contains invalid UTF-8 text") from exc
                    if size > MAX_RESULT_VALUE_BYTES:
                        raise MetricExecutionError("metric result value exceeds the configured byte limit")
                elif value is not None and type(value) not in (int, float):
                    raise MetricExecutionError("metric result contains an unsupported value")
                output[name] = value
            output_rows.append(output)
            try:
                result_size += len(json.dumps(output, ensure_ascii=False, allow_nan=False,
                                              separators=(",", ":")).encode("utf-8")) + 1
            except (TypeError, ValueError, UnicodeEncodeError) as exc:
                raise MetricExecutionError("metric result is not finite JSON data") from exc
            if result_size > MAX_RESULT_BYTES:
                raise MetricExecutionError("metric result exceeds the configured byte limit")
        result = {"metric": metric["id"], "revision": metric["data"]["governance"],
                  "unit": metric["data"]["unit"], "format": metric["data"]["format"],
                  "rows": output_rows}
        try:
            encoded_result = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise MetricExecutionError("metric result is not finite JSON data") from exc
        if len(encoded_result) > MAX_RESULT_BYTES:
            raise MetricExecutionError("metric result exceeds the configured byte limit")
        return result
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc).lower():
            raise MetricExecutionError("metric query exceeded its time limit") from exc
        raise MetricExecutionError("metric source query failed or its schema changed") from exc
    except sqlite3.Error as exc:
        if "too big" in str(exc).lower():
            raise MetricExecutionError("metric result value exceeds the configured byte limit") from exc
        raise MetricExecutionError("metric source is unavailable") from exc
    finally:
        if connection is not None:
            connection.close()
