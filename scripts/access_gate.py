"""Python twin of access.js's read gate (#53) for Python serving paths (#459).

access.js stays the source of the rules. A Python host that answers reads (the
MCP endpoint in runtime/portal-container/) needs the same answers the Worker
gives: who is an owner, which paths a reader may open, which tools a reader may
call, and which compiled records survive for that reader. This module copies
exactly those parts: `client.config.json` `access` (owners, restricted paths
and their extra readers, restricted tools), the person register (#212) and the
graph, pack and unfiltered-artifact checks. tests/test_access_gate.py runs both
engines over shared fixtures, so the copy cannot drift silently.

The modes match makeAccess:
  * no `access` block: open. Every predicate permits, filters return their input.
  * a valid block that restricts nothing: open, but `is_owner` checks owners.
  * owners and restricted tools, no paths: paths stay open, tools are gated.
  * restricted paths: the full gate.
A block this module cannot parse is LOCKDOWN, as in access.js: nobody is an
owner, no restricted-mode path is readable and no tool is allowed. A register
that cannot be read unambiguously locks down a gate that relies on it.

Identity is an email (lowercased), as the Worker's Cloudflare Access header
gives it; an empty identity is never an owner and never a reader of a
restricted path.
"""
from __future__ import annotations

import re
from urllib.parse import unquote

# JavaScript's \s (WhiteSpace and LineTerminator), spelled out: Python's \s
# differs at the edges (\x1c-\x1f, \x85, \ufeff), and the patterns below must
# match exactly what access.js matches.
_JS_SPACE = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_JS_TRIM = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a" \
           "\u2028\u2029\u202f\u205f\u3000\ufeff"

_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)
_MALFORMED_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_GLOB_META = re.compile(r"[*?]")
# Deep-link parameters naming a document, and path or filename tokens inside
# prose (mentionsRestricted). re.ASCII keeps IGNORECASE to ASCII letters, as a
# non-unicode JavaScript /i does.
_DEEP_LINK = re.compile(r"[?&](?:f|doc|path|file)=([^&#" + _JS_SPACE + r"\"'<>\)\]]+)", re.IGNORECASE | re.ASCII)
_PATH_TOKEN = re.compile(r"[A-Za-z0-9_@%.~\-]+(?:[/\\][A-Za-z0-9_@%.~\-]+)+")
_FILE_TOKEN = re.compile(
    r"(?:^|[" + _JS_SPACE + r"(\"'=:\[>])([A-Za-z0-9_.\-]+\.(?:md|markdown|txt|json|jsonl|ndjson|csv|sql|ya?ml|pdf"
    r"|docx?|pptx?|xlsx?))(?=\Z|[" + _JS_SPACE + r")\"',;:\]<>?#])", re.IGNORECASE | re.ASCII)
_TRAILING_DOTS = re.compile(r"\.+\Z")

_KNOWN_KEYS = frozenset({"owners", "admins", "restricted", "owner_only", "privateDocs",
                         "restricted_tools", "owner_only_tools"})
_RULE_KEYS = ("restricted", "owner_only", "privateDocs")
# The artifacts access.js scrubs per reader (ARTIFACT_FILTERS). A Python host
# that does not carry those filters must not serve these raw to a reader.
FILTERED_ARTIFACTS = frozenset({"app/knowledge-pack.json", "app/brain.json", "app/knowledge_graph.json",
                                "app/docs-manifest.json", "app/kinds.json", "app/deliverables.json"})
_MEMO_LIMIT = 512
UNBOUND = object()


def _js_trim(text):
    return text.strip(_JS_TRIM)


def decode_uri_component(text):
    """JavaScript's decodeURIComponent: a malformed escape or invalid UTF-8 raises."""
    if _MALFORMED_ESCAPE.search(text):
        raise ValueError("malformed percent escape")
    return unquote(text, errors="strict")


def normalize_path(raw, keep_query=False):
    """access.js normalizePath: the one string the asset layer would serve.

    Percent-encoding is decoded up to three times, backslashes become slashes,
    a request path ends at its query or fragment (a rule keeps them, since `?`
    is a glob character there), and "." / ".." / empty segments resolve.
    """
    s = "" if raw is None else raw if isinstance(raw, str) else str(raw)
    for _ in range(3):
        if not _ESCAPE.search(s):
            break
        try:
            decoded = decode_uri_component(s)
        except ValueError:
            break
        if decoded == s:
            break
        s = decoded
    s = s.replace("\\", "/")
    if not keep_query:
        s = s.split("?")[0].split("#")[0]
    out = []
    for segment in s.split("/"):
        if not segment or segment == ".":
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    joined = "/".join(out)
    return joined[len("_site/"):] if joined.startswith("_site/") else joined


def _path_string(value):
    return isinstance(value, str) and len(value) > 0


def node_paths(node):
    """Every document path a compiled node carries, whatever shape it uses."""
    out = []

    def push(value):
        if _path_string(value):
            out.append(value)
        elif isinstance(value, dict) and _path_string(value.get("path")):
            out.append(value["path"])

    if not isinstance(node, dict):
        return out
    source = node.get("source")
    if isinstance(source, list):
        for item in source:
            push(item)
    else:
        push(source)
    data = node.get("data")
    if isinstance(data, dict):
        push(data.get("path"))
        if isinstance(data.get("sourcePaths"), list):
            for item in data["sourcePaths"]:
                push(item)
    push(node.get("path"))
    evidence = node.get("evidence")
    if isinstance(evidence, dict):
        for key in ("sources", "representations"):
            if isinstance(evidence.get(key), list):
                for item in evidence[key]:
                    push(item)
    return out


def _compile_glob(rule):
    """`**` crosses segments, `*` and `?` stay inside one, everything else is literal."""
    parts, i = [], 0
    while i < len(rule):
        c = rule[i]
        if c == "*":
            if i + 1 < len(rule) and rule[i + 1] == "*":
                i += 1
                parts.append(r"[\s\S]*")
            else:
                parts.append("[^/]*")
        elif c == "?":
            parts.append("[^/]")
        else:
            parts.append(re.escape(c))
        i += 1
    return re.compile("".join(parts))


class _Rule:
    """One restricted entry: case-insensitive, ancestor-aware, `a/**` also covers `a`."""

    def __init__(self, rule, readers):
        self.rule = rule
        self.readers = tuple(readers)
        self._bare = rule[:-3] if rule.endswith("/**") else None
        self._glob = _compile_glob(rule) if _GLOB_META.search(rule) else None

    def _hit(self, s):
        exact = self._glob.fullmatch(s) is not None if self._glob is not None else s == self.rule
        return exact or (self._bare is not None and s == self._bare)

    def test(self, path):
        if not path:
            return False
        s = path
        while True:
            if self._hit(s):
                return True
            i = s.rfind("/")
            if i < 0:
                return False
            s = s[:i]


def _compile_rule(raw):
    rule = normalize_path(raw, True).lower()
    return rule or None


def _string_list(value, problems, where):
    if value is None:
        return []
    if not isinstance(value, list):
        problems.append(f"{where} must be an array")
        return []
    out = []
    for item in value:
        if not isinstance(item, str) or not _js_trim(item):
            problems.append(f"{where} entries must be non-empty strings")
            continue
        trimmed = _js_trim(item)
        # An OIDC subject is case-sensitive; every other identity is not.
        out.append(trimmed if trimmed.startswith("oidc:") else trimmed.lower())
    return out


def _parse(raw):
    problems = []
    if raw is None:
        return {"present": False, "problems": problems, "owners": [], "rules": [], "tools": []}
    if not isinstance(raw, dict):
        return {"present": True, "problems": ["access must be an object"], "owners": [], "rules": [], "tools": []}
    for key in raw:
        if not key.startswith("$") and key not in _KNOWN_KEYS:
            problems.append(f"unknown access key: {key}")
    owners = (_string_list(raw.get("owners"), problems, "access.owners")
              + _string_list(raw.get("admins"), problems, "access.admins"))
    rules = []
    for key in _RULE_KEYS:
        value = raw.get(key)
        if value is None:
            continue
        where = f"access.{key}"
        if not isinstance(value, list):
            problems.append(f"{where} must be an array")
            continue
        for entry in value:
            if isinstance(entry, str):
                rule = _compile_rule(entry)
                if rule is None:
                    problems.append(f'{where}: "{entry}" is not a usable path')
                    continue
                rules.append(_Rule(rule, ()))
                continue
            if not isinstance(entry, dict):
                problems.append(f"{where} entries must be a path string or {{path, owners}}")
                continue
            path = entry["path"] if "path" in entry else entry.get("glob")
            if not isinstance(path, str) or not _js_trim(path):
                problems.append(f'{where} entries need a non-empty "path"')
                continue
            rule = _compile_rule(path)
            if rule is None:
                problems.append(f'{where}: "{path}" is not a usable path')
                continue
            readers = _string_list(entry.get("owners"), problems, f"{where}[{path}].owners")
            for name in entry:
                if not name.startswith("$") and name not in ("path", "glob", "owners"):
                    problems.append(f"{where}[{path}]: unknown key {name}")
            rules.append(_Rule(rule, readers))
    tools = (_string_list(raw.get("restricted_tools"), problems, "access.restricted_tools")
             + _string_list(raw.get("owner_only_tools"), problems, "access.owner_only_tools"))
    return {"present": True, "problems": problems, "owners": owners, "rules": rules, "tools": tools}


def _principal_spec(spec):
    return spec.startswith("person:") or spec.startswith("oidc:")


def _identity(email):
    return _js_trim(email if isinstance(email, str) else "").lower()


class Gate:
    """One access configuration bound to one person register (or none yet)."""

    def __init__(self, access_cfg, register=UNBOUND):
        self._config = access_cfg
        parsed = _parse(access_cfg)
        problems = list(parsed["problems"])
        principals = None
        register_problems = []
        if register is not UNBOUND:
            from principals import PrincipalError, Principals
            try:
                principals = Principals(register)
            except PrincipalError as exc:
                register_problems.append(f"person register: {exc}")
        specs = parsed["owners"] + [spec for rule in parsed["rules"] for spec in rule.readers]
        uses_principals = parsed["present"] and not problems and any(_principal_spec(s) for s in specs)
        if uses_principals and register_problems:
            problems.extend(register_problems)
        self.present = parsed["present"]
        self.problems = tuple(problems)
        self.lockdown = bool(problems)
        self.needs_register = uses_principals and register is UNBOUND
        self._principals = None if register_problems else principals
        self._owners = () if self.lockdown else tuple(parsed["owners"])
        self._rules = () if self.lockdown else tuple(parsed["rules"])
        self._tools = frozenset() if self.lockdown else frozenset(parsed["tools"])
        if not self.present:
            self._mode = "open"
        elif not problems and not parsed["rules"] and not parsed["tools"]:
            self._mode = "owners"
        elif not self.lockdown and not self._rules:
            self._mode = "tools"
        else:
            self._mode = "paths"
        self.enabled = self._mode in ("tools", "paths")
        self.paths_enabled = self._mode == "paths"
        self._memo = {}

    def bind_register(self, register):
        """The same configuration with app/people.json bound (#212)."""
        return Gate(self._config, register)

    def _matches(self, spec, email):
        if not spec or not email:
            return False
        if _principal_spec(spec):
            principal = self._principals.resolve("access:" + email) if self._principals else None
            return bool(principal) and self._principals.resolve(spec) == principal
        if "@" in spec:
            return spec == email
        return spec == email.split("@")[0]

    def is_owner(self, email):
        if self._mode == "open":
            return True
        if self.lockdown:
            return False
        identity = _identity(email)
        return bool(identity) and any(self._matches(spec, identity) for spec in self._owners)

    def _rules_for(self, path):
        key = normalize_path(path).lower()
        if not key:
            return ()
        hits = self._memo.get(key)
        if hits is None:
            hits = tuple(rule for rule in self._rules if rule.test(key))
            if len(self._memo) < _MEMO_LIMIT:
                self._memo[key] = hits
        return hits

    def is_restricted_path(self, path):
        if not self.paths_enabled:
            return False
        return self.lockdown or bool(self._rules_for(path))

    def can_read(self, path, email):
        """A reader must satisfy every rule that matches the path."""
        if not self.paths_enabled:
            return True
        if self.lockdown:
            return False
        hits = self._rules_for(path)
        if not hits:
            return True
        if self.is_owner(email):
            return True
        identity = _identity(email)
        if not identity:
            return False
        return all(any(self._matches(spec, identity) for spec in rule.readers) for rule in hits)

    def allow_for(self, email):
        """A per-request read predicate with one identity resolution."""
        if not self.paths_enabled:
            return lambda path: True
        if self.lockdown:
            return lambda path: False
        if self.is_owner(email):
            return lambda path: True
        seen = {}

        def allow(path):
            key = "" if path is None else path if isinstance(path, str) else str(path)
            if key not in seen:
                verdict = self.can_read(key, email)
                if len(seen) >= _MEMO_LIMIT:
                    return verdict
                seen[key] = verdict
            return seen[key]
        return allow

    def tool_allowed(self, name, email):
        if self._mode in ("open", "owners"):
            return True
        if self.lockdown:
            return False
        if str(name or "").lower() not in self._tools:
            return True
        return self.is_owner(email)

    def mentions_restricted(self, value, allow, depth=0):
        """Whether a value names a path this reader may not read: strings, list
        members, object keys and values, prose paths, deep links and filenames."""
        candidates = mention_candidates(value, depth)
        return candidates is None or any(not allow(candidate) for candidate in candidates)

    def rule_indices(self, path):
        """The restricted rules matching a path; who asks does not matter."""
        key = normalize_path(path).lower()
        return tuple(i for i, rule in enumerate(self._rules) if rule.test(key)) if key else ()

    def satisfied_rules(self, email):
        """Per restricted rule, whether a reader who is not an owner may read what it covers."""
        identity = _identity(email)
        return tuple(bool(identity) and any(self._matches(spec, identity) for spec in rule.readers)
                     for rule in self._rules)

    def filter_graph(self, graph, email):
        """Nodes this reader may see, and only the edges between them."""
        if not isinstance(graph, dict):
            return {"nodes": [], "edges": []}
        if not self.paths_enabled or self.is_owner(email):
            return graph
        allow = self.allow_for(email)
        nodes = [node for node in graph.get("nodes") or [] if isinstance(node, dict)
                 and all(allow(path) for path in node_paths(node)) and not self.mentions_restricted(node, allow)]
        keep = {node.get("id") for node in nodes}
        edges = [edge for edge in graph.get("edges") or [] if isinstance(edge, dict)
                 and edge.get("source") in keep and edge.get("target") in keep
                 and (not edge.get("evidence") or all(allow(p) for p in node_paths({"evidence": edge["evidence"]})))
                 and not self.mentions_restricted(edge, allow)]
        out = dict(graph, nodes=nodes, edges=edges)
        meta = graph.get("meta")
        if isinstance(meta, dict):
            visible_meta = {key: meta[key] for key in ("version", "generator", "ontology")
                            if key in meta and not self.mentions_restricted(meta[key], allow)}
            visible_meta["counts"] = {"nodes": len(nodes), "edges": len(edges)}
            out["meta"] = visible_meta
        for key, value in list(out.items()):
            if key not in ("meta", "nodes", "edges") and self.mentions_restricted(value, allow):
                del out[key]
        if "count" in out:
            out["count"] = len(nodes)
        if "counts" in out:
            out["counts"] = {"nodes": len(nodes), "edges": len(edges)}
        return out

    def filter_pack_items(self, items, email):
        if not self.paths_enabled:
            return items
        if not isinstance(items, list):
            return []
        allow = self.allow_for(email)
        return [item for item in items if not (isinstance(item, dict) and _path_string(item.get("path")))
                or allow(item["path"])]

    def filter_pack(self, pack, email):
        if not isinstance(pack, dict):
            return {"count": 0, "items": []}
        allow = self.allow_for(email)
        out = dict(pack)
        out["items"] = self.filter_pack_items(pack.get("items"), email)
        if "count" in out:
            out["count"] = len(out["items"])
        for key in ("backlinks", "wikilinks"):
            if key in out:
                out[key] = self._filter_path_map(out[key], allow)
        if "dangling" in out:
            rows = []
            for row in pack.get("dangling") if isinstance(pack.get("dangling"), list) else []:
                if not isinstance(row, dict) or (_path_string(row.get("target")) and not allow(row["target"])):
                    continue
                item = dict(row)
                if isinstance(item.get("sources"), list):
                    item["sources"] = [path for path in item["sources"] if allow(path)]
                    if not item["sources"]:
                        continue
                rows.append(item)
            out["dangling"] = rows
        return out

    @staticmethod
    def _filter_path_map(value, allow):
        if not isinstance(value, dict):
            return {}
        out = {}
        for key, member in value.items():
            if not allow(key):
                continue
            if isinstance(member, list):
                kept = [path for path in member if _path_string(path) and allow(path)]
                if kept:
                    out[key] = kept
            elif _path_string(member):
                if allow(member):
                    out[key] = member
            else:
                out[key] = member
        return out

    def filter_docs_manifest(self, manifest, email):
        if not isinstance(manifest, dict):
            return {"sections": []}
        sections = []
        for section in manifest.get("sections") if isinstance(manifest.get("sections"), list) else []:
            if not isinstance(section, dict):
                sections.append(section)
                continue
            docs = self.filter_pack_items(section.get("docs"), email)
            row = dict(section, docs=docs)
            if "count" in row:
                row["count"] = len(docs)
            sections.append(row)
        return dict(manifest, sections=sections)

    def filter_kinds(self, manifest, email):
        if not isinstance(manifest, dict):
            return {"kinds": []}
        allow = self.allow_for(email)
        kinds = []
        for kind in manifest.get("kinds") if isinstance(manifest.get("kinds"), list) else []:
            if not isinstance(kind, dict):
                continue
            artifact = kind.get("artifact")
            if ((_path_string(artifact) and not allow(artifact)) or self.mentions_restricted(kind, allow)):
                continue
            kinds.append(kind)
        header = {key: value for key, value in manifest.items() if key != "kinds"
                  and not self.mentions_restricted(key, allow) and not self.mentions_restricted(value, allow)}
        if "count" in header:
            header["count"] = len(kinds)
        return dict(header, kinds=kinds)

    def filter_deliverables(self, data, email):
        if self.is_owner(email) or not self.paths_enabled:
            return data
        allow = self.allow_for(email)
        rows = data.get("deliverables") if isinstance(data, dict) else None
        deliverables = [row for row in rows if isinstance(row, dict) and not self.mentions_restricted(row, allow)] \
            if isinstance(rows, list) else []
        header = {key: data[key] for key in ("version", "updated")
                  if isinstance(data, dict) and key in data and not self.mentions_restricted(data[key], allow)}
        if isinstance(data, dict) and "count" in data:
            header["count"] = len(deliverables)
        header["deliverables"] = deliverables
        return header

    def filter_artifact(self, key, data, email):
        key = normalize_path(key)
        if key in ("app/brain.json", "app/knowledge_graph.json"):
            return self.filter_graph(data, email)
        if key == "app/knowledge-pack.json":
            return self.filter_pack(data, email)
        if key == "app/docs-manifest.json":
            return self.filter_docs_manifest(data, email)
        if key == "app/kinds.json":
            return self.filter_kinds(data, email)
        if key == "app/deliverables.json":
            return self.filter_deliverables(data, email)
        return data

    def graph_metadata(self, graph):
        def tally(values):
            counts = {}
            for value in values:
                counts[value] = counts.get(value, 0) + 1
            return dict(sorted(counts.items()))
        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        edges = graph.get("edges") if isinstance(graph, dict) else None
        nodes = nodes if isinstance(nodes, list) else []
        edges = edges if isinstance(edges, list) else []
        by_kind = tally([str(node.get("kind") or "(none)") for node in nodes if isinstance(node, dict)])
        by_source = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            source = node.get("source")
            sources = source if isinstance(source, list) else [source]
            by_source.extend(item if isinstance(item, str) else item.get("path", "(none)")
                             if isinstance(item, dict) else "(none)" for item in sources)
        return {"version": (graph.get("meta") or {}).get("version", "1") if isinstance(graph, dict) else "1",
                "generator": (graph.get("meta") or {}).get("generator", "gen-brain") if isinstance(graph, dict) else "gen-brain",
                "counts": {"nodes": len(nodes), "edges": len(edges), "by_kind": by_kind,
                           "by_source": tally(by_source)}}

    def filter_brain_meta(self, graph, email):
        return self.graph_metadata(self.filter_graph(graph, email))

    def filter_brain_manifest(self, manifest, graph, schema, email):
        """Produce the same reader-specific inventory as access.js or fail closed."""
        def obj(value):
            return isinstance(value, dict)

        if (not obj(manifest) or manifest.get("manifest") != "brain-manifest/v1"
                or manifest.get("generator") != "gen-manifest" or not obj(graph)
                or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list)
                or not obj(schema) or not isinstance(schema.get("kinds"), list)
                or any(not obj(node) or not isinstance(node.get("kind"), str) for node in graph["nodes"])
                or any(not obj(kind) or not isinstance(kind.get("id"), str)
                       or not (kind.get("node") is None or isinstance(kind.get("node"), str)
                               or isinstance(kind.get("node"), list) and all(isinstance(n, str) for n in kind["node"]))
                       for kind in schema["kinds"])):
            return None
        allow = self.allow_for(email)

        def pick(value, keys):
            return {key: value[key] for key in keys if isinstance(value, dict) and key in value
                    and not self.mentions_restricted(value[key], allow)}

        kinds = [kind for kind in schema["kinds"] if not self.mentions_restricted(kind, allow)
                 and all(not isinstance(path, str) or allow(path)
                         for path in (kind.get("storage") if isinstance(kind.get("storage"), list)
                                      else [kind.get("storage")]))]
        counts = self.graph_metadata(self.filter_graph(graph, email))["counts"]
        populated = {kind["id"] for kind in kinds
                     if any(counts["by_kind"].get(name, 0) > 0
                            for name in (kind.get("node") if isinstance(kind.get("node"), list)
                                         else [kind.get("node")]) if name)}
        ids = {kind["id"] for kind in kinds}
        substrate = manifest.get("substrate") if isinstance(manifest.get("substrate"), dict) else {}
        graduation = substrate.get("graduation") if isinstance(substrate.get("graduation"), dict) else {}
        threshold = graduation.get("threshold_nodes")
        policy = manifest.get("policy") if isinstance(manifest.get("policy"), dict) else {}
        if (type(threshold) is not int or threshold < 0 or not isinstance(manifest.get("projections"), list)
                or not isinstance(policy.get("publishes"), list) or not isinstance(policy.get("withholds"), list)):
            return None
        projections = [pick(row, ("resolution", "artifact", "enabled", "present"))
                       for row in manifest["projections"] if isinstance(row, dict)
                       and isinstance(row.get("artifact"), str) and allow(row["artifact"])
                       and not self.mentions_restricted(row, allow)]
        out = {
            "manifest": manifest["manifest"], "generator": manifest["generator"],
            "identity": pick(manifest.get("identity"), ("id", "name", "engagement", "domain")),
            "scope": pick(manifest.get("scope"), ("level", "id", "parent", "peers")),
            "profile": pick(manifest.get("profile"), ("base", "overlays", "declared", "schema_version", "contract_version")),
            "engine": pick(manifest.get("engine"), ("brain_version", "schema_present", "gates")),
            "inventory": {"nodes": counts["nodes"], "edges": counts["edges"], "kinds_declared": len(ids),
                          "kinds_populated": len(populated), "by_kind": counts["by_kind"],
                          "unpopulated": sorted(ids - populated)},
            "projections": projections,
            "substrate": {**pick(substrate, ("tier", "store", "blobs", "vectors")),
                          "deploy": pick(substrate.get("deploy"), ("target", "persistence", "replicas")),
                          "graduation": {"needed": threshold > 0 and counts["nodes"] > threshold,
                                         "threshold_nodes": threshold, "current_nodes": counts["nodes"]}},
            "policy": {"access_gate": policy.get("access_gate"),
                       "publishes": [item for item in policy["publishes"] if item in ids],
                       "withholds": [item for item in policy["withholds"] if item in ids]},
            "surfaces": pick(manifest.get("surfaces"), ("portal", "chat", "store", "template", "features")),
        }
        required = {"identity": ("id", "name"), "scope": ("level", "id", "parent", "peers"),
                    "profile": ("base", "overlays", "schema_version", "contract_version"),
                    "engine": ("brain_version", "schema_present", "gates"),
                    "substrate": ("tier", "store", "blobs", "vectors", "deploy"),
                    "surfaces": ("store", "features")}
        if any(any(field not in out[key] for field in fields) for key, fields in required.items()) \
                or self.mentions_restricted(out, allow):
            return None
        return out

    def filter_config(self, config, email):
        if not isinstance(config, dict):
            return config
        out = {key: value for key, value in config.items() if key != "access"}
        if isinstance(out.get("pages"), list):
            out["pages"] = [page for page in out["pages"] if self.page_allowed(page, email)]
        portal = out.get("portal")
        experience = portal.get("experience") if isinstance(portal, dict) else None
        records = experience.get("recordViews") if isinstance(experience, dict) else None
        if isinstance(experience, dict) and "recordViews" in experience:
            allow = self.allow_for(email)
            raw_pages = records.get("pages") if isinstance(records, dict) else None
            pages = []
            for page in raw_pages if isinstance(raw_pages, list) else []:
                if not isinstance(page, dict) or not isinstance(page.get("url"), str) or not self.page_allowed({"url": page["url"]}, email):
                    continue
                raw_views = page.get("views")
                views = [view for view in raw_views if isinstance(view, dict)
                         and _path_string(view.get("artifact")) and allow(view["artifact"])
                         and not self.mentions_restricted(view, allow)] if isinstance(raw_views, list) else []
                ids = {view.get("id") for view in views}
                pages.append({"url": page["url"], "views": views,
                              "entry": page.get("entry") if isinstance(page.get("entry"), str) and page.get("entry") in ids
                              else next((v.get("id", "") for v in views), ""),
                              "pinned": [key for key in page.get("pinned", []) if key in ids]
                              if isinstance(page.get("pinned"), list) else []})
            allowed = {view.get("kind") for page in pages for view in page["views"]}
            descriptors = experience.get("recordViewDescriptors")
            descriptors = {key: value for key, value in descriptors.items() if key in allowed} \
                if isinstance(descriptors, dict) else {}
            filtered_records = {"protocolVersion": records.get("protocolVersion"), "pages": pages} \
                if isinstance(records, dict) else None
            out["portal"] = dict(portal, experience=dict(experience, recordViewDescriptors=descriptors,
                                                          recordViews=filtered_records))
        return out

    def page_allowed(self, page, email):
        url = str(page.get("url") or "") if isinstance(page, dict) else ""
        if not url:
            return True
        allow = self.allow_for(email)
        match = _DEEP_LINK.search(url)
        if match:
            target = match.group(1)
            try:
                target = decode_uri_component(target)
            except ValueError:
                pass
            if not allow(target):
                return False
        return allow(url)

    def artifact_safe_for(self, key, data, email):
        """access.js artifactSafeFor: an artifact with no per-reader filter is
        withheld from a reader when it names a path that reader may not read."""
        if not self.paths_enabled:
            return True
        if normalize_path(key) in FILTERED_ARTIFACTS:
            return True
        return not self.mentions_restricted(data, self.allow_for(email))


def _string_candidates(value):
    out = []
    normalized = normalize_path(value)
    if normalized and "/" in normalized:
        out.append(normalized)
    out.extend(match.group(1).replace("+", " ") for match in _DEEP_LINK.finditer(value))
    decoded = value
    for _ in range(3):
        try:
            following = decode_uri_component(decoded)
        except ValueError:
            break
        if following == decoded:
            break
        decoded = following
    for token in _PATH_TOKEN.findall(decoded):
        out.extend((token, _TRAILING_DOTS.sub("", token)))
    out.extend(match.group(1) for match in _FILE_TOKEN.finditer(decoded))
    return out


def mention_candidates(value, depth=0):
    """Every string mentionsRestricted asks a reader's predicate about, or None
    when the value nests deeper than it will look (always restricted)."""
    out = []

    def walk(item, level):
        if level > 12:
            return False
        if isinstance(item, str):
            out.extend(_string_candidates(item))
            return True
        if isinstance(item, list):
            return all(walk(member, level + 1) for member in item)
        if isinstance(item, dict):
            return all(walk(key, level + 1) and walk(member, level + 1) for key, member in item.items())
        return True

    return out if walk(value, depth) else None


class Prepared:
    """filter_graph's test for fixed records, with who-independent work done once.

    A reader sees a record when every path it carries and every path its
    strings mention is readable to them. Which rules match those paths does not
    depend on who asks, so they are found once here; a request only checks the
    reader against the rules (`satisfied_rules`). `records` holds one
    (paths, value) pair per record: the paths it carries and the value whose
    strings are checked for mentions.
    """

    def __init__(self, gate, records):
        self.gate = gate
        self._records = []
        hits = {}
        for paths, value in records:
            candidates = mention_candidates(value)
            if candidates is None:
                self._records.append(None)
                continue
            strings = [*paths, *candidates]
            rules = set()
            for s in strings:
                if s not in hits:
                    hits[s] = gate.rule_indices(s)
                rules.update(hits[s])
            self._records.append((frozenset(rules), bool(strings)))

    def mask(self, email):
        """One verdict per record: may this reader see it?"""
        gate = self.gate
        if not gate.paths_enabled or gate.is_owner(email):
            return [True] * len(self._records)
        if gate.lockdown:
            # Nothing is readable, so only a record naming no path at all survives.
            return [entry is not None and not entry[1] for entry in self._records]
        ok = gate.satisfied_rules(email)
        return [entry is not None and all(ok[i] for i in entry[0]) for entry in self._records]


def make_access(access_cfg, register=UNBOUND):
    """The gate for one `access` block; `register` is the parsed app/people.json."""
    return Gate(access_cfg, register)
