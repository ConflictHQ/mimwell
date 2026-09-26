// Trusted instance record rules composed AFTER the shared path policy.
// No module discovery, stored-policy evaluator, or arbitrary data transformation.
import { normalizePath } from "../access.js";

function permits(predicate, row, email) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return false;
  try {
    // A local predicate cannot mutate a cached record or grant by returning a
    // truthy promise. A failed rule denies the record without publishing errors.
    const result = predicate(structuredClone(row), email);
    if (result && typeof result.then === "function") {
      Promise.resolve(result).catch(() => {});
      return false;
    }
    return result === true;
  } catch { return false; }
}

function headers(data) {
  return Object.fromEntries(["version", "updated"]
    .filter((key) => Object.hasOwn(data || {}, key)).map((key) => [key, data[key]]));
}

export function withRecordFilters(base, { graph, artifacts = {} } = {}) {
  if (graph !== undefined && typeof graph !== "function") throw new TypeError("graph must be a record predicate");
  if (!artifacts || typeof artifacts !== "object" || Array.isArray(artifacts)) throw new TypeError("artifacts must be a map");
  const filters = new Map();
  const graphPaths = new Set(["app/brain.json", "app/knowledge_graph.json"]);
  for (const [path, rule] of Object.entries(artifacts)) {
    if (normalizePath(path) !== path || graphPaths.has(path) ||
        ["client.config.json", "app/brain-meta.json", "app/brain-manifest.json"].includes(path) || !path.endsWith(".json") ||
        !rule || typeof rule.collection !== "string" || !/^[a-zA-Z][\w-]*$/.test(rule.collection) ||
        typeof rule.allow !== "function") throw new TypeError("Invalid artifact record rule");
    filters.set(path, {collection: rule.collection, allow: rule.allow});
  }
  if (!graph && !filters.size) return base;
  if (!base.present) throw new TypeError("Record filters require explicit access configuration");

  function nodeAllowed(node, email) {
    if (base.lockdown || !node || typeof node.id !== "string") return false;
    const visible = base.filterGraph({nodes: [node], edges: []}, email);
    return visible?.nodes?.length === 1 && visible.nodes[0].id === node.id &&
      (!graph || permits(graph, node, email));
  }

  function filterGraph(value, email) {
    const visible = base.filterGraph(value, email);
    if (!graph && !base.lockdown) return visible;
    const original = Array.isArray(visible?.nodes) ? visible.nodes : [];
    const nodes = original.filter((node) => nodeAllowed(node, email));
    if (nodes.length === original.length && Array.isArray(visible?.nodes) && Array.isArray(visible?.edges)) return visible;
    const ids = new Set(nodes.map((node) => node.id));
    const edges = (Array.isArray(visible?.edges) ? visible.edges : [])
      .filter((edge) => edge && ids.has(edge.source) && ids.has(edge.target));
    // Unknown aggregate headers can describe removed records. Preserve standard
    // version/ontology headers and compute counts from the final visible graph.
    const result = {...headers(visible), nodes, edges};
    if (visible?.meta) {
      result.meta = Object.fromEntries(["version", "generator", "ontology"]
        .filter((key) => Object.hasOwn(visible.meta, key)).map((key) => [key, visible.meta[key]]));
      result.meta.counts = {nodes: nodes.length, edges: edges.length};
    }
    if (Object.hasOwn(visible || {}, "count")) result.count = nodes.length;
    if (Object.hasOwn(visible || {}, "counts")) result.counts = {nodes: nodes.length, edges: edges.length};
    return result;
  }

  function filterArtifact(path, value, email) {
    const key = normalizePath(path);
    if (graphPaths.has(key)) return filterGraph(value, email);
    const visible = base.filterArtifact(key, value, email);
    const rule = filters.get(key);
    if (!rule) return visible;
    const rows = Array.isArray(visible?.[rule.collection]) ? visible[rule.collection] : [];
    const kept = rows.filter((row) => !base.lockdown && base.artifactSafeFor(key, {[rule.collection]: [row]}, email)
      && permits(rule.allow, row, email));
    if (kept.length === rows.length && Array.isArray(visible?.[rule.collection]) &&
        base.artifactSafeFor(key, visible, email)) return visible;
    const result = {...headers(visible), [rule.collection]: kept};
    if (Object.hasOwn(visible || {}, "count")) result.count = kept.length;
    // Even headers must not reintroduce a source-path restriction.
    return base.artifactSafeFor(key, result, email) ? result : {[rule.collection]: kept};
  }

  return Object.freeze({
    ...base, present: true, enabled: true, pathsEnabled: true,
    nodeAllowed: graph ? nodeAllowed : base.nodeAllowed, filterGraph,
    filterPack: (value, email) => filterArtifact("app/knowledge-pack.json", value, email),
    filterPackItems: (items, email) => filterArtifact("app/knowledge-pack.json", {items}, email)?.items || [],
    filterBrainMeta: (value, email) => base.filterBrainMeta(filterGraph(value, email), email),
    filterBrainManifest: (manifest, value, schema, email) =>
      base.filterBrainManifest(manifest, filterGraph(value, email), schema, email),
    hasArtifactFilter: (path) => graphPaths.has(normalizePath(path)) || filters.has(normalizePath(path)) || base.hasArtifactFilter(path),
    filterArtifact,
    // Binding the person register (#212) must keep these record rules.
    bindRegister: (register) => withRecordFilters(base.bindRegister(register), {graph, artifacts}),
  });
}
