// Identity-aware read scoping (#53) — the SINGLE source of the access matcher.
//
// WHY THIS FILE EXISTS
// --------------------
// Two first-party portals independently grew the same missing engine feature —
// per-document scoping on a Cloudflare-Access-authenticated host — and both had
// to FORK worker.js to get it, which is why neither can take engine updates to
// that file any more. This module lifts the seam into the engine so runtime
// (worker.js) and tests exercise the SAME matcher and cannot drift.
//
// THE COMPATIBILITY PROPERTY THAT MATTERS MOST
// --------------------------------------------
// With NO `access` block in client.config.json the gate is DISABLED: every
// predicate short-circuits on a boolean, every filter returns its input by
// reference, and worker.js never enters an access branch. Same bytes, same
// headers, no new failure modes. Everything below is dead weight until an
// engagement opts in.
//
// FAIL CLOSED
// -----------
// A configured-but-unparseable `access` block does NOT fall back to "open" — it
// puts the gate in LOCKDOWN: nobody is an owner, every path is restricted, every
// artifact filter returns an empty shell. A security config that the engine
// cannot understand must never be interpreted as permission.
//
// CONFIG SHAPE (canonical, with the two instances' legacy key names accepted as
// aliases so an existing fork's config validates and runs unchanged):
//
//   "access": {
//     "owners": ["ceo@example.com", "ops"],        // full email OR bare local-part
//     "restricted": [
//       "knowledge/docs/finance/**",               // string  -> owners only
//       { "path": "knowledge/docs/hr/**",          // object  -> owners PLUS
//         "owners": ["hrlead@example.com"] }       //            these readers
//     ],
//     "restricted_tools": ["search_graph"]         // tools withheld from non-owners
//   }
//
//   aliases: admins -> owners | owner_only, privateDocs -> restricted
//            owner_only_tools -> restricted_tools
//
// Any owner entry may instead name a person (#212): "person:<slug>" or
// "oidc:<issuer>#<subject>", matched through the person register (app/people.json)
// to the principal the Access email is bound to. See PRINCIPALS below.

// A bare local-part in an owner list matches that local-part at ANY domain (the
// prefix-matching model one instance shipped). Prefer full addresses.
const HAS_DOMAIN = /@/;

// Only `*` and `?` are glob metacharacters. `[` is a literal so a bracket in a
// filename cannot silently become a character class.
const GLOB_META = /[*?]/;

// Deep-link parameters a portal page may use to address a document, e.g.
// "/app/reader.html?f=knowledge/docs/x.md".
const PAGE_DOC_PARAM = /[?&](?:f|doc|path|file)=([^&#]+)/i;

// Bounded memo for path -> matching rules. Capped so a caller feeding attacker
// -controlled paths cannot grow it without limit.
const MEMO_LIMIT = 512;

// Cloudflare Access stamps the authenticated identity on this header. Read for
// AUTHZ only — no access path here logs or records it.
export function accessEmail(request) {
  try {
    return (request.headers.get("Cf-Access-Authenticated-User-Email") || "").trim().toLowerCase();
  } catch {
    return "";
  }
}

// Collapse any spelling of a path to the ONE string the asset layer would serve.
// Traversal-proof: percent-encoding (including double-encoding) is decoded first,
// backslashes become slashes, a query/fragment is dropped, and "." / ".." / empty
// segments are resolved, so `/x`, `x`, `./x`, `../x`, `a/../x`, `%2e%2e/x`,
// `%252e%252e/x`, `\x` and `//x` all normalize to the same `x`.
//
// The caller MUST fetch the string this returns, not the raw input — gate and
// fetch reading the same normalized path is what makes the gate unbypassable.
export function normalizePath(raw, keepQuery = false) {
  let s = String(raw == null ? "" : raw);
  // Bounded repeat: %252e%252e is "%2e%2e" after one pass and ".." after two.
  for (let i = 0; i < 3 && /%[0-9a-f]{2}/i.test(s); i++) {
    let decoded;
    try {
      decoded = decodeURIComponent(s);
    } catch {
      break; // malformed escape: keep the raw form (matching is deny-biased)
    }
    if (decoded === s) break;
    s = decoded;
  }
  s = s.replace(/\\/g, "/");
  // A REQUEST path ends at the query/fragment; a RULE must keep them,
  // because `?` is a declared glob metacharacter and truncating it here
  // silently rewrites "notes/q?.md" to the literal "notes/q" — which
  // both under-matches (the intended files stay open) and over-matches
  // ("knowledge/?/x" collapses to "knowledge", locking a whole tree).
  if (!keepQuery) s = s.split("?")[0].split("#")[0];
  const out = [];
  for (const seg of s.split("/")) {
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      out.pop();
      continue;
    }
    out.push(seg);
  }
  // The build mirror under _site/ is the same document by another name.
  return out.join("/").replace(/^_site\//, "");
}

const isPathString = (v) => typeof v === "string" && v.length > 0;

// Every document path a graph node carries, whatever shape it uses: `source` as
// a string, an object with `.path`, or a list of either; `data.path` (the brain's
// path-identity convention, which is also what `references` edges are built
// from); and a bare `path`. Exported so the D1 read path scopes the same way the
// JSON one does.
export function nodePaths(n) {
  const out = [];
  const push = (v) => {
    if (isPathString(v)) out.push(v);
    else if (v && typeof v === "object" && isPathString(v.path)) out.push(v.path);
  };
  const s = n && n.source;
  if (Array.isArray(s)) s.forEach(push);
  else push(s);
  if (n && n.data && typeof n.data === "object") push(n.data.path);
  if (Array.isArray(n?.data?.sourcePaths)) n.data.sourcePaths.forEach(push);
  push(n && n.path);
  // Evidence travels with the record it supports. A claim derived from a
  // restricted original or representation has the same visibility boundary.
  if (n && n.evidence) {
    for (const list of [n.evidence.sources, n.evidence.representations]) {
      if (Array.isArray(list)) list.forEach(push);
    }
  }
  return out;
}

// An owner spec matches either a full address or, when it carries no "@", the
// local part of one. Empty identity NEVER matches: no identity means no grant.
function identityMatches(spec, email, principals) {
  if (!spec || !email) return false;
  if (isPrincipalSpec(spec)) {
    // #212: a spec naming a person matches the Access email bound to the same
    // principal in the person register. Unbound or unresolvable -> no grant.
    const principal = principals ? principals.resolve("access:" + email) : null;
    return !!principal && principals.resolve(spec) === principal;
  }
  if (HAS_DOMAIN.test(spec)) return spec === email;
  return spec === email.split("@")[0];
}

// PRINCIPALS (#212)
// -----------------
// JS twin of scripts/principals.py. The principal a host trusts is an OIDC
// issuer + subject, written `oidc:<issuer>#<subject>`. The person register
// (app/people.json) binds each entry to one principal and lists the identities
// a host sees; `resolve` maps `person:<slug>`, `access:<email>`,
// `consumer:<actor>` or `oidc:<issuer>#<subject>` to that principal, or null.
// A register binding one identity to two principals is refused whole.
const isPrincipalSpec = (spec) => spec.startsWith("person:") || spec.startsWith("oidc:");
const ISSUER = /^https:\/\/[^#?\s]+$/;
const NON_SPACE = /^\S+$/;

function recordSlug(text) {
  let out = "";
  for (const ch of String(text).trim().toLowerCase()) {
    if (/[\p{L}\p{N}]/u.test(ch)) out += ch;
    else if (out && !out.endsWith("-")) out += "-";
  }
  return out.replace(/-+$/, "") || "item";
}

export function makePrincipals(register) {
  const problems = [];
  const byIdentity = new Map();
  const oidc = (o) => (o && typeof o === "object" && ISSUER.test(o.issuer) && NON_SPACE.test(o.subject || "")
    ? `oidc:${o.issuer}#${o.subject}` : null);
  const people = register && typeof register === "object" ? register.people : undefined;
  if (!Array.isArray(people)) problems.push("person register needs a people array");
  for (const entry of Array.isArray(people) ? people : []) {
    if (!entry || typeof entry !== "object" || typeof entry.name !== "string" || !entry.name.trim()) {
      problems.push("person register entries need a name");
      continue;
    }
    const ids = entry.identities || {};
    const bound = [`person:${recordSlug(entry.name)}`];
    for (const email of Array.isArray(ids.access) ? ids.access : []) {
      if (typeof email === "string" && /^[^@\s]+@[^@\s]+$/.test(email)) bound.push(`access:${email.trim().toLowerCase()}`);
      else problems.push("person register access identities must be emails");
    }
    for (const actor of Array.isArray(ids.consumers) ? ids.consumers : []) {
      if (typeof actor === "string" && NON_SPACE.test(actor)) bound.push(`consumer:${actor}`);
      else problems.push("person register consumers must be non-empty strings");
    }
    for (const pair of Array.isArray(ids.oidc) ? ids.oidc : []) {
      const id = oidc(pair);
      if (id) bound.push(id);
      else problems.push("person register oidc identities need an https issuer and a subject");
    }
    if (entry.principal === undefined) {
      if (bound.length > 1) problems.push(`${bound[0]} lists identities but binds no principal`);
      continue;
    }
    const canonical = oidc(entry.principal);
    if (!canonical) {
      problems.push(`${bound[0]} principal needs an https issuer and a subject`);
      continue;
    }
    for (const id of [...bound, canonical]) {
      if (byIdentity.has(id) && byIdentity.get(id) !== canonical) problems.push(`${id} resolves to two principals`);
      else byIdentity.set(id, canonical);
    }
  }
  const resolve = (identity) => {
    if (problems.length || typeof identity !== "string") return null;
    const key = identity.startsWith("access:") ? identity.trim().toLowerCase() : identity;
    return byIdentity.get(key) || null;
  };
  return Object.freeze({ problems, resolve });
}

// Compile one rule into a segment-aware matcher. `**` crosses segments, `*` and
// `?` stay inside one; everything else is literal.
function compileGlob(rule) {
  let src = "";
  for (let i = 0; i < rule.length; i++) {
    const c = rule[i];
    if (c === "*") {
      if (rule[i + 1] === "*") {
        i += 1;
        src += "[\\s\\S]*";
      } else {
        src += "[^/]*";
      }
    } else if (c === "?") {
      src += "[^/]";
    } else {
      src += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp("^" + src + "$");
}

// Build the predicate for one restricted entry.
//
// Matching is deny-biased on purpose:
//   * case-insensitive — a rule must not be dodged by a case variant on a
//     case-insensitive store,
//   * ancestor-aware — a rule that names a directory (or matches one) covers
//     everything beneath it, so `knowledge/hr` and `knowledge/hr/` and
//     `knowledge/hr/**` all cover `knowledge/hr/a/b.md`,
//   * `a/**` also matches the bare `a`.
function compileRule(rawPath) {
  // keepQuery: see normalizePath — a rule's `?` is a glob metacharacter.
  const rule = normalizePath(rawPath, true).toLowerCase();
  if (!rule) return null; // an empty/rootward rule is ambiguous -> caller locks down
  const bare = rule.endsWith("/**") ? rule.slice(0, -3) : null;
  const re = GLOB_META.test(rule) ? compileGlob(rule) : null;
  const hit = (s) => (re ? re.test(s) : s === rule) || (bare != null && s === bare);
  return {
    rule,
    // p is already normalized + lowercased by the caller.
    test(p) {
      if (!p) return false;
      let s = p;
      for (;;) {
        if (hit(s)) return true;
        const i = s.lastIndexOf("/");
        if (i < 0) return false;
        s = s.slice(0, i);
      }
    },
  };
}

function stringList(value, problems, where) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    problems.push(`${where} must be an array`);
    return [];
  }
  const out = [];
  for (const v of value) {
    if (typeof v !== "string" || !v.trim()) {
      problems.push(`${where} entries must be non-empty strings`);
      continue;
    }
    // An OIDC subject is case-sensitive; every other identity is not.
    out.push(v.trim().startsWith("oidc:") ? v.trim() : v.trim().toLowerCase());
  }
  return out;
}

// Parse + validate. Any complaint at all puts the caller in lockdown; this
// function never "does its best" with a security config.
function parseAccess(raw) {
  const problems = [];
  if (raw === undefined || raw === null) return { present: false, problems };
  if (typeof raw !== "object" || Array.isArray(raw)) {
    return { present: true, problems: ["access must be an object"] };
  }

  // Unknown keys are ambiguous: they may be a restriction this engine version
  // does not implement. Deny rather than ignore. `$`-prefixed keys are comments.
  const KNOWN = new Set([
    "owners",
    "admins",
    "restricted",
    "owner_only",
    "privateDocs",
    "restricted_tools",
    "owner_only_tools",
  ]);
  for (const k of Object.keys(raw)) {
    if (!k.startsWith("$") && !KNOWN.has(k)) problems.push(`unknown access key: ${k}`);
  }

  const owners = [
    ...stringList(raw.owners, problems, "access.owners"),
    ...stringList(raw.admins, problems, "access.admins"),
  ];

  const rules = [];
  for (const [key, value] of [
    ["access.restricted", raw.restricted],
    ["access.owner_only", raw.owner_only],
    ["access.privateDocs", raw.privateDocs],
  ]) {
    if (value === undefined || value === null) continue;
    if (!Array.isArray(value)) {
      problems.push(`${key} must be an array`);
      continue;
    }
    for (const entry of value) {
      if (typeof entry === "string") {
        const m = compileRule(entry);
        if (!m) {
          problems.push(`${key}: "${entry}" is not a usable path`);
          continue;
        }
        rules.push({ ...m, owners: [] });
        continue;
      }
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        problems.push(`${key} entries must be a path string or {path, owners}`);
        continue;
      }
      const p = entry.path !== undefined ? entry.path : entry.glob;
      if (typeof p !== "string" || !p.trim()) {
        problems.push(`${key} entries need a non-empty "path"`);
        continue;
      }
      const m = compileRule(p);
      if (!m) {
        problems.push(`${key}: "${p}" is not a usable path`);
        continue;
      }
      const extra = stringList(entry.owners, problems, `${key}[${p}].owners`);
      for (const k of Object.keys(entry)) {
        if (!k.startsWith("$") && k !== "path" && k !== "glob" && k !== "owners") {
          problems.push(`${key}[${p}]: unknown key ${k}`);
        }
      }
      rules.push({ ...m, owners: extra });
    }
  }

  const tools = [
    ...stringList(raw.restricted_tools, problems, "access.restricted_tools"),
    ...stringList(raw.owner_only_tools, problems, "access.owner_only_tools"),
  ];

  return { present: true, problems, owners, rules, tools };
}

// The disabled gate: every method is a constant. Nothing allocates, nothing
// copies, filters hand back their input by reference.
//
// One exception, and only when an `access` block is PRESENT: filterConfig still
// strips it, because an owner list is server-only material even on a portal that
// currently restricts nothing. With no `access` block at all this is the
// identity function and worker.js never calls it.
function graphMetadata(graph) {
  function tally(values) {
    const counts = new Map();
    for (const value of values) counts.set(value, (counts.get(value) || 0) + 1);
    return Object.fromEntries([...counts].sort(([a], [b]) => a.localeCompare(b)));
  }
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];
  const byKind = tally(nodes.map((node) => String(node.kind || "(none)")));
  const bySource = tally(nodes.flatMap((node) => {
    const sources = Array.isArray(node.source) ? node.source : [node.source];
    return sources.map((source) => typeof source === "string" ? source : source?.path || "(none)");
  }));
  return {version:graph?.meta?.version || "1", generator:graph?.meta?.generator || "gen-brain",
    counts:{nodes:nodes.length, edges:edges.length, by_kind:byKind, by_source:bySource}};
}

// app/brain-manifest.json describes this reader's graph, never the full inventory.
// Kind IDs and compiled node kinds are different namespaces: use the readable
// schema declarations to retain the generator's population semantics.
function readerManifest(manifest, graph, schema, allow, mentionsRestricted = () => false) {
  const object = (value) => value && typeof value === "object" && !Array.isArray(value);
  if (!object(manifest) || manifest.manifest !== "brain-manifest/v1" || manifest.generator !== "gen-manifest"
      || !Array.isArray(graph?.nodes) || !Array.isArray(graph?.edges) || !Array.isArray(schema?.kinds)
      || graph.nodes.some((node) => !object(node) || typeof node.kind !== "string")
      || schema.kinds.some((kind) => !object(kind) || typeof kind.id !== "string"
        || !(kind.node === null || typeof kind.node === "string"
          || (Array.isArray(kind.node) && kind.node.every((node) => typeof node === "string"))))) return null;
  const pick = (value, keys) => Object.fromEntries(keys
    .filter((key) => object(value) && Object.hasOwn(value, key) && !mentionsRestricted(value[key], allow))
    .map((key) => [key, value[key]]));
  const kinds = schema.kinds.filter((kind) => !mentionsRestricted(kind, allow)
    && (Array.isArray(kind.storage) ? kind.storage : [kind.storage])
      .every((path) => typeof path !== "string" || allow(path)));
  const counts = graphMetadata(graph).counts;
  const populated = new Set(kinds.filter((kind) => (Array.isArray(kind.node) ? kind.node : [kind.node])
    .some((node) => node && counts.by_kind[node] > 0)).map((kind) => kind.id));
  const ids = new Set(kinds.map((kind) => kind.id));
  const graduation = manifest.substrate?.graduation;
  if (!Number.isSafeInteger(graduation?.threshold_nodes) || graduation.threshold_nodes < 0
      || !Array.isArray(manifest.projections) || !Array.isArray(manifest.policy?.publishes)
      || !Array.isArray(manifest.policy?.withholds)) return null;
  const out = {
    manifest: manifest.manifest, generator: manifest.generator,
    identity: pick(manifest.identity, ["id", "name", "engagement", "domain"]),
    scope: pick(manifest.scope, ["level", "id", "parent", "peers"]),
    profile: pick(manifest.profile, ["base", "overlays", "declared", "schema_version", "contract_version"]),
    engine: pick(manifest.engine, ["brain_version", "schema_present", "gates"]),
    inventory: {nodes: counts.nodes, edges: counts.edges, kinds_declared: ids.size,
      kinds_populated: populated.size, by_kind: counts.by_kind,
      unpopulated: [...ids].filter((id) => !populated.has(id)).sort()},
    projections: manifest.projections.filter((row) => object(row) && typeof row.artifact === "string"
      && allow(row.artifact) && !mentionsRestricted(row, allow))
      .map((row) => pick(row, ["resolution", "artifact", "enabled", "present"])),
    substrate: {...pick(manifest.substrate, ["tier", "store", "blobs", "vectors"]),
      // Full-corpus actions/reasons/lag and federation inventory cannot be
      // attributed to this view. Recompute only the scoped threshold advisory.
      deploy: pick(manifest.substrate?.deploy, ["target", "persistence", "replicas"]),
      graduation: {needed: graduation.threshold_nodes > 0 && counts.nodes > graduation.threshold_nodes,
        threshold_nodes: graduation.threshold_nodes, current_nodes: counts.nodes}},
    policy: {access_gate: manifest.policy.access_gate,
      publishes: manifest.policy.publishes.filter((id) => ids.has(id)),
      withholds: manifest.policy.withholds.filter((id) => ids.has(id))},
    surfaces: pick(manifest.surfaces, ["portal", "chat", "store", "template", "features"]),
  };
  const required = {identity:["id", "name"], scope:["level", "id", "parent", "peers"],
    profile:["base", "overlays", "schema_version", "contract_version"], engine:["brain_version", "schema_present", "gates"],
    substrate:["tier", "store", "blobs", "vectors", "deploy"], surfaces:["store", "features"]};
  if (Object.entries(required).some(([key, fields]) => fields.some((field) => !Object.hasOwn(out[key], field)))
      || mentionsRestricted(out, allow)) return null;
  return out;
}

function openGate(present, problems) {
  const yes = () => true;
  const same = (x) => x;
  const stripAccess = present
    ? (cfg) => {
        if (!cfg || typeof cfg !== "object") return cfg;
        const out = { ...cfg };
        delete out.access;
        return out;
      }
    : same;
  return Object.freeze({
    present,
    enabled: false,
    pathsEnabled: false,
    lockdown: false,
    problems,
    normalizePath,
    isOwner: yes,
    isRestrictedPath: () => false,
    canRead: yes,
    allowFor: () => yes,
    toolAllowed: yes,
    redactSearch: same,
    identityNote: () => "",
    hasArtifactFilter: () => false,
    artifactSafeFor: () => true,
    filterArtifact: (_key, data) => data,
    filterPackItems: same,
    filterPack: same,
    filterGraph: same,
    filterBrainMeta: graphMetadata,
    filterBrainManifest: (manifest, graph, schema) => readerManifest(manifest, graph, schema, yes),
    filterDocsManifest: same,
    filterPages: same,
    pageAllowed: yes,
    filterConfig: stripAccess,
  });
}

/**
 * Build the access gate for an engagement.
 *
 * @param {*} accessCfg the raw `access` block from client.config.json (or undefined)
 * @returns a frozen gate: {enabled, lockdown, isOwner, isRestrictedPath, canRead,
 *          allowFor, toolAllowed, redactSearch, filterArtifact, filter*, ...}
 */
export function makeAccess(accessCfg, register) {
  const parsed = parseAccess(accessCfg);

  // Principals (#212). `register` is the parsed app/people.json; undefined means
  // not loaded yet. An owner spec naming a person (`person:<slug>`,
  // `oidc:<issuer>#<subject>`) matches nobody until the register is bound
  // (`needsRegister`; worker.js binds it), and a register that cannot be read
  // unambiguously puts a gate that relies on it in LOCKDOWN.
  const principals = register === undefined ? null : makePrincipals(register);
  const usesPrincipals = parsed.present && !parsed.problems.length &&
    [...parsed.owners, ...parsed.rules.flatMap((r) => r.owners)].some(isPrincipalSpec);
  if (usesPrincipals && principals && principals.problems.length) {
    parsed.problems.push(...principals.problems.map((p) => `person register: ${p}`));
  }
  const bound = (gate) => Object.freeze({
    ...gate,
    needsRegister: usesPrincipals && !principals,
    principalOf: (email) => {
      const e = String(email || "").trim().toLowerCase();
      return principals && e ? principals.resolve("access:" + e) : null;
    },
    resolvePrincipal: (identity) => (principals ? principals.resolve(identity) : null),
    bindRegister: (next) => makeAccess(accessCfg, next),
  });

  // Not configured -> the fast path. Also the case where an `access` block is
  // present and valid but restricts nothing: there is no document or tool to protect,
  // so the engine stays on the zero-cost path.
  if (!parsed.present) return bound(openGate(false, []));
  if (!parsed.problems.length && !parsed.rules.length && !parsed.tools.length) {
    // An instance record rule may use owner identity without restricting paths.
    // Keep reads on the open fast path, but do not turn every reader into an owner.
    return bound({...openGate(true, []), isOwner: (email) => {
      const identity = String(email || "").trim().toLowerCase();
      return !!identity && parsed.owners.some((spec) => identityMatches(spec, identity, principals));
    }});
  }

  const lockdown = parsed.problems.length > 0;
  const owners = lockdown ? [] : parsed.owners;
  const rules = lockdown ? [] : parsed.rules;
  const tools = new Set(lockdown ? [] : parsed.tools);
  const memo = new Map();

  function rulesFor(path) {
    const key = normalizePath(path).toLowerCase();
    if (!key) return [];
    const cached = memo.get(key);
    if (cached) return cached;
    const hits = rules.filter((r) => r.test(key));
    if (memo.size < MEMO_LIMIT) memo.set(key, hits);
    return hits;
  }

  function isOwner(email) {
    if (lockdown) return false;
    const e = String(email || "").trim().toLowerCase();
    if (!e) return false; // no identity -> never an owner
    return owners.some((spec) => identityMatches(spec, e, principals));
  }

  function isRestrictedPath(path) {
    if (lockdown) return true;
    return rulesFor(path).length > 0;
  }

  // A reader must satisfy EVERY rule that matches the path. Two overlapping
  // rules can only narrow access, never widen it.
  function canRead(path, email) {
    if (lockdown) return false;
    const hits = rulesFor(path);
    if (!hits.length) return true;
    if (isOwner(email)) return true;
    const e = String(email || "").trim().toLowerCase();
    if (!e) return false;
    return hits.every((r) => r.owners.some((spec) => identityMatches(spec, e, principals)));
  }

  // Memoized per-request predicate: one identity resolution, one path cache.
  function allowFor(email) {
    if (lockdown) return () => false;
    if (isOwner(email)) return () => true;
    const seen = new Map();
    return (path) => {
      const key = String(path == null ? "" : path);
      if (seen.has(key)) return seen.get(key);
      const ok = canRead(key, email);
      if (seen.size < MEMO_LIMIT) seen.set(key, ok);
      return ok;
    };
  }

  // Whole-tool gate: some tool output is aggregate/entity-led and cannot be
  // path-redacted, so an engagement may withhold the tool from non-owners.
  function toolAllowed(name, email) {
    if (lockdown) return false;
    if (!tools.has(String(name || "").toLowerCase())) return true;
    return isOwner(email);
  }

  // Tool permissions compose independently of document permissions. With no path
  // rules, keep documents/artifacts on their unchanged fast path while enforcing
  // owner identity and tool dispatch. Malformed policy still uses full lockdown.
  if (!lockdown && !rules.length) {
    return bound({ ...openGate(true, []), enabled: true, isOwner, toolAllowed });
  }

  // Drop restricted entries from a PATH-LED tool result: each entry is a
  // non-indented path line followed by indented detail lines. Text-level
  // backstop for search paths (D1) where there is no structure to filter.
  function redactSearch(text, email) {
    if (!text || typeof text !== "string") return text;
    const allow = allowFor(email);
    const out = [];
    let skip = false;
    for (const line of text.split("\n")) {
      if (line && !/^\s/.test(line)) skip = !allow(line.trim().split(/\s+/)[0]);
      if (!skip) out.push(line);
    }
    const kept = out.join("\n").trim();
    return kept || "No matches. Try different keywords.";
  }

  // Defense in depth for the chat agent: the tools already hide what this user
  // cannot read; this tells the model not to reconstruct it from memory.
  function identityNote(email) {
    if (isOwner(email)) return "";
    return (
      "Access note: some documents in this knowledge base are access-controlled. " +
      "Anything this user may not read is already hidden from your search results and " +
      "read_doc will refuse it. Never speculate about, reconstruct, or summarize a document " +
      "you could not read; if asked about restricted material, say it is access-controlled and stop there."
    );
  }

  // --- artifact filtering -------------------------------------------------
  // Compiled artifacts are SERVED, and several carry document paths beyond their
  // obvious list — the pack's #49 link graph and the brain's node sources,
  // data.path and `references` edges all name documents. An edge naming a
  // restricted document leaks its existence and its path just as surely as
  // serving it. Everything below is built from the same three primitives so a
  // future artifact key is one table entry, not another copy of the logic.

  // Primitive 1: filter a list, dropping members with an unreadable path.
  function filterList(list, getPaths, allow) {
    if (!Array.isArray(list)) return [];
    return list.filter((m) => {
      const paths = getPaths(m);
      return !paths.length || paths.every(allow);
    });
  }

  // Primitive 2: filter a path-keyed map whose values are paths or path lists.
  function filterPathMap(map, allow) {
    if (!map || typeof map !== "object" || Array.isArray(map)) return {};
    const out = {};
    for (const [k, v] of Object.entries(map)) {
      if (!allow(k)) continue;
      if (Array.isArray(v)) {
        const kept = v.filter((x) => isPathString(x) && allow(x));
        if (kept.length) out[k] = kept;
      } else if (isPathString(v)) {
        if (allow(v)) out[k] = v;
      } else {
        out[k] = v;
      }
    }
    return out;
  }

  // Primitive 3: keep nodes this user may see, then drop every edge that now
  // dangles. Edge source/target are NODE IDS (not paths) — including the
  // `references` edges projected from the link graph (#60 slice 1) — so an edge
  // survives only when BOTH endpoints survived.
  function filterNodesEdges(graph, allow) {
    const nodes = filterList(graph && graph.nodes, nodePaths, allow)
      .filter((node) => !mentionsRestricted(node, allow));
    const keep = new Set(nodes.map((n) => n && n.id));
    const edges = Array.isArray(graph && graph.edges)
      ? graph.edges.filter((e) => e && keep.has(e.source) && keep.has(e.target) &&
          (!e.evidence || nodePaths({ evidence: e.evidence }).every(allow)) && !mentionsRestricted(e, allow))
      : [];
    const out = { ...graph, nodes, edges };
    if (graph && graph.meta && typeof graph.meta === "object" && !Array.isArray(graph.meta)) {
      // Counts describe the visible graph. Unknown aggregate metadata cannot be
      // safely inherited from the full corpus (including hidden source buckets).
      out.meta = Object.fromEntries(["version", "generator", "ontology"]
        .filter((key) => key in graph.meta && !mentionsRestricted(graph.meta[key], allow))
        .map((key) => [key, graph.meta[key]]));
      out.meta.counts = {nodes:nodes.length, edges:edges.length};
    }
    for (const key of Object.keys(out)) {
      if (!["meta", "nodes", "edges"].includes(key) && mentionsRestricted(out[key], allow)) delete out[key];
    }
    if ("count" in out) out.count = nodes.length;
    if ("counts" in out) out.counts = {nodes:nodes.length, edges:edges.length};
    return out;
  }

  function filterPackItems(items, email) {
    return filterList(items, (i) => (isPathString(i && i.path) ? [i.path] : []), allowFor(email));
  }

  function filterPack(pack, email) {
    if (!pack || typeof pack !== "object") return { count: 0, items: [] };
    const allow = allowFor(email);
    const out = { ...pack };
    out.items = filterList(pack.items, (i) => (isPathString(i && i.path) ? [i.path] : []), allow);
    if ("count" in out) out.count = out.items.length;
    // #49 link graph: backlinks (target -> [sources]), wikilinks (label -> path),
    // dangling ([{target, sources}]). Each names documents by path.
    if ("backlinks" in out) out.backlinks = filterPathMap(pack.backlinks, allow);
    if ("wikilinks" in out) out.wikilinks = filterPathMap(pack.wikilinks, allow);
    if ("dangling" in out) {
      out.dangling = (Array.isArray(pack.dangling) ? pack.dangling : [])
        .filter((d) => d && typeof d === "object")
        .filter((d) => !isPathString(d.target) || allow(d.target))
        .map((d) => (Array.isArray(d.sources) ? { ...d, sources: d.sources.filter(allow) } : d))
        .filter((d) => !Array.isArray(d.sources) || d.sources.length);
    }
    return out;
  }

  function filterGraph(graph, email) {
    if (!graph || typeof graph !== "object") return { nodes: [], edges: [] };
    if (isOwner(email)) return graph;
    return filterNodesEdges(graph, allowFor(email));
  }

  // app/brain-meta.json is derived from the authorized graph at request time.
  // A sidecar alone cannot reconstruct per-kind totals or edge counts safely.
  function filterBrainMeta(graph, email) {
    return graphMetadata(filterGraph(graph, email));
  }

  function filterDeliverables(data, email) {
    if (isOwner(email)) return data;
    const allow = allowFor(email);
    const rows = Array.isArray(data?.deliverables) ? data.deliverables : [];
    const deliverables = rows.filter((row) => row && typeof row === "object" && !Array.isArray(row)
      && !mentionsRestricted(row, allow));
    // Retain standard version headers; global changelogs/count breakdowns may
    // describe rows this reader cannot see and do not have per-entry provenance.
    const header = Object.fromEntries(["version", "updated"]
      .filter((key) => data && key in data && !mentionsRestricted(data[key], allow))
      .map((key) => [key, data[key]]));
    if (data && "count" in data) header.count = deliverables.length;
    return {...header, deliverables};
  }

  function filterDocsManifest(manifest, email) {
    if (!manifest || typeof manifest !== "object") return { sections: [] };
    const allow = allowFor(email);
    const sections = (Array.isArray(manifest.sections) ? manifest.sections : []).map((s) => {
      if (!s || typeof s !== "object") return s;
      const docs = filterList(s.docs, (d) => (isPathString(d && d.path) ? [d.path] : []), allow);
      const out = { ...s, docs };
      if ("count" in out) out.count = docs.length;
      return out;
    });
    return { ...manifest, sections };
  }

  function filterKinds(manifest, email) {
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return { kinds: [] };
    const allow = allowFor(email);
    const kinds = (Array.isArray(manifest.kinds) ? manifest.kinds : [])
      .filter((kind) => kind && typeof kind === "object" && !Array.isArray(kind)
        // artifact is a declared path, including root files such as issues.json.
        // The generic prose/path scanner below intentionally looks for slashes.
        && (typeof kind.artifact !== "string" || allow(kind.artifact))
        && !mentionsRestricted(kind, allow));
    const header = Object.fromEntries(Object.entries(manifest).filter(([key, value]) =>
      key !== "kinds" && !mentionsRestricted(key, allow) && !mentionsRestricted(value, allow)));
    if ("count" in header) header.count = kinds.length;
    return { ...header, kinds };
  }

  // The served artifact table. Keys are normalized corpus-relative paths; add a
  // key here and every choke point picks it up.
  const ARTIFACT_FILTERS = new Map([
    ["app/knowledge-pack.json", filterPack],
    ["app/brain.json", filterGraph],
    ["app/knowledge_graph.json", filterGraph],
    ["app/docs-manifest.json", filterDocsManifest],
    ["app/kinds.json", filterKinds],
    ["app/deliverables.json", filterDeliverables],
  ]);

  function hasArtifactFilter(key) {
    return ARTIFACT_FILTERS.has(normalizePath(key));
  }

  function filterArtifact(key, data, email) {
    const fn = ARTIFACT_FILTERS.get(normalizePath(key));
    return fn ? fn(data, email) : data;
  }

  // Does this value mention a path this reader may not have? Walks strings,
  // arrays, object VALUES *and* object KEYS — a path-keyed map (the brain
  // sidecar's counts.by_source is one) publishes the path in its key.
  function mentionsRestricted(value, allow, depth = 0) {
    if (depth > 12) return true; // pathologically deep: fail closed
    if (typeof value === "string") {
      const n = normalizePath(value);
      if (n && n.includes("/") && !allow(n)) return true;
      // Paths also occur inside prose, Markdown links and reader URLs. Checking
      // the whole string alone misses an activity sentence naming a private doc.
      // Split query parameters BEFORE decoding: %26 belongs to the filename,
      // while an unescaped ampersand separates parameters.
      const targets = [...value.matchAll(/[?&](?:f|doc|path|file)=([^&#\s"'<>\)\]]+)/gi)];
      if (targets.some((match) => !allow(match[1].replace(/\+/g, " ")))) return true;
      let decoded = value;
      for (let i = 0; i < 3; i++) {
        try { const next = decodeURIComponent(decoded); if (next === decoded) break; decoded = next; }
        catch { break; }
      }
      const tokens = decoded.match(/[A-Za-z0-9_@%.~\-]+(?:[/\\][A-Za-z0-9_@%.~\-]+)+/g) || [];
      // A root filename token must stand on its own; a public directory may
      // legitimately contain a different file with the same basename.
      const filenames = [...decoded.matchAll(/(?:^|[\s("'=:\[>])([A-Za-z0-9_.\-]+\.(?:md|markdown|txt|json|jsonl|ndjson|csv|sql|ya?ml|pdf|docx?|pptx?|xlsx?))(?=$|[\s)"',;:\]<>?#])/gi)]
        .map((match) => match[1]);
      // A prose sentence may end immediately after an exact restricted path.
      return tokens.some((path) => !allow(path) || !allow(path.replace(/\.+$/, "")))
        || filenames.some((path) => !allow(path));
    }
    if (Array.isArray(value)) {
      return value.some((v) => mentionsRestricted(v, allow, depth + 1));
    }
    if (value && typeof value === "object") {
      for (const [k, v] of Object.entries(value)) {
        if (mentionsRestricted(k, allow, depth + 1)) return true;
        if (mentionsRestricted(v, allow, depth + 1)) return true;
      }
    }
    return false;
  }

  // The default for a SERVED artifact nobody wrote a filter for.
  //
  // The portal serves ~40 compiled JSON artifacts; the table above understands
  // four. Leaving the rest to publish by default meant a decision, session,
  // deliverable or staleness row sourced from a restricted document was served
  // in full to every authenticated user, even while the brain filter dropped
  // the very same node. An allowlist of filters with a publish-by-default tail
  // is the wrong shape for a security control, so the tail now fails CLOSED:
  // an unfiltered artifact that mentions a path this reader may not read is
  // withheld from them entirely. Readers who may see everything it mentions
  // still get it untouched, so an unscoped portal is unaffected.
  //
  // Withholding is deliberately coarse — the fix an operator wants is a real
  // filter entry in ARTIFACT_FILTERS (one line), which this makes visible
  // instead of silent. scripts/check-access-leaks.py names them at build time.
  function artifactSafeFor(key, data, email) {
    // This gate only exists when access IS configured (the unconfigured gate
    // has its own constant-true stub), so there is no disabled case here.
    if (hasArtifactFilter(key)) return true;
    return !mentionsRestricted(data, allowFor(email));
  }

  // A portal page is hidden when its own URL, or the document it deep-links
  // (?f= / ?doc= / ?path= / ?file=), is one this user may not read.
  function pageAllowed(page, email) {
    const url = String((page && page.url) || "");
    if (!url) return true;
    const allow = allowFor(email);
    const m = url.match(PAGE_DOC_PARAM);
    if (m) {
      let target = m[1];
      try {
        target = decodeURIComponent(target);
      } catch {
        /* keep raw */
      }
      if (!allow(target)) return false;
    }
    return allow(url);
  }

  function filterPages(pages, email) {
    if (!Array.isArray(pages)) return [];
    return pages.filter((p) => pageAllowed(p, email));
  }

  // The SPA fetches client.config.json. The access rules are server-only — the
  // owner list and the restricted paths must never ship to a browser.
  function filterConfig(cfg, email) {
    if (!cfg || typeof cfg !== "object") return cfg;
    const out = { ...cfg };
    delete out.access;
    if (Array.isArray(out.pages)) out.pages = filterPages(out.pages, email);
    const experience = out.portal?.experience;
    if (experience && Object.hasOwn(experience, "recordViews")) {
      const records = experience.recordViews;
      const allow = allowFor(email);
      // Presentation metadata is public within its admitted page/source scope.
      // Do not return denied view labels, literal predicates or source hints.
      // An emptied selected page remains explicit so the renderer cannot fall
      // back to a broader legacy collection after its views were filtered out.
      const pages = Array.isArray(records?.pages) ? records.pages
        .filter((page) => page && typeof page.url === "string" && pageAllowed({url:page.url}, email))
        .map((page) => {
          const views = Array.isArray(page.views) ? page.views.filter((view) => view
            && typeof view.artifact === "string" && allow(view.artifact)
            && !mentionsRestricted(view, allow)) : [];
          const ids = new Set(views.map((view) => view.id));
          return {url:page.url, views, entry:ids.has(page.entry) ? page.entry : views[0]?.id || "",
            pinned:Array.isArray(page.pinned) ? page.pinned.filter((id) => ids.has(id)) : []};
        }) : [];
      const allowedKinds = new Set(pages.flatMap((page) => page.views.map((view) => view.kind)));
      const descriptors = Object.fromEntries(Object.entries(experience.recordViewDescriptors || {})
        .filter(([kind]) => allowedKinds.has(kind)));
      out.portal = {...out.portal, experience:{...experience, recordViewDescriptors:descriptors,
        recordViews:Array.isArray(records?.pages) ? {protocolVersion:records?.protocolVersion, pages} : null}};
    }
    return out;
  }

  return bound({
    present: true,
    enabled: true,
    pathsEnabled: true,
    lockdown,
    problems: parsed.problems,
    normalizePath,
    isOwner,
    isRestrictedPath,
    canRead,
    allowFor,
    toolAllowed,
    redactSearch,
    identityNote,
    hasArtifactFilter,
    artifactSafeFor,
    filterArtifact,
    filterBrainMeta,
    filterBrainManifest: (manifest, graph, schema, email) =>
      readerManifest(manifest, filterGraph(graph, email), schema, allowFor(email), mentionsRestricted),
    filterPackItems,
    filterPack,
    filterGraph,
    filterDocsManifest,
    filterPages,
    pageAllowed,
    filterConfig,
  });
}

export default makeAccess;
