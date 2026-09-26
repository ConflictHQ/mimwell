// Same contract as scripts/knowledge_policy.py. Shared fixtures pin both engines.
// `trusted` contains runtime-authenticated identity and observed state, never body fields.
export class PolicyError extends Error {}
const ACL = ["readers", "proposers", "committers", "reviewers"];
const RULES = [...ACL, "fastAuto", "separateReview", "allowDelete", "retentionDays"];
const clone = value => JSON.parse(JSON.stringify(value));
export const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` :
  value && typeof value === "object" ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}` : JSON.stringify(value);
export async function sha256(text) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)))].map(x => x.toString(16).padStart(2, "0")).join("");
}
function time(value) {
  const match = typeof value === "string" && /^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.exec(value);
  const date = match && new Date(`${match[1]}-${match[2]}-${match[3]}T00:00:00Z`);
  if (!match || +match[1] < 1 || !Number.isFinite(Date.parse(value)) || date.getUTCDate() !== +match[3])
    throw new PolicyError("a timezone-aware policy timestamp is required");
  return Date.parse(value);
}
export function localPath(value) {
  if (typeof value !== "string" || !value || value.startsWith("/") || /[\\:%?#]/.test(value) || value.split("/").some(x => ["", ".", ".."].includes(x)))
    throw new PolicyError("policy sources must use plain relative paths");
  return value;
}
// The engine-owned schemas use this closed subset of JSON Schema. An unsupported
// keyword is rejected, rather than silently weakening a future contract.
export function validate(schema, value, root = schema, depth = 0) {
  if (depth > 100) throw new PolicyError("schema nesting limit exceeded");
  const known = new Set(["$schema", "$id", "$defs", "$ref", "title", "description", "x-conflict", "type", "properties", "required", "additionalProperties", "items", "enum", "const", "pattern", "minLength", "minimum"]);
  if (Object.keys(schema).some(k => !known.has(k))) throw new PolicyError("unsupported policy schema keyword");
  if (schema.$ref) {
    if (!schema.$ref.startsWith("#/$defs/")) throw new PolicyError("only local schema definitions are supported");
    const target = root.$defs?.[schema.$ref.slice(8)];
    if (!target) throw new PolicyError("unknown schema definition");
    validate(target, value, root, depth + 1);
  }
  const matches = t => t === "null" ? value === null : t === "array" ? Array.isArray(value) : t === "object" ? value !== null && typeof value === "object" && !Array.isArray(value) :
    t === "integer" ? Number.isSafeInteger(value) : t === "number" ? typeof value === "number" && Number.isFinite(value) : typeof value === t;
  if (schema.type && !(Array.isArray(schema.type) ? schema.type : [schema.type]).some(matches)) throw new PolicyError("invalid policy value type");
  if (schema.enum && !schema.enum.includes(value) || "const" in schema && value !== schema.const) throw new PolicyError("unknown policy value");
  if (typeof value === "string" && ((schema.minLength && value.length < schema.minLength) || schema.pattern && !new RegExp(schema.pattern).test(value))) throw new PolicyError("invalid policy string");
  if (typeof value === "number" && schema.minimum !== undefined && value < schema.minimum) throw new PolicyError("invalid policy number");
  if (schema.items && Array.isArray(value)) value.forEach(item => validate(schema.items, item, root, depth + 1));
  if (schema.properties && value && typeof value === "object" && !Array.isArray(value)) {
    if ((schema.required || []).some(k => !Object.hasOwn(value, k))) throw new PolicyError("required policy field missing");
    for (const [key, item] of Object.entries(value)) {
      if (!Object.hasOwn(schema.properties, key) && schema.additionalProperties === false) throw new PolicyError("unknown policy field");
      if (Object.hasOwn(schema.properties, key)) validate(schema.properties[key], item, root, depth + 1);
    }
  }
}
function indexed(rows, key = "id") {
  const map = new Map();
  for (const row of rows) {
    if (map.has(row[key])) throw new PolicyError(`duplicate policy identity: ${row[key]}`);
    map.set(row[key], row);
  }
  return map;
}
export async function makePolicy(input, ontology, schemas) {
  const document = clone(input);
  validate(schemas.policy, document);
  const binding = {id: document.id, version: document.version, sha256: await sha256(canonical(document)), ontologySha256: await sha256(canonical(ontology))};
  const principals = indexed(document.principals), scopes = indexed(document.scopes), resources = indexed(document.resources);
  const exceptions = indexed(document.exceptions, "scope"), kinds = new Map(ontology.kinds.map(k => [k.id, k.mutability]));
  if ([...kinds.values()].some(t => !["fast", "slow", "anchor"].includes(t))) throw new PolicyError("unsupported ontology mutability");
  for (const scope of scopes.values()) {
    localPath(scope.practice.path);
    if (!principals.has(scope.owner)) throw new PolicyError("scope owner is not a declared principal");
    if (scope.parent === null && (RULES.some(k => !(k in scope.rules)) || Object.keys(scope.rules).length !== RULES.length)) throw new PolicyError("root scope must declare every rule");
    if (ACL.some(k => (scope.rules[k] || []).some(id => !principals.has(id)))) throw new PolicyError("policy grant names an unknown principal");
    let current = scope;
    const seen = new Set();
    while (current.parent !== null) {
      if (seen.has(current.id) || !scopes.has(current.parent)) throw new PolicyError("scope inheritance cycle or unknown parent");
      seen.add(current.id); current = scopes.get(current.parent);
    }
  }
  for (const r of resources.values()) {
    if (!scopes.has(r.scope) || !kinds.has(r.kind)) throw new PolicyError("resource names an unknown scope or ontology kind");
    if (r.retentionSince !== null) time(r.retentionSince);
  }
  for (const e of exceptions.values()) {
    if (!scopes.has(e.scope) || !principals.has(e.approvedBy)) throw new PolicyError("exception names an unknown scope or approver");
    time(e.expiresAt);
  }
  function effective(id, now) {
    const scope = scopes.get(id);
    if (scope.parent === null) return {rules: clone(scope.rules), chain: [scope.practice], exceptions: []};
    const result = effective(scope.parent, now), inherited = result.rules, changes = scope.rules;
    const relaxes = ACL.some(k => k in changes && changes[k].some(p => !inherited[k].includes(p))) ||
      ["fastAuto", "allowDelete"].some(k => (changes[k] ?? inherited[k]) && !inherited[k]) ||
      inherited.separateReview && !(changes.separateReview ?? inherited.separateReview) ||
      (changes.retentionDays ?? inherited.retentionDays) < inherited.retentionDays;
    if (relaxes) {
      const exception = exceptions.get(id);
      if (!exception || !inherited.reviewers.includes(exception.approvedBy) || now >= time(exception.expiresAt))
        throw new PolicyError("scope relaxation needs a current exception approved by an inherited reviewer");
      result.exceptions.push(clone(exception));
    }
    Object.assign(inherited, clone(changes)); result.chain.push(scope.practice);
    return result;
  }
  function evaluate(request, trusted) {
    validate(schemas.request, request);
    const result = {allowed: false, requiresReview: false, reasons: [], policy: binding, resource: request.resource, practiceChain: [], exceptions: [], reviewers: []};
    const deny = reason => {result.reasons.push(reason); return result;};
    const {actor, operation} = trusted;
    if (!principals.has(actor) || !["read", "propose", "review", "commit"].includes(operation)) return deny("unknown actor or operation");
    const resource = resources.get(request.resource);
    if (!resource) return deny("resource is outside this policy");
    const now = time(trusted.now);
    let resolved;
    try {resolved = effective(resource.scope, now);} catch (error) {return deny(error.message);}
    const {rules, chain, exceptions: applied} = resolved;
    result.practiceChain = chain; result.exceptions = applied;
    if (!rules.readers.includes(actor)) return deny("read access denied");
    if (operation === "read") {result.allowed = true; return result;}
    const tier = kinds.get(resource.kind);
    if (tier === "anchor") return deny("anchor knowledge cannot be mutated through this gate");
    if (request.mutation === "read") return deny("a write operation requires a mutation");
    if (request.expectedRevision !== trusted.currentRevision) return deny("stale revision; propose again against the current record");
    if (!request.evidence.length || !request.reason.trim()) return deny("mutation requires reason and evidence");
    const permission = {propose: "proposers", review: "reviewers", commit: "committers"}[operation];
    if (!rules[permission].includes(actor)) return deny(`${operation} authority denied`);
    if (request.mutation === "delete") {
      const since = trusted.retentionSince === undefined ? resource.retentionSince : trusted.retentionSince;
      if (!rules.allowDelete || since === null) return deny("deletion is forbidden or retention age is unknown");
      if (now - time(since) < rules.retentionDays * 86400000) return deny("retention period has not elapsed");
    }
    if (request.mutation === "promote") {
      const source = resources.get(request.sourceResource);
      if (!source) return deny("promotion requires a governed source resource");
      let sourceRules;
      try {sourceRules = effective(source.scope, now).rules;} catch {return deny("source policy is unavailable");}
      if (!sourceRules.readers.includes(actor)) return deny("promotion source read access denied");
      if (operation === "commit" && !sourceRules.reviewers.includes(trusted.sourceApprovedBy)) return deny("promotion requires source-scope release approval");
    } else if (request.sourceResource !== null) return deny("sourceResource is only valid for promotion");
    const proposedBy = trusted.proposedBy === undefined ? actor : trusted.proposedBy;
    let needsReview = tier !== "fast" || !rules.fastAuto || proposedBy !== scopes.get(resource.scope).owner || ["supersede", "retract", "delete", "promote"].includes(request.mutation);
    const owner = scopes.get(resource.scope).owner;
    if (trusted.appPrincipal === owner && proposedBy === owner && principals.get(owner).kind === "service" &&
        tier === "fast" && rules.fastAuto && ["create", "correct", "retract"].includes(request.mutation)) needsReview = false;
    result.requiresReview = needsReview; result.reviewers = [...rules.reviewers].sort();
    if (operation === "review" && rules.separateReview && actor === trusted.proposedBy) return deny("an independent reviewer is required");
    const slowReview = tier === "slow" || ["supersede", "retract", "delete", "promote"].includes(request.mutation);
    if (operation === "review" && slowReview && principals.get(actor).kind !== "human") return deny("slow-tier review requires a human authority");
    if (operation === "commit" && needsReview) {
      const reviewer = trusted.approvedBy;
      if (!rules.reviewers.includes(reviewer) || !rules.readers.includes(reviewer)) return deny("review approval is required");
      if (rules.separateReview && reviewer === proposedBy) return deny("an independent reviewer is required");
      if (slowReview && principals.get(reviewer).kind !== "human") return deny("slow-tier review requires a human authority");
    }
    result.allowed = true;
    return result;
  }
  return {binding, document, resources, kinds, evaluate};
}

export async function loadPolicy(env, config) {
  async function read(path, expected) {
    localPath(path);
    const response = await env.ASSETS.fetch(new Request(`https://policy.invalid/${path}`));
    if (!response.ok) throw new PolicyError(`policy source unavailable: ${path}`);
    const text = await response.text();
    if (expected && await sha256(text) !== expected) throw new PolicyError(`pinned policy source changed: ${path}`);
    return text;
  }
  if (!config || !/^[a-f0-9]{64}$/.test(config.sha256) || !/^[a-f0-9]{64}$/.test(config.ontologySha256)) throw new PolicyError("policy and ontology pins are required");
  const policy = await makePolicy(JSON.parse(await read(config.path, config.sha256)),
    JSON.parse(await read("brain-schema.json", config.ontologySha256)), {
      policy: JSON.parse(await read("schemas/knowledge-policy.schema.json")),
      request: JSON.parse(await read("schemas/mutation-request.schema.json")),
    });
  for (const scope of policy.document.scopes) await read(scope.practice.path, scope.practice.sha256);
  return policy;
}
