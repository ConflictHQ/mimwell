import {canonical, loadPolicy, PolicyError, sha256, validate} from "./knowledge-policy.js";

const encode = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const decode = text => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
async function key(secret) {
  if (typeof secret !== "string" || secret.length < 32) throw new PolicyError("governed authoring requires a signing secret of at least 32 characters");
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name: "HMAC", hash: "SHA-256"}, false, ["sign", "verify"]);
}
async function sign(payload, secret) {
  const bytes = new TextEncoder().encode(canonical(payload));
  return `${encode(bytes)}.${encode(new Uint8Array(await crypto.subtle.sign("HMAC", await key(secret), bytes)))}`;
}
async function verify(token, secret) {
  if (typeof token !== "string" || token.length > 150000 || token.split(".").length !== 2) throw new PolicyError("invalid proposal token");
  const [body, signature] = token.split(".");
  try {
    if (!await crypto.subtle.verify("HMAC", await key(secret), decode(signature), decode(body))) throw new Error();
    return JSON.parse(new TextDecoder().decode(decode(body)));
  } catch {throw new PolicyError("invalid proposal token");}
}
function fields(body, allowed) {
  if (Object.keys(body).some(k => !allowed.includes(k))) throw new PolicyError("unknown request field; actor, roles, approvals and file content come from the trusted workflow");
}
function mutation(op) {
  if (op.op === "add_record") return "create";
  const status = op.op === "set_status" ? op.status : op.fields?.status;
  return ({retracted: "retract", superseded: "supersede", deleted: "delete", retained: "retain"})[status] || "correct";
}

// Validate a changed source artifact against its schema. Shared by the governed
// and the direct portal writers, so every input surface commits the same bytes.
export async function checkArtifact(env, spec, before, after) {
  const response = await env.ASSETS.fetch(new Request(`https://policy.invalid/schemas/${spec.schema}.schema.json`));
  if (!response.ok) throw new PolicyError("artifact schema unavailable");
  const schema = await response.json();
  // applyEditOp stamps derived on every kind. Provenance is in the receipt or the
  // commit; do not inject a field forbidden by the source artifact's actual schema.
  let items = schema.properties?.[spec.collection]?.items;
  if (items?.$ref?.startsWith("#/$defs/")) items = schema.$defs?.[items.$ref.slice(8)];
  if (items?.additionalProperties === false && !items.properties?.derived) {
    for (let i = 0; i < after[spec.collection].length; i++) {
      if (!before[spec.collection]?.[i]?.derived) delete after[spec.collection][i].derived;
    }
  }
  // A changed record takes the schema's property order, so the same edit yields
  // the same bytes whichever surface (form, JSON, conversation) staged it.
  const order = Object.keys(items?.properties || {});
  if (order.length && Array.isArray(after[spec.collection])) {
    after[spec.collection] = after[spec.collection].map((rec, i) => {
      const prior = before[spec.collection]?.[i];
      if (!rec || typeof rec !== "object" || (prior !== undefined && canonical(rec) === canonical(prior))) return rec;
      const keys = [...order.filter(k => Object.hasOwn(rec, k)), ...Object.keys(rec).filter(k => !order.includes(k))];
      return Object.fromEntries(keys.map(k => [k, rec[k]]));
    });
  }
  validate(schema, after);
}

async function applyValidated(env, spec, source, op, intent, at, deps) {
  const before = JSON.parse(source.text);
  const after = deps.apply(before, op);
  if ("changelog" in before || "version" in before && "updated" in before) {
    if (!Number.isInteger(before.version) || !Array.isArray(before.changelog)) throw new PolicyError("invalid versioned source envelope");
    after.version = before.version + 1; after.updated = at.slice(0, 10);
    after.changelog.push({version: after.version, date: after.updated, note: intent.reason});
  }
  await checkArtifact(env, spec, before, after);
  return JSON.stringify(after, null, 2) + "\n";
}

// All writes use signed, exact proposals and a fresh source revision. The portal
// adapter deliberately commits one resource at a time, matching Contents API CAS.
export async function governedEdit(request, env, body, settings, deps) {
  try {
    const config = settings.authoring.governance;
    if ((settings.authoring.editorial && settings.authoring.editorial !== "direct") ||
        (settings.authoring.storage_mode && settings.authoring.storage_mode !== "json-commit"))
      throw new PolicyError("governed portal commits require direct editorial mode and json-commit storage");
    const policy = await loadPolicy(env, config);
    await key(env.KNOWLEDGE_POLICY_SECRET);
    const actor = deps.actor(request), now = new Date().toISOString(), repo = deps.repo(env), branch = deps.branch;
    if (!actor) return deps.json({error: "authenticated policy identity required"}, 403);
    if (!repo || !env.GITHUB_TOKEN) return deps.json({error: "governed source unavailable"}, 503);
    const audience = `${repo}@${branch}`;
    const action = body.action || "draft";
    const decisionFor = (req, operation, currentRevision, more = {}) => policy.evaluate(req, {actor, operation, currentRevision, now, ...more});
    if (action === "draft") {
      fields(body, ["action", "ops", "instruction", "messages", "id", "reason", "evidence"]);
      const ops = Array.isArray(body.ops) ? body.ops : deps.agentDraft ? await deps.agentDraft(body) : [];
      if (ops.length !== 1) return deps.json({error: "one typed record operation is required per governed proposal"}, 422);
      const op = JSON.parse(JSON.stringify(ops[0])), spec = deps.artifacts[op.type];
      if (!spec || !["add_record", "update_record", "set_status"].includes(op.op)) return deps.json({error: "unknown typed operation"}, 422);
      const resource = policy.resources.get(spec.path);
      if (!resource || resource.kind !== spec.kind) return deps.json({error: "artifact does not match its governed ontology kind"}, 403);
      const req = {id: body.id || crypto.randomUUID(), resource: spec.path, record: String(op.id || op.data?.id || op.data?.title || op.data?.text || op.data?.question || op.data?.term || op.data?.name || ""),
        mutation: mutation(op), expectedRevision: null, reason: body.reason, evidence: body.evidence, sourceResource: null};
      const readable = decisionFor(req, "read", null);
      if (!readable.allowed || !deps.canRead(spec.path, actor)) return deps.json({error: "source read denied", decision: readable}, 403);
      const source = await deps.get(env, repo, spec.path, branch);
      req.expectedRevision = source.sha;
      const decision = decisionFor(req, "propose", source.sha);
      if (!decision.allowed) return deps.json({decision}, 403);
      if (op.op !== "add_record" && op.fields && ("id" in op.fields || "title" in op.fields))
        return deps.json({error: "identity changes require an explicit replacement workflow"}, 422);
      const after = await applyValidated(env, spec, source, op, req, now, deps);
      if (after === source.text) return deps.json({error: "proposal has no change"}, 422);
      const payload = {version: "1.0", audience, policy: policy.binding, request: req, op, path: spec.path,
        afterSha256: await sha256(after), proposedBy: actor, proposedAt: now, review: null,
        expiresAt: Date.now() + Math.max(60, Math.min(config.ttlSeconds || 600, 3600)) * 1000};
      return deps.json({committed: false, decision, proposalToken: await sign(payload, env.KNOWLEDGE_POLICY_SECRET),
        files: [{path: spec.path, before: source.text, after, baseSha: source.sha}]});
    }
    if (!["review", "commit"].includes(action)) return deps.json({error: "unsupported governed action"}, 422);
    fields(body, action === "review" ? ["action", "proposalToken", "reason"] : ["action", "proposalToken"]);
    const payload = await verify(body.proposalToken, env.KNOWLEDGE_POLICY_SECRET);
    if (payload.version !== "1.0" || payload.audience !== audience || payload.expiresAt <= Date.now() || canonical(payload.policy) !== canonical(policy.binding))
      return deps.json({error: "proposal expired or policy, ontology or target changed; propose again"}, 409);
    const readable = decisionFor(payload.request, "read", null);
    if (!readable.allowed || !deps.canRead(payload.path, actor)) return deps.json({error: "source read denied", decision: readable}, 403);
    const source = await deps.get(env, repo, payload.path, branch);
    const decision = decisionFor(payload.request, action, source.sha, {proposedBy: payload.proposedBy, approvedBy: payload.review?.actor});
    if (!decision.allowed) return deps.json({decision}, decision.reasons.some(r => r.startsWith("stale revision")) ? 409 : 403);
    if (action === "review") {
      if (typeof body.reason !== "string" || !body.reason.trim()) return deps.json({error: "review requires a reason"}, 422);
      payload.review = {actor, at: now, reason: body.reason};
      return deps.json({approved: true, decision, proposalToken: await sign(payload, env.KNOWLEDGE_POLICY_SECRET)});
    }
    const spec = deps.artifacts[payload.op.type];
    const after = await applyValidated(env, spec, source, payload.op, payload.request, payload.proposedAt, deps);
    if (await sha256(after) !== payload.afterSha256) return deps.json({error: "proposal content changed; propose again"}, 409);
    const receipt = {protocolVersion: "1.0", id: payload.request.id, operation: "commit", mutation: payload.request.mutation,
      actor, proposedBy: payload.proposedBy, review: payload.review, policy: policy.binding,
      resource: payload.path, record: payload.request.record, expectedRevision: source.sha,
      afterSha256: payload.afterSha256, reason: payload.request.reason, evidence: payload.request.evidence, at: now};
    const response = await deps.put(env, repo, payload.path, after,
      `knowledge: ${payload.request.mutation} ${payload.request.record}\n\nKnowledge-Receipt: ${canonical(receipt)}`, branch, source.sha);
    return deps.json({committed: true, receipt, files: [{path: payload.path, commit: response.commit?.sha}]});
  } catch (error) {
    return deps.json({error: String(error.message || error)}, error instanceof PolicyError ? 422 : 409);
  }
}
