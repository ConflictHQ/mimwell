// Client portal worker — serves the repo as static assets, injects the chat
// bubble into HTML pages, and exposes the knowledge-base chat agent at
// POST /api/chat. Auth is handled upstream by Cloudflare Access.
//
// All client-specific values (identity, audience, model, pages) come from
// client.config.json; this engine is client-agnostic.

import Anthropic from "@anthropic-ai/sdk";
import { settings as config } from "./config.js";
import { makeAccess, accessEmail, normalizePath, nodePaths } from "./access.js";

// Identity-aware read scoping (#53). Built ONCE from client.config.json's
// optional `access` block. With no such block ACCESS.present is false, every
// branch guarded by it below is skipped, and the portal behaves exactly as it
// always has: same responses, same headers, same cost. See access.js for the
// config shape and the fail-closed rules.
const ACCESS = makeAccess(config.access);

// A lockdown is a config bug, and a silently locked-down portal is a confusing
// one. Say so once at isolate start — but keep denying, never fall open.
if (ACCESS.lockdown) {
  console.error(
    `access config is unusable — serving in LOCKDOWN (every document withheld): ${ACCESS.problems.join("; ")}`,
  );
}

const MODEL = config.assistant.model;

// Model provider (#438). "anthropic" (the default) uses the Anthropic SDK;
// "openai" uses the OpenAI adapter in openai-client.js, which keeps the same
// client contract, so every agent path below is provider-agnostic. An OpenAI
// brain must name its model explicitly: there is no guessed default, and a
// Claude model id left over from the template is refused.
const PROVIDER = config.assistant.provider || "anthropic";
const PROVIDER_KEY = { anthropic: "ANTHROPIC_API_KEY", openai: "OPENAI_API_KEY" };
const MODEL_CONFIG_ERROR = !(PROVIDER in PROVIDER_KEY)
  ? `unknown assistant.provider "${PROVIDER}" (use "anthropic" or "openai")`
  : PROVIDER === "openai" && (!MODEL || /^claude-/.test(MODEL))
    ? 'assistant.provider "openai" needs assistant.model set to an OpenAI model id'
    : "";
if (MODEL_CONFIG_ERROR) console.error(`assistant config: ${MODEL_CONFIG_ERROR}`);
// True when the configured provider's key is present and the config is usable.
const modelAvailable = (env) => !MODEL_CONFIG_ERROR && Boolean(env && env[PROVIDER_KEY[PROVIDER]]);
const MAX_AGENT_TURNS = config.assistant.maxAgentTurns;
const MAX_DOC_CHARS = config.assistant.maxDocChars; // ~75k tokens per doc — the model has a 1M input window

// Per-REQUEST tool-output context budget (#62). maxDocChars caps ONE document;
// this caps the total tool-result text fed back across the whole agent loop, so
// a handful of large reads cannot blow the context window. Config-driven
// (assistant.maxToolOutputChars) with a safe default when absent — ~600k chars
// is roughly 150k tokens against a 1M input window. Over budget the tool result
// is truncated with a VISIBLE marker; the request never fails.
const MAX_TOOL_OUTPUT_CHARS =
  Number(config.assistant.maxToolOutputChars) > 0
    ? Number(config.assistant.maxToolOutputChars)
    : 600000;

const TOOL_BUDGET_MARKER =
  "[tool output omitted — the per-request tool-output budget is exhausted. Answer from what you have already read.]";

// Appended when the model service fails part way through the agent loop and the
// worker returns the best partial answer instead of a 500 (#62).
const PARTIAL_NOTE =
  "\n\n---\n\n*Partial answer: the assistant service returned an error before this reply was finished, so this is what had been gathered. Ask again to retry.*";

// Optional corpus allowlist for read_doc (#62). When assistant.docRoots is a
// non-empty array of top-level directories, read_doc may only reach paths inside
// them; absent (the default) any non-dot path with a supported extension inside
// the served bundle is readable. Config-driven, so no engagement layout is baked in.
const DOC_ROOTS = Array.isArray(config.assistant.docRoots)
  ? config.assistant.docRoots.map((r) => String(r).replace(/^\/+|\/+$/g, "")).filter(Boolean)
  : [];

// Supported document extensions for read_doc. Anything else is refused before a
// fetch is issued.
const DOC_EXT = /\.(md|json|txt|py|js|toml|html|css)$/i;

// Config default theme (resolution order: cookie -> prefers-color-scheme ->
// this). theming.default is the engagement's preferred mode; absent -> "dark".
const DEFAULT_THEME =
  (config.theming && config.theming.default === "light") ? "light" : "dark";

// Agent-query observability (#30). Capture what the agent is asked and whether
// it could answer, so gaps in the knowledge base surface and get filled. Gated
// behind features.observability (default false) — a clean no-op when off.
// PRIVACY: logs the query text + tool/answer METADATA only. Never auth identity
// — the worker assumes Cloudflare Access upstream and reads no identity; this
// path reads no CF-Access-* header and no cookie, by design.
const OBSERVABILITY = !!(config.features && config.features.observability);

// Brain edge store (#37). When features.brain_d1 is ON and brain.store is "d1",
// the worker answers kb/graph reads from the Cloudflare D1 binding (env.DB) with
// indexed SQL instead of loading app/brain.json / app/knowledge_graph.json into
// worker memory per request — so a large brain never gets pulled into the worker.
// OFF by default: env.DB is undefined and the d1 path is never reached, so the
// worker serves the JSON-in-memory path BYTE-IDENTICALLY to before. This is the
// JS half of scripts/brain_store.py's store-agnostic accessor; the SQL below
// mirrors brain_store.py's _D1_SQL (single source of the search haystack /
// recursive-CTE traversal) so the edge answers identically to json/sqlite.
const BRAIN_D1 =
  !!(config.features && config.features.brain_d1) &&
  config.brain && config.brain.store === "d1";

// Writable authoring layer (#38). The portal is read-only unless features.authoring
// is on. When ON, a SECOND agent is mounted at POST /api/edit (handleEdit) holding
// the write tools; the read agent at /api/chat keeps its READ-ONLY TOOLS array with
// ZERO write tools (structural isolation, acceptance-tested). OFF by default: the
// /api/edit route is never registered (404, behavior unchanged) and app/editor.js is
// not injected, so the page is byte-identical to before. The sub-flags scope the
// individual write modes: authoring_agent (conversational edit -> diff -> commit),
// authoring_wysiwyg / authoring_wysiwyg_agent (buffer/selection edit-agent, never
// commits), authoring_access_gate (require an editor role on /api/edit).
const F = config.features || {};
const AUTHORING = !!F.authoring;
const AUTHORING_AGENT = AUTHORING && !!F.authoring_agent;
const AUTHORING_WYSIWYG_AGENT =
  AUTHORING && (!!F.authoring_wysiwyg_agent || !!F.authoring_wysiwyg);
const AUTHORING_ACCESS_GATE = AUTHORING && !!F.authoring_access_gate;

// Authoring settings (commit identity / target / editorial mode). Inert when
// AUTHORING is off. bot identity honors engagement conventions (no AI attribution).
// storage_mode names the files-cell writer only (json-commit). A brain whose
// records live in a store authority edits through that authority's governed
// writer, never through this Worker (docs/design/adr-authority-per-brain-kind.md).
const AUTHORING_CFG = config.authoring || {};
const AUTHORING_BRANCH = AUTHORING_CFG.branch || "main";
const AUTHORING_EDITORIAL = AUTHORING_CFG.editorial || "direct";
const AUTHORING_STORAGE = AUTHORING_CFG.storage_mode || "json-commit";
const AUTHORING_EDITOR_ROLE = AUTHORING_CFG.editor_role || "";

// The repo edits commit back to, e.g. "owner/name". Read from env at the edge
// (env.GITHUB_REPO), undefined by default so the commit path is unreachable to
// build/test. The bot token is env.GITHUB_TOKEN (also undefined by default).
function authoringRepo(env) {
  return (env && env.GITHUB_REPO) || "";
}

// The set of source artifacts the editor agent may mutate (#38 audit clarification:
// writes target SOURCES, then regen — the brain envelope itself is read-only). It
// derives from the ontology, never a parallel list: a kind is editable only when
// its artifact schema declares x-conflict.editable, it has a records collection,
// and its mutability tier is not `anchor`. Read per request from the compiled
// app/kinds.json (scripts/gen-kinds.py), so an anchor kind is structurally absent
// from the editor prompt, the tool schemas and the commit allowlist. Each entry
// maps an artifact `type` (the source file's basename, which is also its schema
// name) to its source path + collection key. A missing descriptor fails closed.
async function editableArtifacts(env) {
  let kinds = [];
  try {
    const resp = await env.ASSETS.fetch(new Request("https://assets.invalid/app/kinds.json"));
    if (resp.ok) kinds = (await resp.json()).kinds || [];
  } catch {
    kinds = [];
  }
  const out = {};
  for (const k of kinds) {
    if (k.editable !== true || k.mutability === "anchor" || !k.records) continue;
    const m = /^app\/([a-z0-9-]+)\.json$/.exec(k.artifact || "");
    if (!m) continue;
    out[m[1]] = { path: k.artifact, collection: k.records, schema: m[1], kind: k.id, mutability: k.mutability };
  }
  return out;
}

// The D1 read SQL — kept in lockstep with brain_store.py _D1_SQL. search() matches
// the precomputed, already-lowercased `search_text` column with LIKE '%q%' (FTS5
// is intentionally NOT on the search path — raw token matching disagrees with
// substring search; LIKE is the portable fallback per the #37 acceptance). The
// recursive CTE mirrors _SqliteBackend.path. Ordering: nodes by id (deterministic).
const D1_SQL = {
  search: "SELECT json FROM node WHERE search_text LIKE ?1 ESCAPE '\\' ORDER BY id LIMIT ?2",
  getNode: "SELECT json FROM node WHERE id = ?1",
  neighborsOut: "SELECT e.dst AS nb, e.type, e.json AS edge_json, n.json AS node_json FROM edge e JOIN node n ON n.id = e.dst WHERE e.src = ?1",
  neighborsIn: "SELECT e.src AS nb, e.type, e.json AS edge_json, n.json AS node_json FROM edge e JOIN node n ON n.id = e.src WHERE e.dst = ?1",
};

// Escape SQL LIKE metacharacters so the query matches them literally (a "%"/"_"
// in the query is a substring, not a wildcard) — paired with ESCAPE '\\'. Mirrors
// brain_store._like_escape so D1 search() is the same literal substring as the
// JSON/SQLite backends. NOTE: replace order matters — escape the backslash first.
function likeEscape(text) {
  return String(text).replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

// Optional D1 corpus index (#64). When features.corpus_d1 is ON and the DB binding
// holds a corpus-index/v1 index (scripts/corpus_index.py d1-push), search_knowledge
// answers markdown documents from their best-matching chunk with a snippet instead
// of the pack's one-line summaries. Pack items the index does not cover (the
// knowledge.jsonDocs data files) still answer from the pack, after the documents.
// OFF by default. Absent index (no binding, no tables, other schema, no pack):
// the existing path answers, unchanged. The SQL is scripts/corpus_index.py
// SEARCH_SQL verbatim: LIKE only, no FTS assumed. Its readers/restricted filter
// mirrors canRead under the policy at index time; canRead on the live config is
// the final check on every row, so a stale policy can under-return, never leak.
// The deployed knowledge pack is the reference for content: a row whose document
// is not in the pack is dropped, a row whose revision differs from the pack's is
// shown with the pack's current summary instead of the indexed snippet, and a
// corpusDigest that differs from the pack's marks the whole result stale.
const CORPUS_D1 = !!(config.features && config.features.corpus_d1);
const CORPUS_SCHEMA = "corpus-index/v1";
const CORPUS_TERMS = 6;
const CORPUS_SQL = {
  meta: "SELECT k, v FROM corpus_meta",
  search: "SELECT path, title, revision, ord, text, score FROM (SELECT path, title, revision, ord, text, score, ROW_NUMBER() OVER (PARTITION BY path ORDER BY score DESC, ord) AS rn FROM (SELECT d.path, d.title, d.revision, c.ord, c.text, d.restricted, d.readers, (?1 != '' AND c.search_text LIKE ?1 ESCAPE '\\') + (?2 != '' AND c.search_text LIKE ?2 ESCAPE '\\') + (?3 != '' AND c.search_text LIKE ?3 ESCAPE '\\') + (?4 != '' AND c.search_text LIKE ?4 ESCAPE '\\') + (?5 != '' AND c.search_text LIKE ?5 ESCAPE '\\') + (?6 != '' AND c.search_text LIKE ?6 ESCAPE '\\') AS score FROM corpus_chunk c JOIN corpus_doc d ON d.source_id = c.source_id) WHERE score > 0 AND (restricted = 0 OR ?7 = 1 OR NOT EXISTS (SELECT 1 FROM json_each(readers) AS r WHERE NOT EXISTS (SELECT 1 FROM json_each(r.value) AS o WHERE o.value = ?8 OR o.value = ?9)))) WHERE rn = 1 ORDER BY score DESC, path LIMIT ?10",
};
const CORPUS_STALE_POLICY_NOTE =
  "\n\n[corpus index is stale: it was built under a different access policy, so some permitted documents may be missing. read_doc still answers for any path you are allowed to read.]";
const CORPUS_STALE_CONTENT_NOTE =
  "\n\n[corpus index is stale: documents changed since it was built. Deleted documents are left out, changed ones show their current summary, and documents added since may be missing. read_doc returns the current text.]";

function corpusTerms(query) {
  const out = [];
  for (const t of String(query || "").toLowerCase().split(/[^a-z0-9]+/))
    if (t.length > 1 && !out.includes(t)) out.push(t);
  return out.slice(0, CORPUS_TERMS);
}

// Sorted keys, no spaces: corpus_index.canonical_json, hashed for accessDigest.
function canonicalJson(v) {
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (v && typeof v === "object")
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
  return JSON.stringify(v === undefined ? null : v);
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// The deployed pack's markdown items by path, and corpus_index.corpus_digest over
// them. Cached per pack array: the pack itself is cached per asset binding.
const packCorpusCache = new WeakMap();
async function packCorpus(pack) {
  if (packCorpusCache.has(pack)) return packCorpusCache.get(pack);
  const docs = new Map();
  for (const i of pack) {
    const path = String((i && i.path) || "");
    if (path.toLowerCase().endsWith(".md")) docs.set(path, i);
  }
  const lines = [...docs].map(([path, i]) => `${path} ${typeof i.revision === "string" ? i.revision : ""}`).sort();
  const value = { docs, digest: await sha256Hex(CORPUS_SCHEMA + "\n" + lines.join("\n")) };
  packCorpusCache.set(pack, value);
  return value;
}

function corpusSnippet(text, terms) {
  const flat = String(text || "").replace(/\s+/g, " ").trim();
  const lower = flat.toLowerCase();
  const at = Math.min(...terms.map((t) => lower.indexOf(t)).filter((i) => i >= 0), flat.length);
  const start = at === flat.length ? 0 : Math.max(0, at - 80);
  const cut = flat.slice(start, start + 240);
  return (start > 0 ? "…" : "") + cut + (start + 240 < flat.length ? "…" : "");
}

// Returns null when no usable index is bound (the caller falls through), else
// {text, note}. Rows are filtered by canRead before any snippet is built.
async function searchCorpusD1(db, query, email, gate, pack) {
  const deployed = await packCorpus(pack);
  if (!deployed.docs.size) return null; // no pack to check the index against
  let meta;
  try {
    const res = await db.prepare(CORPUS_SQL.meta).all();
    meta = Object.fromEntries(((res && res.results) || []).map((r) => [r.k, r.v]));
  } catch {
    return null; // no corpus tables in this database
  }
  if (meta.schema !== CORPUS_SCHEMA) return null;
  const policyStale = meta.accessDigest !== (await sha256Hex(canonicalJson(config.access)));
  let contentStale = meta.corpusDigest !== deployed.digest;
  const terms = corpusTerms(query);
  const lines = [];
  if (terms.length) {
    const patterns = Array.from({ length: CORPUS_TERMS }, (_, i) => (terms[i] ? "%" + likeEscape(terms[i]) + "%" : ""));
    const who = String(email || "").trim().toLowerCase();
    const allow = gate.enabled ? gate.allowFor(who) : () => true;
    const res = await db.prepare(CORPUS_SQL.search)
      .bind(...patterns, gate.isOwner(who) ? 1 : 0, who, who.split("@")[0], 60).all();
    for (const r of (res && res.results) || []) {
      const path = String(r.path || "");
      if (!path || !allow(path)) continue;
      const current = deployed.docs.get(path);
      if (!current) {
        contentStale = true; // deleted since indexing: never served
        continue;
      }
      if (current.revision === r.revision) {
        lines.push(`${path}\n  ${r.title || path} — ${corpusSnippet(r.text, terms)}`);
      } else {
        contentStale = true; // edited since indexing: the indexed text is not shown
        lines.push(`${path}\n  ${current.title || path} — ${current.summary || ""}`);
      }
      if (lines.length >= 12) break;
    }
  }
  // Pack items outside the index (jsonDocs data files), scoped like the pack path.
  const other = pack.filter((i) => !String((i && i.path) || "").toLowerCase().endsWith(".md"));
  const visible = gate.enabled ? gate.filterPackItems(other, email) : other;
  const extra = visible.length ? searchKnowledge(visible, query) : "";
  if (extra && !extra.startsWith("No matches")) lines.push(extra);
  return {
    text: lines.length ? lines.join("\n") : "No matches. Try different keywords.",
    note: (policyStale ? CORPUS_STALE_POLICY_NOTE : "") + (contentStale ? CORPUS_STALE_CONTENT_NOTE : ""),
  };
}

// Emit one structured record per chat query. Sink is intentionally lightweight:
// a single structured console.log line, captured by `wrangler tail` / Cloudflare
// Logpush — no new binding, no wrangler.toml change, no infra to stand up. If an
// engagement later declares an Analytics Engine binding named KB_OBSERVABILITY
// in wrangler.toml, the same record is also written there (durable, queryable);
// absent the binding this is skipped, so the default ships empty and clean.
// `grounded` (sources read / actions offered) vs `degraded` (fallback fired,
// zero sources, or no answer) makes the unanswered/low-confidence list queryable
// — filter on degraded:true to see what the base could not answer.
function observe(env, ctx, record) {
  if (!OBSERVABILITY) return;
  try {
    console.log(`kb_observability ${JSON.stringify(record)}`);
    const ae = env && env.KB_OBSERVABILITY;
    if (ae && typeof ae.writeDataPoint === "function") {
      ctx.waitUntil(
        Promise.resolve().then(() =>
          ae.writeDataPoint({
            // blobs: query, mode, degraded flag, tool names fired
            blobs: [
              record.query,
              record.mode,
              record.degraded ? "degraded" : "grounded",
              Object.keys(record.tools).filter((k) => record.tools[k]).join(","),
            ],
            // doubles: tool-call counts + sources read + turns used
            doubles: [
              record.tools.search_knowledge,
              record.tools.read_doc,
              record.tools.search_graph,
              record.tools.navigate,
              record.sourcesRead,
              record.turns,
            ],
            indexes: [record.degraded ? "degraded" : "grounded"],
          }),
        ),
      );
    }
  } catch {
    // Observability must never break the chat response.
  }
}

// Read the persisted theme from the kb_prefs cookie so the worker can paint the
// right palette before the page renders (no flash-of-wrong-theme). The cookie
// is written by app/theme.js + app/bubble.js as URL-encoded JSON, e.g.
// kb_prefs=%7B%22theme%22%3A%22dark%22%7D. Returns "light" | "dark" | null.
function themeFromCookie(request) {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== "kb_prefs") continue;
    try {
      const prefs = JSON.parse(decodeURIComponent(part.slice(eq + 1).trim()));
      return prefs && (prefs.theme === "light" || prefs.theme === "dark")
        ? prefs.theme
        : null;
    } catch {
      return null;
    }
  }
  return null;
}

// First-visit no-flash fallback: with no cookie yet, resolve the OS preference
// (prefers-color-scheme), falling back to the config default, and set data-theme
// synchronously in <head> before the body paints. theme.js then takes over and
// persists the choice to the cookie on first interaction.
const NOFLASH_SCRIPT = `(function(){try{var d=document.documentElement;if(d.getAttribute('data-theme'))return;var m=window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':${JSON.stringify(DEFAULT_THEME)};d.setAttribute('data-theme',m);}catch(e){}})();`;

// Cache-bust token for /app code assets: they are not content-hashed, so
// ?v=<ASSET_V> gives every js/css a fresh URL on bump — escapes any browser
// pinned to a previously-cached copy. Manually bumped date string.
const ASSET_V = "20260808";
const withV = (u) => /^\/app\/.*\.(?:js|css)(?:$|\?)/.test(u) && !/[?&]v=/.test(u)
  ? u + (u.includes("?") ? "&" : "?") + "v=" + ASSET_V
  : u;

// Normalize a portal URL for exact-match comparison: directory pages carry a
// trailing slash; absolute URLs, query/hash-bearing links, and file paths
// (…/reader.html?f=…) pass through untouched — appending "/" to those broke
// reader deep links offered by chat navigation chips.
function normUrl(u) {
  const s = String(u);
  if (s === "/") return "/";
  if (/^https?:\/\//i.test(s)) return s;   // absolute URL — a whole target, not a path
  if (/[?#]/.test(s)) return s;            // query/hash carries data past the path
  if (/\.[a-z0-9]+$/i.test(s)) return s;   // file (…/brain.html), not a directory
  return s.endsWith("/") ? s : s + "/";
}

// The only URLs the navigate tool may offer — built once from config.pages.
const ALLOWED_URLS = new Set(config.pages.map((p) => normUrl(p.url)));

// Page menu rendered into the navigate paragraph of the system prompt.
const PAGE_MENU = config.pages
  .map((p) => `${p.url} (${p.label} — ${p.description})`)
  .join(", ");

const SYSTEM = `${config.assistant.identity}

Ground every answer in what you have read this conversation — use search_knowledge to find documents, read_doc to read them, and search_graph to look up entities (people, systems, data sources, decisions) and how they relate. The graph is good for who/what/how-connected questions and for discovering related material to read; documents are the authority for details and status. When a story, feature, or decision under discussion may have implementing code, call code_context with its id — it returns real code targets when this brain's graph links them, or an honest gap; never state or guess a file or function name yourself. If the knowledge base does not cover something, say so plainly; never invent project facts. Quote decisions and statuses as recorded, with dates where they matter. Every document you read with read_doc is automatically listed as a clickable source under your answer — so read the documents you rely on, and in deep/academic modes attribute claims inline by document name and date (plain text).

When a portal page would help the user, call navigate to offer it. Use ONLY these URLs with navigate: ${PAGE_MENU}. Never navigate to .md or .json file paths. At most two navigation targets per reply.

Turn discipline: only the text in your FINAL message (after all tool calls are done) is shown to the user — text written alongside tool calls is discarded. So: search and read first, call navigate if useful, and then write the complete answer in ONE final message — never split an answer across multiple messages or turns. The final message must be a self-contained prose answer to the question. Do not narrate what you are about to do.

Length: governed by the answer-mode instruction at the end of this system prompt. The mode is a user-chosen UI setting and is AUTHORITATIVE — it overrides any length implied by the question's phrasing.

Style: simple markdown is rendered — use ## subheadings, **bold**, - bullet lists, and --- dividers where they aid scanning; prose paragraphs otherwise. NEVER write markdown link syntax [text](url), raw URLs, or file paths as links — page links are created exclusively by the navigate tool and rendered as chips. No emojis. Be direct and token-efficient — maximum information per sentence, no filler. ${config.assistant.audience}`;

// Per-user system prompt (#53). With the gate off this returns the module-level
// SYSTEM by reference, so the cached prompt block is byte-identical to today's.
// With the gate on, a page whose deep-linked document this user may not read is
// dropped from the navigate menu — otherwise the menu itself would publish the
// restricted path.
function systemFor(email, gate = ACCESS) {
  if (!gate.enabled || !PAGE_MENU) return SYSTEM;
  const visible = gate.filterPages(config.pages, email);
  if (visible.length === config.pages.length) return SYSTEM;
  const menu = visible.map((p) => `${p.url} (${p.label} — ${p.description})`).join(", ");
  return SYSTEM.replace(PAGE_MENU, () => menu);
}

const TOOLS = [
  {
    name: "search_knowledge",
    description:
      "Search the knowledge-base index (project memory, wiki, docs, specs, live trackers). Returns matching documents with path, title, and summary. Call this first for any project question, then read_doc the best matches.",
    input_schema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Keywords to search for, e.g. 'identity resolution CCID' or 'event bus ingestion'",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "read_doc",
    description:
      "Read a file from the knowledge base by its path (as returned by search_knowledge). Returns the full text (truncated if very large). Markdown, JSON, text, and code files (.py/.js/.html/.toml) supported.",
    input_schema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Repo-relative path, e.g. 'memory/decisions.md' or 'specs/manifest.json'",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "search_graph",
    description:
      "Search this brain's knowledge graph (entities: people, systems, databases, data sources, decisions, concepts — with typed relationships between them). Returns matching entities and all their relationships with neighbor names. Use for who/what/how-related questions, e.g. a person's name, a system name.",
    input_schema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Entity name or keyword, e.g. 'Common Client ID' or 'Event Hubs'",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "code_context",
    description:
      "Look up what code implements a record under discussion (a story, feature, or decision), via this brain's implemented_in edges (Navegador-populated code-realm identities, #60). Returns {address, targets, gaps} — targets are real file/symbol identities when the graph attests them; an empty targets list carries an explicit 'code-context-unavailable' gap, never a guess. Call with the record's compiled-brain id (kind:id), e.g. an id returned by search_graph.",
    input_schema: {
      type: "object",
      properties: {
        address: {
          type: "string",
          description: "The record's compiled-brain id, e.g. 'spec:phase-one/epic/feature/story-a'.",
        },
      },
      required: ["address"],
    },
  },
  {
    name: "navigate",
    description:
      "Offer the user a portal page as a clickable navigation chip in the chat UI. Use for pages that answer or illustrate their question. The user decides whether to click.",
    input_schema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Portal-relative URL, e.g. '/' or '/app/'",
        },
        label: { type: "string", description: "Short chip label, e.g. 'Knowledge Graph'" },
      },
      required: ["url", "label"],
    },
  },
];

// --- Editor agent (#38) ----------------------------------------------------
// A SEPARATE agent at /api/edit, mounted only when AUTHORING is on. It gets a
// DEDICATED editor system prompt (no nav/read persona) and the write-only
// EDIT_TOOLS below — NEVER the read TOOLS. Its tools are granular + typed +
// schema-validated + operate on ONE record per call; there is no write_file
// tool, so the blast radius is a single record and whole-file rewrites are
// impossible. Nothing the editor agent does commits on its own: it drafts a
// change set, the worker returns a diff, and a commit happens only on an
// explicit, separate /api/edit commit call (human-confirmed). Honors this
// brain's content conventions (no emoji / feedback-language) from config.
const editorSystem = (artifacts) => `You are the editor agent for ${config.brain && config.brain.name ? config.brain.name : "this brain"}'s portal. You help an authenticated operator DRAFT changes to this brain's structured records. You are not a chat or navigation assistant — you do not answer general questions, offer page links, or read documents for retrieval.

Your job: turn the operator's instruction into a precise, schema-valid change to ONE record at a time, using the typed edit tools (update_record, add_record, set_status). Each tool call targets exactly one record. You NEVER write whole files and you NEVER commit — you only stage a draft change. The operator reviews a diff and explicitly approves before anything is committed to the repository.

Editable record types: ${Object.keys(artifacts).join(", ")}. Writes target these source artifacts; the compiled brain is read-only and regenerates from them.

Discipline: make the minimum change that satisfies the instruction. Do not invent facts, dates, owners, or statuses — if a required field is unknown, leave it absent or ask the operator rather than guessing. Records you author or change are marked derived so provenance stays auditable. Honor this brain's content conventions: no emojis; plain, direct, professional language; no AI self-attribution. ${config.assistant && config.assistant.audience ? config.assistant.audience : ""}`;

// Write-only tools for the editor agent. Granular, typed, ONE record per call,
// schema-validated before commit. Deliberately NO write_file / no raw path write.
const EDIT_TOOLS = [
  {
    name: "update_record",
    description:
      "Stage an update to the fields of ONE existing record in an editable artifact. Does not commit — produces a draft change for operator review. Only the given fields are changed; others are left as-is.",
    input_schema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          description: "Artifact type, one of the editable record types.",
        },
        id: {
          type: "string",
          description: "The record's identifier (its `id`, or `title` when the artifact has no id).",
        },
        fields: {
          type: "object",
          description: "The fields to change, as a JSON object of key -> new value. One record only.",
        },
        unset: {
          type: "array",
          items: { type: "string" },
          description: "Optional fields to remove from the record (clearing a value). Required fields cannot be removed.",
        },
      },
      required: ["type", "id", "fields"],
    },
  },
  {
    name: "add_record",
    description:
      "Stage the creation of ONE new record in an editable artifact. Does not commit — produces a draft change for operator review. The new record is marked derived:true (portal-authored).",
    input_schema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          description: "Artifact type, one of the editable record types.",
        },
        data: {
          type: "object",
          description: "The new record as a JSON object. Must satisfy that artifact's schema.",
        },
      },
      required: ["type", "data"],
    },
  },
  {
    name: "set_status",
    description:
      "Stage a status change on ONE existing record (e.g. an action item to 'done', an open question to 'resolved'). Does not commit — produces a draft change for operator review.",
    input_schema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          description: "Artifact type, one of the editable record types.",
        },
        id: { type: "string", description: "The record's identifier (`id` or `title`)." },
        status: { type: "string", description: "The new status value." },
      },
      required: ["type", "id", "status"],
    },
  },
];

// EDIT_TOOLS with each `type` constrained to the editable types derived for this
// request, so the model cannot name an anchor or non-editable kind.
function editTools(artifacts) {
  const types = Object.keys(artifacts);
  return EDIT_TOOLS.map((t) => {
    const tool = JSON.parse(JSON.stringify(t));
    tool.input_schema.properties.type.enum = types;
    return tool;
  });
}

// Credentials never enter authored records, commit messages or commit identity
// (#38). Checks the Worker's own secret values plus well-known token shapes.
const CREDENTIAL_ENV = ["GITHUB_TOKEN", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "KNOWLEDGE_POLICY_SECRET", "BRAIN_OPERATIONS_CREDENTIALS"];
const CREDENTIAL_SHAPES = [
  /\bgh[pousr]_[A-Za-z0-9]{20,}/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bsk-ant-[A-Za-z0-9_-]{16,}/,
  /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{16,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];
function carriesCredential(env, text) {
  const s = String(text == null ? "" : text);
  for (const k of CREDENTIAL_ENV) {
    const v = env && env[k];
    if (typeof v === "string" && v.length >= 8 && s.includes(v)) return true;
  }
  return CREDENTIAL_SHAPES.some((re) => re.test(s));
}

// --- Model client seam (#62) -----------------------------------------------
// Every agent path builds its model client through this factory instead of
// calling `new Anthropic(...)` inline, so a test can inject a scripted fake and
// exercise the agent loop with no network. Production behavior is unchanged:
// the default factory is exactly the constructor call it replaced.
// With provider "openai", the adapter module loads on first use (a dynamic
// import, like policy-authoring.js), so an Anthropic brain never evaluates it.
const openAIModelClient = (env) => ({
  messages: {
    stream(params) {
      return {
        async finalMessage() {
          const { createOpenAIClient } = await import("./openai-client.js");
          const client = createOpenAIClient({ apiKey: env.OPENAI_API_KEY, baseUrl: config.assistant.baseUrl });
          return client.messages.stream(params).finalMessage();
        },
      };
    },
  },
});
const defaultModelClient = PROVIDER === "openai"
  ? openAIModelClient
  : (env) => new Anthropic({ apiKey: env.ANTHROPIC_API_KEY });
let modelClientFactory = defaultModelClient;

// Inject a model client factory (env) => client, where `client` exposes
// `messages.stream(params)` returning `{ finalMessage(): Promise<Message> }`.
// Pass nothing (or null) to restore the real SDK client. Test-only seam; nothing
// in the served portal calls this.
export function setModelClientFactory(factory) {
  modelClientFactory = typeof factory === "function" ? factory : defaultModelClient;
}

// --- Fault-tolerant artifact loaders (#62) ---------------------------------
// A missing, unreachable, or malformed knowledge artifact must degrade the ONE
// tool that reads it, never kill the agent. Every loader funnels through here:
// any failure (fetch error, non-200, invalid JSON, unexpected shape) resolves to
// the caller's empty value, which is then cached like a successful load so a
// broken artifact is not re-fetched on every tool call.
async function loadJsonAsset(env, path, shape, empty) {
  try {
    const resp = await env.ASSETS.fetch(`https://portal/${path}`);
    if (!resp || !resp.ok) return empty;
    const data = await resp.json();
    const out = shape(data);
    return out === undefined || out === null ? empty : out;
  } catch {
    return empty;
  }
}

// Raw caches belong to the asset binding, not to a requesting actor or a
// module-wide first caller. Composed Workers may use distinct corpus bindings.
async function cachedAsset(cache, env, path, shape, empty) {
  const binding = env?.ASSETS;
  const keyed = binding && ["object", "function"].includes(typeof binding);
  if (keyed && cache.has(binding)) return cache.get(binding);
  const value = await loadJsonAsset(env, path, shape, empty);
  if (keyed) cache.set(binding, value);
  return value;
}

const packCache = new WeakMap();
async function loadPack(env) {
  return cachedAsset(packCache, env, "app/knowledge-pack.json",
    (data) => (Array.isArray(data && data.items) ? data.items.filter((i) => i && typeof i === "object") : []), []);
}

function searchKnowledge(pack, query) {
  const terms = query.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 1);
  // Records are read defensively: a pack entry missing title/summary/path is a
  // content problem, not a reason to fail the search (#62).
  const scored = pack
    .map((raw) => {
      const item = {
        path: String((raw && raw.path) || ""),
        title: String((raw && raw.title) || ""),
        summary: String((raw && raw.summary) || ""),
      };
      const hay = `${item.path} ${item.title} ${item.summary}`.toLowerCase();
      const title = item.title.toLowerCase();
      let score = 0;
      for (const t of terms) {
        if (hay.includes(t)) score += 1;
        if (title.includes(t)) score += 2;
      }
      return { item, score };
    })
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 12);
  if (!scored.length) return "No matches. Try different keywords.";
  return scored
    .map(({ item }) => `${item.path}\n  ${item.title} — ${item.summary}`)
    .join("\n");
}

// Normalize either graph shape into {nodes, edges}. Malformed members are
// dropped rather than crashing the tool (#62).
function asGraph(data) {
  return {
    nodes: Array.isArray(data && data.nodes) ? data.nodes.filter((n) => n && typeof n === "object") : [],
    edges: Array.isArray(data && data.edges) ? data.edges.filter((e) => e && typeof e === "object") : [],
  };
}

const graphCache = new WeakMap();
async function loadGraph(env) {
  return cachedAsset(graphCache, env, "app/knowledge_graph.json", asGraph, {nodes: [], edges: []});
}

// Compiled-brain fallback for search_graph (#62). The extracted semantic KG is
// empty until discovery material has been processed, but the compiled brain is
// always a graph (decisions, sessions, stakeholders, terms and the edges between
// them). searchGraph reads both shapes, so the fallback is the same search over
// a different source.
const brainGraphCache = new WeakMap();
async function loadBrainGraph(env) {
  return cachedAsset(brainGraphCache, env, "app/brain.json", asGraph, {nodes: [], edges: []});
}

// Shape-agnostic accessors: the extracted KG uses name/type on nodes and
// source/target/type on edges; the compiled brain uses title/kind and
// source/target/rel. One search covers both.
const nodeLabel = (n) => String(n.name || n.title || n.id || "");
const nodeKind = (n) => String(n.type || n.kind || "entity");
const edgeRel = (e) => String(e.type || e.rel || "related_to");

function searchGraph(graph, query) {
  const q = String(query || "").toLowerCase();
  const terms = q.split(/[^a-z0-9]+/).filter((t) => t.length > 1);
  const hits = graph.nodes
    .map((n) => {
      const name = nodeLabel(n).toLowerCase();
      let score = 0;
      if (name && name === q) score += 10;
      if (name && q && name.includes(q)) score += 5;
      for (const t of terms) if (name.includes(t)) score += 1;
      return { n, score };
    })
    .filter((h) => h.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);
  if (!hits.length) return "No matching entities. Try a different name or keyword.";
  const out = [];
  for (const { n } of hits) {
    const id = n.id;
    const rels = graph.edges
      .filter((e) => e.source === id || e.target === id)
      .slice(0, 30)
      .map((e) =>
        e.source === id ? `  -> ${edgeRel(e)} -> ${e.target}` : `  <- ${edgeRel(e)} <- ${e.source}`,
      );
    const sessions = Array.isArray(n.sessions) && n.sessions.length
      ? ` [sessions: ${n.sessions.join(", ")}]`
      : "";
    out.push(
      `${nodeLabel(n) || id} (${nodeKind(n)})${sessions}\n` +
        (rels.length ? rels.join("\n") : "  (no relationships recorded)"),
    );
  }
  return out.join("\n\n");
}

// --- D1 edge-store reads (#37) --------------------------------------------
// Reached ONLY when BRAIN_D1 && env.DB. Each runs an indexed SELECT against the
// brain.db schema in D1 (node.search_text / node.id / edge.src/dst) — the same
// statements brain_store.py runs locally — so a large brain answers without the
// JSON ever entering worker memory. The D1 client returns {results: [{col:val}]}.

// search_knowledge over D1: substring match on node.search_text (the precomputed,
// already-lowercased haystack). Returns the same "path\n  title — summary" shape
// as the JSON searchKnowledge so the agent sees one stable contract.
//
// `allow` is the per-request read predicate (#53). It defaults to permit-all, so
// with no access config this function issues the same query and returns the same
// string it always did.
async function searchKnowledgeD1(db, query, allow = () => true, allowNode = () => true) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return "No matches. Try different keywords.";
  const pattern = "%" + likeEscape(q) + "%";
  const res = await db.prepare(D1_SQL.search).bind(pattern, 12).all();
  const rows = (res && res.results) || [];
  if (!rows.length) return "No matches. Try different keywords.";
  const lines = [];
  for (const r of rows) {
    let n;
    try {
      n = JSON.parse(r.json);
    } catch {
      continue; // an unparseable row is not something to render, or to leak
    }
    if (!nodePaths(n).every(allow) || !allowNode(n)) continue;
    const summary = (n.text || "").replace(/\s+/g, " ").slice(0, 200);
    const path = (n.source && n.source.path) || n.source || n.id;
    lines.push(`${path}\n  ${n.title || n.id} — ${summary}`);
  }
  if (!lines.length) return "No matches. Try different keywords.";
  return lines.join("\n");
}

// search_graph over D1: find matching nodes by substring, then one indexed hop
// for each to list neighbors — mirrors searchGraph's output without loading the
// whole graph. Neighbor lookups use the edge src/dst indexes.
//
// `allow` (#53) drops nodes sourced from a document this user may not read,
// exactly as the JSON path does. Neighbor NAMES are entity labels, not paths, so
// an engagement whose entity names are themselves sensitive puts search_graph in
// access.restricted_tools; that is what the tool gate is for.
export async function searchGraphD1(db, query, allow = () => true, allowNode = () => true) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return "No matching entities. Try a different name or keyword.";
  const pattern = "%" + likeEscape(q) + "%";
  const res = await db.prepare(D1_SQL.search).bind(pattern, 5).all();
  const rows = (res && res.results) || [];
  if (!rows.length) return "No matching entities. Try a different name or keyword.";
  const out = [];
  for (const row of rows) {
    let n;
    try {
      n = JSON.parse(row.json);
    } catch {
      continue;
    }
    if (!nodePaths(n).every(allow) || !allowNode(n)) continue;
    const [outRes, inRes] = await Promise.all([
      db.prepare(D1_SQL.neighborsOut).bind(n.id).all(),
      db.prepare(D1_SQL.neighborsIn).bind(n.id).all(),
    ]);
    const rels = [];
    const permitted = (r) => {
      try {
        const edge = JSON.parse(r.edge_json);
        const neighbor = JSON.parse(r.node_json);
        return nodePaths(neighbor).every(allow) && allowNode(neighbor) && nodePaths({ evidence: edge.evidence }).every(allow);
      } catch {
        return false;
      }
    };
    for (const r of ((outRes && outRes.results) || []).filter(permitted).slice(0, 30)) rels.push(`  -> ${r.type} -> ${r.nb}`);
    for (const r of ((inRes && inRes.results) || []).filter(permitted).slice(0, 30)) rels.push(`  <- ${r.type} <- ${r.nb}`);
    out.push(
      `${n.title || n.id} (${n.kind || "entity"})\n` +
        (rels.length ? rels.join("\n") : "  (no relationships recorded)"),
    );
  }
  if (!out.length) return "No matching entities. Try a different name or keyword.";
  return out.join("\n\n");
}

// Strict read_doc path validation (#62). Returns the canonical corpus-relative
// path, or null when the request must be refused. The old code stripped ".."
// substrings, which mangled legitimate names and still let encoded traversal
// through; this validates SEGMENTS instead and refuses anything that is not a
// plain path inside the served corpus:
//   - percent-encoded forms are decoded first (%2e%2e%2f is the same attack)
//   - "\" is normalized to "/" so Windows-style paths cannot slip past
//   - control characters, scheme-qualified URLs, drive letters, "~" are refused
//   - any "." or ".." segment is refused (no traversal, no implicit cwd)
//   - any dot-prefixed segment is refused (.git/, .dev.vars are not corpus)
//   - the extension must be supported, and DOC_ROOTS (when configured) must contain it
// A single leading "/" is portal-root-relative (the form the model tends to
// emit) and is normalized away, not treated as a filesystem-absolute path; the
// asset binding cannot reach outside the deployed bundle either way.
function safeDocPath(raw) {
  let p = String(raw == null ? "" : raw).trim();
  if (!p) return null;
  if (/%[0-9a-f]{2}/i.test(p)) {
    try {
      p = decodeURIComponent(p);
    } catch {
      return null;
    }
  }
  p = p.replace(/\\/g, "/");
  if (/[\u0000-\u001f\u007f]/.test(p)) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(p)) return null; // https:, file:, data:, C:/…
  if (p.startsWith("~")) return null;
  if (p.startsWith("//")) return null; // protocol-relative
  const parts = p.split("/").filter((s) => s !== "");
  if (!parts.length) return null;
  for (const seg of parts) {
    if (seg === "." || seg === "..") return null;
    if (seg.startsWith(".")) return null;
  }
  const clean = parts.join("/");
  if (!DOC_EXT.test(clean)) return null;
  if (DOC_ROOTS.length && !DOC_ROOTS.some((r) => clean === r || clean.startsWith(r + "/"))) return null;
  return clean;
}

async function readDoc(env, path, email = "", gate = ACCESS) {
  const clean = safeDocPath(path);
  if (!clean)
    return "Error: refused — read_doc takes a plain path inside the knowledge base (no absolute paths, no '..', no dot-directories) with a supported extension (.md .json .txt .py .js .toml .html .css).";
  // Access scoping (#53). Checked on the CANONICAL path that is about to be
  // fetched, so no spelling of the path can reach a document the check refused.
  // Fail closed: an access-controlled document is invisible to everyone outside
  // its owners, whatever path the model asks for.
  if (!gate.canRead(clean, email))
    return "Error: that document is access-controlled and not available to this user.";
  let resp;
  try {
    const request = new Request(`https://portal/${clean}`, {
      headers: {"Cf-Access-Authenticated-User-Email": email},
    });
    resp = gate.present ? await serveScoped(request, env, new URL(request.url), gate) : null;
    if (!resp) resp = await env.ASSETS.fetch(request.url);
  } catch {
    return `Error: ${clean} could not be read.`;
  }
  if (!resp || !resp.ok) return `Error: ${clean} not found (${resp ? resp.status : "no response"}).`;
  const text = await resp.text();
  return text.length > MAX_DOC_CHARS
    ? text.slice(0, MAX_DOC_CHARS) + `\n\n[truncated — ${text.length} chars total]`
    : text;
}

// Charge one tool result against the per-request context budget (#62). Applied
// in block order after the concurrent tool calls settle, so the truncation point
// is deterministic regardless of which tool finished first.
function chargeToolBudget(text, budget) {
  const s = typeof text === "string" ? text : String(text == null ? "" : text);
  const room = budget.limit - budget.used;
  if (room <= 0) return TOOL_BUDGET_MARKER;
  if (s.length <= room) {
    budget.used += s.length;
    return s;
  }
  budget.used = budget.limit;
  return (
    s.slice(0, room) +
    `\n\n[truncated — per-request tool-output budget of ${budget.limit} chars reached]`
  );
}

// Serve-time federation (#209). When the Worker has a BRAIN_FEDERATION_SERVICE
// binding and BRAIN_FEDERATION_CREDENTIALS, search_knowledge and search_graph
// read the federation host instead of this portal's own index. Without both,
// nothing here runs and the single-brain tools are unchanged.
//
// Identity follows the context-inspection extension: the Cloudflare Access email
// selects an exact per-user bearer credential from the Worker secret; there is no
// shared fallback and no caller-supplied bearer. The host maps the credential to
// a policy principal and applies discovery, source policy and publication checks
// on every request, so a withdrawn participant disappears on the next call.

const FEDERATION_LIMIT = 1048576;
const FEDERATION_DEADLINE_MS = 10000;
const FEDERATION_SEARCH_BUDGET = { maxSources: 64, maxMatches: 12, maxBytes: 262144 };
const FEDERATION_COMPOSE_BUDGET = { maxSources: 64, maxNodes: 1000, maxEdges: 2000, maxBytes: FEDERATION_LIMIT };

function federationConfigured(env) {
  return Boolean(env && env.BRAIN_FEDERATION_SERVICE && typeof env.BRAIN_FEDERATION_SERVICE.fetch === "function" &&
    env.BRAIN_FEDERATION_CREDENTIALS);
}

// A credential key is the Access email or, with the person register bound
// (#212), a `person:<slug>` / `oidc:<issuer>#<subject>` resolving to the same
// principal as that email. Keys that match one user with different tokens deny.
function federationCredential(env, email, gate = ACCESS) {
  const mapping = JSON.parse(env.BRAIN_FEDERATION_CREDENTIALS);
  const principal = email ? gate.principalOf(email) : null;
  const tokens = new Set(Object.entries(mapping)
    .filter(([key]) => email && (key === email || (principal && gate.resolvePrincipal(key) === principal)))
    .map(([, value]) => value));
  const token = tokens.size === 1 ? [...tokens][0] : null;
  if (typeof token !== "string" || token.length > 4096 || !/^[A-Za-z0-9._~+/\-]+=*$/.test(token)) return null;
  return token;
}

// Whether any credential key names a person, so the register must be bound.
function federationNamesPeople(env) {
  if (!federationConfigured(env)) return false;
  try {
    return Object.keys(JSON.parse(env.BRAIN_FEDERATION_CREDENTIALS))
      .some((key) => key.startsWith("person:") || key.startsWith("oidc:"));
  } catch {
    return false;
  }
}

// The gate with app/people.json bound when an owner spec or a federation
// credential key names a person (#212). Loaded once per isolate from the served
// bundle; an unreadable register leaves person specs matching nobody.
const BOUND_GATES = new WeakMap();
async function withPrincipals(env, gate) {
  if (!gate.needsRegister && !federationNamesPeople(env)) return gate;
  if (BOUND_GATES.has(gate)) return BOUND_GATES.get(gate);
  let register;
  try {
    const response = await env.ASSETS.fetch("https://portal/app/people.json");
    if (!response || !response.ok) return gate;
    register = await response.json();
  } catch {
    return gate;
  }
  const bound = gate.bindRegister(register);
  if (bound.lockdown && !gate.lockdown) {
    console.error(`person register is unusable — serving in LOCKDOWN: ${bound.problems.join("; ")}`);
  }
  BOUND_GATES.set(gate, bound);
  return bound;
}

async function federationCall(env, token, operation, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FEDERATION_DEADLINE_MS);
  try {
    const reply = await env.BRAIN_FEDERATION_SERVICE.fetch("https://brain-federation.internal/federation/" + operation, {
      method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + token },
      body: JSON.stringify(body), signal: controller.signal, redirect: "error",
    });
    const raw = await reply.text();
    if (reply.status !== 200) throw new Error(`federation host refused (${reply.status})`);
    if (raw.length > FEDERATION_LIMIT) throw new Error("federation host reply exceeds its limit");
    return JSON.parse(raw);
  } finally {
    clearTimeout(timer);
  }
}

// The actor's selectable sources with a capability, at their current revisions.
async function federationSources(env, token, capability) {
  const basis = await federationCall(env, token, "basis", {});
  return (basis.sources || [])
    .filter((s) => Array.isArray(s.capabilities) && s.capabilities.includes(capability))
    .map(({ participant, realm, revision }) => ({ participant, realm, revision }));
}

const federationUnavailable = (rows) => rows
  .filter((r) => r.status === "unavailable")
  .map((r) => `${r.source.participant}/${r.source.realm}: unavailable (${r.reason})`);

async function federatedSearch(env, email, query, gate = ACCESS) {
  const token = federationCredential(env, email, gate);
  if (!token) return "Error: federated search is not available to this user.";
  const sources = await federationSources(env, token, "search");
  if (!sources.length) return "No federated sources are available to this user.";
  const result = await federationCall(env, token, "search", {
    protocolVersion: "1.0", query: String(query || "").slice(0, 256), sources, budget: FEDERATION_SEARCH_BUDGET,
  });
  const lines = result.matches.map(({ target, record }) =>
    `${target.participant}/${target.realm}: ${record.id}\n  ${record.title || record.kind || ""} — ${String(record.text || "").slice(0, 200)}`);
  const notes = federationUnavailable(result.sources);
  if (!lines.length) return ["No matches. Try different keywords.", ...notes].join("\n");
  return [...lines, ...notes].join("\n");
}

// Compose the actor's authorized graphs, then run the portal's own graph search
// over the composed nodes and edges (coordinates keep each participant distinct).
async function federatedGraph(env, email, query, gate = ACCESS) {
  const token = federationCredential(env, email, gate);
  if (!token) return "Error: federated search is not available to this user.";
  const sources = await federationSources(env, token, "compose");
  if (!sources.length) return "No federated sources are available to this user.";
  const result = await federationCall(env, token, "compose", { protocolVersion: "1.0", sources, budget: FEDERATION_COMPOSE_BUDGET });
  const key = (c) => `${c.participant}/${c.realm}:${c.address}`;
  const graph = {
    nodes: result.nodes.map(({ coordinate, record }) => ({ ...record, id: key(coordinate),
      name: `${nodeLabel(record)} [${coordinate.participant}/${coordinate.realm}]` })),
    edges: result.edges.map(({ source, target, record }) => ({ ...record, source: key(source), target: key(target) })),
  };
  const notes = federationUnavailable(result.sources);
  return [searchGraph(graph, query), ...notes].join("\n");
}

// Execute ONE read-only tool call. Returns { text, source?, action? }; the
// caller applies the ordered side effects (budget, sources list, nav chips).
// Every failure is caught here so a single broken tool degrades to a message the
// model can work around instead of failing the request (#62).
// `email` is the Cloudflare Access identity (#53), "" when unauthenticated or
// when the portal has no access config. Every branch that can surface a document
// path or body is scoped through it; with the gate disabled `scope` permits
// everything and each call is the one it always was.
async function runToolCall(env, pack, block, email = "", gate = ACCESS, federationEmail = email) {
  const input = (block && block.input) || {};
  const scoped = gate.enabled;
  const allow = scoped ? gate.allowFor(email) : null;
  try {
    // Whole-tool gate: output that is aggregate or entity-led cannot be
    // path-redacted, so an engagement may withhold such a tool from non-owners.
    if (scoped && !gate.toolAllowed(block.name, email)) {
      return { text: `Error: ${block.name} is not available to this user. Answer from the other tools.` };
    }
    if (block.name === "search_knowledge") {
      if (federationConfigured(env)) return { text: await federatedSearch(env, federationEmail, input.query || "", gate) };
      // D1 corpus index (#64) when on and loaded: redacted like every path-led
      // search, with any stale note appended after redaction.
      if (CORPUS_D1 && env.DB) {
        const hit = await searchCorpusD1(env.DB, input.query || "", email, gate, pack);
        if (hit) return { text: (scoped ? gate.redactSearch(hit.text, email) : hit.text) + hit.note };
      }
      // D1 edge store (#37) when on; else the JSON-in-memory pack (default).
      if (BRAIN_D1 && env.DB) {
        const text = await searchKnowledgeD1(env.DB, input.query || "", allow || undefined,
          gate.nodeAllowed ? (node) => gate.nodeAllowed(node, email) : undefined);
        return { text: scoped ? gate.redactSearch(text, email) : text };
      }
      // The pack cache is loaded raw (one copy for the isolate) and scoped here,
      // per request, so one user's view is never cached as another's.
      const visible = scoped ? gate.filterPackItems(pack, email) : pack;
      if (!visible.length)
        return { text: "The knowledge index is unavailable or empty — no documents are indexed. Try search_graph, or say plainly that the knowledge base does not cover this." };
      const text = searchKnowledge(visible, input.query || "");
      // Belt and braces: the result is path-led, so redact it too. Structural
      // filtering above is the real gate; this catches any future formatter.
      return { text: scoped ? gate.redactSearch(text, email) : text };
    }
    if (block.name === "search_graph") {
      if (federationConfigured(env)) return { text: await federatedGraph(env, federationEmail, input.query || "", gate) };
      if (BRAIN_D1 && env.DB) return { text: await searchGraphD1(env.DB, input.query || "", allow || undefined,
        gate.nodeAllowed ? (node) => gate.nodeAllowed(node, email) : undefined) };
      // Nodes sourced from a restricted document are dropped, and every edge
      // that then dangles goes with them — an edge naming a restricted document
      // reveals it just as surely as serving it.
      const graph = scoped ? gate.filterGraph(await loadGraph(env), email) : await loadGraph(env);
      if (graph.nodes.length) return { text: searchGraph(graph, input.query || "") };
      // Semantic KG empty (no discovery material processed yet, or the artifact
      // is unreadable): fall back to the compiled brain, which is also a graph.
      const brain = scoped ? gate.filterGraph(await loadBrainGraph(env), email) : await loadBrainGraph(env);
      if (brain.nodes.length) return { text: searchGraph(brain, input.query || "") };
      return { text: "The knowledge graph is unavailable or empty. Use search_knowledge and read_doc instead." };
    }
    if (block.name === "code_context") {
      const address = String(input.address || "").trim();
      if (!address)
        return { text: "Error: address is required — pass a compiled-brain record id (e.g. from search_graph)." };
      const graph = await loadBrainGraph(env);
      // Visibility uses the SAME node check every other read tool applies (#53).
      // A record this reader may not see answers identically whether or not it
      // exists at all — never distinguishing "restricted" from "not found".
      const visible = scoped ? gate.filterGraph(graph, email) : graph;
      if (!visible.nodes.some((n) => n && n.id === address))
        return { text: "Error: address does not resolve to a record this user may read." };
      // implemented_in's target is a raw realm-qualified string, never a brain
      // node id (#60 slice 2 — the code realm is never compiled into the brain),
      // so the generic edge filter above (which keeps an edge only when BOTH
      // endpoints survive as node ids) can never keep this edge. Read it
      // directly from the compiled brain instead, and gate each target's own
      // path the same way a knowledge-base document path is gated.
      const targets = [];
      for (const e of graph.edges) {
        if (!e || e.source !== address || edgeRel(e) !== "implemented_in") continue;
        const raw = String(e.target || "").trim();
        if (!raw) continue;
        const hash = raw.indexOf("#");
        const path = hash === -1 ? raw : raw.slice(0, hash);
        if (scoped && !allow(path)) continue;
        targets.push({ target: raw, path, symbol: hash === -1 ? null : raw.slice(hash + 1) });
      }
      return {
        text: JSON.stringify({ address, targets, gaps: targets.length ? [] : ["code-context-unavailable"] }),
      };
    }
    if (block.name === "read_doc") {
      const text = await readDoc(env, input.path || "", email, gate);
      const source = text.startsWith("Error") ? null : safeDocPath(input.path || "");
      return { text, source };
    }
    if (block.name === "navigate") {
      const u = normUrl(input.url || "/");
      // A page whose deep-linked document this user may not read is not offered.
      if (!ALLOWED_URLS.has(u) || (scoped && !gate.pageAllowed({ url: input.url || u }, email)))
        return { text: "Rejected: URL is not an allowed portal page. Use only the URLs listed in your instructions." };
      return {
        text: "Navigation chip added to the reply.",
        action: { url: u, label: String(input.label || "Open") },
      };
    }
    return { text: `Unknown tool: ${block.name}` };
  } catch (err) {
    return {
      text: `Error: ${block.name} is temporarily unavailable (${String((err && err.message) || err)}). Continue with the other tools and answer from what you have.`,
    };
  }
}

async function handleChat(request, env, ctx, gate = ACCESS) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const history = Array.isArray(body.messages) ? body.messages.slice(-40) : [];
  if (!history.length || history[history.length - 1].role !== "user") {
    return json({ error: "messages must end with a user message" }, 400);
  }

  if (MODEL_CONFIG_ERROR) return json({ error: `chat unavailable: ${MODEL_CONFIG_ERROR}` }, 503);
  const client = modelClientFactory(env);
  const pack = await loadPack(env);

  // Identity-aware scoping (#53). Read for AUTHZ only — the observability record
  // below still carries no identity, by design. "" when the portal has no access
  // config or the request carries no Access header.
  const userEmail = gate.present ? accessEmail(request) : "";
  // Tools withheld from this user are removed from the tool list as well as
  // refused at call time, so the model never sees a tool it cannot use.
  const userTools = gate.enabled ? TOOLS.filter((t) => gate.toolAllowed(t.name, userEmail)) : TOOLS;
  const userSystem = systemFor(userEmail, gate);
  // Defense in depth: the tools already hide what this user may not read; this
  // tells the model not to reconstruct it from pre-training or context.
  const identityNote = gate.enabled ? gate.identityNote(userEmail) : "";

  const MODES = {
    terse: {
      effort: "medium",
      maxTokens: 750,
      hint: "Answer mode: TERSE. HARD LIMIT: the final answer is 1-2 sentences — the single most important fact, nothing else. No headings, no lists. Overrides ANY request for detail in the question; the user can switch modes for more.",
    },
    brief: {
      effort: "medium",
      maxTokens: 1500,
      hint: "Answer mode: BRIEF. HARD LIMIT: the final answer is at most 5 sentences (~100 words). No headings, no lists, no dividers — one short paragraph. Research properly first, then distill to the essentials. This limit overrides ANY request for detail in the user's question (\"explain everything\", \"walk me through\") — give the 5-sentence core and note they can switch the chat to deep mode for the full picture.",
    },
    standard: {
      effort: "medium",
      maxTokens: 15000,
      hint: "Answer mode: STANDARD — match length to the ask: tight for narrow questions, fuller (with headings/lists) for broad ones.",
    },
    deep: {
      effort: "high",
      maxTokens: 30000,
      hint: "Answer mode: DEEP — be exhaustive: read every relevant document, cover all angles, organized with headings and lists.",
    },
    academic: {
      effort: "high",
      maxTokens: 60000,
      hint: "Answer mode: ACADEMIC — exhaustive and rigorous. Read every relevant document. Structure: a one-paragraph abstract, then sections with headings. Define terms on first use. Attribute every claim to its source document by name and date (as plain text, never links). State confidence and known gaps explicitly; end with open questions and their owners. Formal register.",
    },
  };
  const mode = MODES[body.mode] || MODES.standard;

  // History from the client is text-only turns; tool round-trips stay server-side per request.
  const messages = history.map((m) => ({
    role: m.role === "assistant" ? "assistant" : "user",
    content: String(m.content).slice(0, 32000),
  }));

  const actions = [];
  const textsSeen = [];
  const sourcesRead = [];
  // Per-query tool-firing tally for observability (#30).
  const toolCalls = { search_knowledge: 0, read_doc: 0, search_graph: 0, code_context: 0, navigate: 0 };
  let turnsUsed = 0;
  let response;
  // Mid-loop model API failure (#62): the loop stops, and the request still
  // answers with whatever was gathered plus an honest note — never a 500.
  let modelFailed = false;
  // Per-request tool-output context budget (#62), shared across every turn.
  const budget = { limit: MAX_TOOL_OUTPUT_CHARS, used: 0 };
  for (let turn = 0; turn < MAX_AGENT_TURNS; turn++) {
    turnsUsed = turn + 1;
    try {
      const stream = client.messages.stream({
        model: MODEL,
        max_tokens: mode.maxTokens,
        thinking: { type: "adaptive" },
        output_config: { effort: mode.effort },
        system: [
          { type: "text", text: userSystem, cache_control: { type: "ephemeral" } },
          { type: "text", text: mode.hint },
          ...(identityNote ? [{ type: "text", text: identityNote }] : []),
        ],
        tools: userTools,
        messages,
      });
      const next = await stream.finalMessage();
      if (!next || !Array.isArray(next.content)) throw new Error("empty model response");
      response = next;
    } catch (err) {
      // Log for observability; the user gets the partial answer, not the detail.
      console.warn(`chat model error on turn ${turnsUsed}: ${String((err && err.message) || err)}`);
      modelFailed = true;
      break;
    }

    for (const b of response.content) {
      if (b.type === "text" && b.text.trim()) textsSeen.push(b.text.trim());
    }
    if (response.stop_reason !== "tool_use") break;

    // Navigate-only turns: the model writes its answer alongside navigate
    // calls. Collect the chips and treat this turn's text as final instead of
    // forcing another round trip (which orphans the real answer).
    const toolBlocks = response.content.filter((b) => b.type === "tool_use");
    if (toolBlocks.length && toolBlocks.every((b) => b.name === "navigate") &&
        (!gate.enabled || gate.toolAllowed("navigate", userEmail))) {
      for (const block of toolBlocks) {
        toolCalls.navigate += 1;
        const input = block.input || {};
        const u = normUrl(input.url || "/");
        // Same page scoping as runToolCall's navigate branch (#53).
        if (ALLOWED_URLS.has(u) && (!gate.enabled || gate.pageAllowed({ url: input.url || u }, userEmail))) {
          actions.push({ url: u, label: String(input.label || "Open") });
        }
      }
      break;
    }

    messages.push({ role: "assistant", content: response.content });
    // All four tools are READ-ONLY and independent, so the calls in one turn run
    // concurrently instead of serially (#62) — a turn that reads three documents
    // costs one round trip, not three. Ordered state (context budget, source
    // list, nav chips, tool tally) is applied below in BLOCK order, so the
    // conversation the model sees is identical whatever order they complete in.
    const callBlocks = response.content.filter((b) => b.type === "tool_use");
    const settled = await Promise.all(callBlocks.map((block) => runToolCall(env, pack, block, userEmail, gate, accessEmail(request))));
    const results = [];
    for (let i = 0; i < callBlocks.length; i++) {
      const block = callBlocks[i];
      const outcome = settled[i] || { text: "" };
      if (block.name in toolCalls) toolCalls[block.name] += 1;
      if (outcome.source && !sourcesRead.includes(outcome.source)) sourcesRead.push(outcome.source);
      if (outcome.action) actions.push(outcome.action);
      results.push({
        type: "tool_result",
        tool_use_id: block.id,
        content: chargeToolBudget(outcome.text, budget),
      });
    }
    messages.push({ role: "user", content: results });
  }

  // Strip markdown link syntax the model emitted despite instructions —
  // navigation belongs to the chips. Other markdown renders in the bubble.
  const deLink = (t) => t.replace(/\[([^\]]+)\]\(([^)]*)\)/g, "$1").trim();

  let reply = deLink(
    (((response && response.content) || []))
      .filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("\n"),
  );
  // Degenerate final message (e.g. links-only or near-empty): fall back to the
  // longest substantive text produced anywhere in the loop.
  const minReply = { terse: 40, brief: 60, standard: 200, deep: 600, academic: 600 }[body.mode] || 200;
  // Did the degenerate-reply fallback fire? (links-only/near-empty final message)
  const fallbackFired = reply.length < minReply;
  if (fallbackFired) {
    const best = textsSeen.map(deLink).sort((a, b) => b.length - a.length)[0] || "";
    if (best.length > reply.length) reply = best;
  }
  // Model API failure mid-loop (#62): degrade gracefully. Prefer the longest
  // substantive text produced before the failure, and label the reply as partial
  // so the user is not told a truncated answer is the whole story.
  if (modelFailed) {
    const best = textsSeen.map(deLink).sort((a, b) => b.length - a.length)[0] || "";
    if (best.length > reply.length) reply = best;
    if (reply) reply += PARTIAL_NOTE;
  }
  const sources = sourcesRead.map((p) => {
    const item = pack.find((i) => i && i.path === p);
    return { path: p, title: item && item.title ? item.title : p.split("/").pop() };
  });
  const answered =
    reply ||
    (modelFailed
      ? "I could not complete this answer: the model service returned an error. Please try again."
      : "I could not produce an answer — try rephrasing.");

  // Observability (#30): record the query + answer disposition. GROUNDED when the
  // agent read at least one source; DEGRADED when it produced no answer, fell back
  // to the longest-substantive-text path, or grounded nothing — i.e. the cases
  // worth surfacing as knowledge-base gaps. Query text + metadata only; no identity.
  const degraded = modelFailed || !reply || fallbackFired || sourcesRead.length === 0;
  observe(env, ctx, {
    ts: Date.now(),
    query: String(history[history.length - 1].content || "").slice(0, 2000),
    mode: body.mode || "standard",
    tools: toolCalls,
    sourcesRead: sourcesRead.length,
    actions: actions.length,
    turns: turnsUsed,
    replyChars: answered.length,
    grounded: !degraded,
    degraded,
    partial: modelFailed,
  });

  // `partial` is present ONLY when the model failed mid-loop, so the default
  // response shape is unchanged for existing clients.
  const payload = { reply: answered, actions, sources };
  if (modelFailed) payload.partial = true;
  return json(payload);
}

// --- Editor agent write path (#38) -----------------------------------------
// All of this is reachable ONLY through /api/edit, which is mounted ONLY when
// AUTHORING is on. Every commit is human-confirmed: the agent/form/JSON surfaces
// stage a draft, the worker returns a diff, and a commit happens only on an
// explicit { action: "commit" } call carrying the base SHA (optimistic
// concurrency). No auto-commit anywhere. The GitHub token + repo come from env
// and are undefined by default, so the commit path is unreachable to build/test.

// Resolve a record's identity within an artifact collection: the first present
// field of id, title, term, name, question, text, product (app/editor.js
// recordId uses the same order). A record with none of them matches nothing.
// Returns the matching index or -1.
const RECORD_ID_FIELDS = ["id", "title", "term", "name", "question", "text", "product"];
function recordIdentity(r) {
  const field = RECORD_ID_FIELDS.find((k) => r && r[k] != null && r[k] !== "");
  return field ? String(r[field]) : null;
}
function findRecordIndex(records, id) {
  const key = String(id);
  for (let i = 0; i < records.length; i++) {
    if (recordIdentity(records[i]) === key) return i;
  }
  return -1;
}

// Apply ONE typed edit op to an in-memory artifact document and return the
// changed document. Pure + schema-shape-agnostic (the collection key comes from
// the derived editable artifacts). Marks created/changed records derived:true (#38
// provenance); checkArtifact drops the mark where the artifact schema forbids it.
// NEVER touches more than one record. Throws on unknown type / missing record so
// the caller can reject before any commit.
function applyEditOp(doc, op, artifacts) {
  const spec = artifacts[op.type];
  if (!spec) throw new Error(`unknown artifact type: ${op.type}`);
  const out = JSON.parse(JSON.stringify(doc || {}));
  const records = Array.isArray(out[spec.collection]) ? out[spec.collection] : [];
  out[spec.collection] = records;

  if (op.op === "add_record") {
    const rec = Object.assign({}, op.data, { derived: true });
    records.push(rec);
  } else if (op.op === "update_record" || op.op === "set_status") {
    const idx = findRecordIndex(records, op.id);
    if (idx < 0) throw new Error(`record not found: ${op.type}/${op.id}`);
    const patch = op.op === "set_status" ? { status: op.status } : (op.fields || {});
    const rec = Object.assign({}, records[idx], patch, { derived: true });
    // update_record may clear optional fields; the schema check refuses a
    // cleared required one.
    if (op.op === "update_record" && Array.isArray(op.unset)) {
      for (const k of op.unset) if (k !== "derived") delete rec[String(k)];
    }
    records[idx] = rec;
  } else {
    throw new Error(`unknown op: ${op.op}`);
  }
  if (typeof out.count === "number") out.count = records.length;
  return out;
}

// GitHub Contents API client (bot token). Read current file (path + base SHA),
// then commit a new content blob against that SHA — optimistic concurrency. In
// `pr` editorial mode the commit lands on a working branch and a PR is opened
// instead of writing the target branch directly. Token from env.GITHUB_TOKEN.
function ghHeaders(env) {
  return {
    authorization: `Bearer ${env.GITHUB_TOKEN}`,
    accept: "application/vnd.github+json",
    "user-agent": "conflict-portal-editor",
    "x-github-api-version": "2022-11-28",
  };
}

async function ghGetFile(env, repo, path, ref) {
  const u = `https://api.github.com/repos/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`;
  const resp = await fetch(u, { headers: ghHeaders(env) });
  if (!resp.ok) throw new Error(`GitHub GET ${path} failed (${resp.status})`);
  const data = await resp.json();
  // content is base64; decode to text.
  const text = data.content ? decodeBase64(data.content.replace(/\n/g, "")) : "";
  return { sha: data.sha, text };
}

async function ghPutFile(env, repo, path, text, message, branch, baseSha) {
  const author = {
    name: AUTHORING_CFG.bot && AUTHORING_CFG.bot.name ? AUTHORING_CFG.bot.name : undefined,
    email: AUTHORING_CFG.bot && AUTHORING_CFG.bot.email ? AUTHORING_CFG.bot.email : undefined,
  };
  const payload = {
    message,
    content: encodeBase64(text),
    branch,
    sha: baseSha,
  };
  if (author.name && author.email) {
    payload.author = author;
    payload.committer = author;
  }
  if ([text, message, author.name, author.email].some((v) => carriesCredential(env, v))) {
    throw Object.assign(new Error("refused: a credential would enter the record or its attribution"), { status: 422 });
  }
  const u = `https://api.github.com/repos/${repo}/contents/${path}`;
  const resp = await fetch(u, {
    method: "PUT",
    headers: ghHeaders(env),
    body: JSON.stringify(payload),
  });
  if (resp.status === 409) throw new Error("conflict: the record changed upstream — reload and retry");
  if (!resp.ok) throw new Error(`GitHub PUT ${path} failed (${resp.status})`);
  return await resp.json();
}

// `pr` editorial mode: a confirmed commit lands on a fresh working branch cut
// from the target branch, and a pull request opens for review. The base SHA
// check still applies on the working branch, so a record that changed since the
// preview is a 409 (and the unused branch is deleted), never a clobber.
async function ghApi(env, repo, method, path, body) {
  const resp = await fetch(`https://api.github.com/repos/${repo}${path}`, {
    method,
    headers: ghHeaders(env),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`GitHub ${method} ${path} failed (${resp.status})`);
  return resp.status === 204 ? null : await resp.json();
}
async function ghCreateBranch(env, repo, name, from) {
  const ref = await ghApi(env, repo, "GET", `/git/ref/heads/${from}`);
  await ghApi(env, repo, "POST", "/git/refs", { ref: `refs/heads/${name}`, sha: ref.object.sha });
}

// base64 helpers (Workers runtime has atob/btoa over Latin-1; round-trip UTF-8).
function encodeBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function decodeBase64(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

// The optional editor access gate (features.authoring_access_gate). When on,
// /api/edit serves only if the request carries the configured editor role/claim
// (X-Editor-Role, or the Cf-Access-* identity headers Access injects). Off by
// default: the editor agent only exists inside the gated authoring UI, so this is
// defense-in-depth for shared-perimeter deployments.
function editorAccessOk(request) {
  if (!AUTHORING_ACCESS_GATE) return true;
  if (!AUTHORING_EDITOR_ROLE) return false; // gate on, but no role configured -> deny
  const role =
    request.headers.get("x-editor-role") ||
    request.headers.get("cf-access-authenticated-user-groups") ||
    "";
  return role.split(/[,\s]+/).map((s) => s.trim()).includes(AUTHORING_EDITOR_ROLE);
}

// Re-validate one committed file on the server. The commit's `after` comes from
// the client, so it is checked against the exact base blob it claims to update
// (the PUT's base-SHA check then ties that blob to the current file): it must
// pass the artifact schema, and differ from the base only the way typed ops can
// (records updated in place or appended; nothing removed; no other top-level key
// changed except the record count). Returns the normalized bytes to commit.
async function checkCommitFile(env, repo, spec, f) {
  if (!/^[\w-]{1,64}$/.test(String(f.baseSha))) {
    throw Object.assign(new Error(`invalid base SHA for ${f.path}`), { status: 422 });
  }
  const blob = await ghApi(env, repo, "GET", `/git/blobs/${encodeURIComponent(f.baseSha)}`);
  let before, after;
  try {
    before = JSON.parse(blob.content ? decodeBase64(String(blob.content).replace(/\n/g, "")) : "{}");
    after = JSON.parse(String(f.after));
  } catch {
    throw Object.assign(new Error(`schema invalid: ${f.path}: not JSON`), { status: 422 });
  }
  const refuse = (why) => Object.assign(new Error(`not a record edit: ${f.path}: ${why}`), { status: 422 });
  if (!after || typeof after !== "object" || Array.isArray(after)) throw refuse("not an object");
  const base = Array.isArray(before[spec.collection]) ? before[spec.collection] : [];
  const records = after[spec.collection];
  if (!Array.isArray(records)) throw refuse(`no ${spec.collection} collection`);
  if (records.length < base.length) throw refuse("a record was removed");
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const k of keys) {
    if (k === spec.collection) continue;
    const expected = k === "count" && typeof before.count === "number" ? records.length : before[k];
    if (JSON.stringify(after[k]) !== JSON.stringify(expected)) throw refuse(`top-level key ${k} changed`);
  }
  const { checkArtifact } = await import("./policy-authoring.js");
  try {
    await checkArtifact(env, spec, before, after);
  } catch (err) {
    throw Object.assign(new Error(`schema invalid: ${f.path}: ${err.message || err}`), { status: 422 });
  }
  return JSON.stringify(after, null, 2) + "\n";
}

// Build a draft change set from a list of typed ops (from the agent or a form/JSON
// surface), grouped per source file. Validates each op applies cleanly and returns
// { files: [{path, before, after, baseSha}] } for the diff/preview — NO commit.
async function buildDraft(env, repo, ref, ops, artifacts) {
  const byPath = new Map();
  for (const op of ops) {
    const spec = artifacts[op.type];
    if (!spec) throw new Error(`unknown artifact type: ${op.type}`);
    let entry = byPath.get(spec.path);
    if (!entry) {
      const file = repo ? await ghGetFile(env, repo, spec.path, ref) : { sha: null, text: "{}" };
      let doc;
      try { doc = JSON.parse(file.text || "{}"); } catch { doc = {}; }
      entry = { spec, path: spec.path, before: file.text, baseSha: file.sha, original: doc, doc };
      byPath.set(spec.path, entry);
    }
    entry.doc = applyEditOp(entry.doc, op, artifacts);
  }
  // Every surface (form, JSON, conversation) lands here, so every draft is
  // schema-validated the same way the governed writer validates its proposals.
  const { checkArtifact } = await import("./policy-authoring.js");
  const files = [];
  for (const entry of byPath.values()) {
    try {
      await checkArtifact(env, entry.spec, entry.original, entry.doc);
    } catch (err) {
      throw new Error(`schema invalid: ${entry.path}: ${err.message || err}`);
    }
    const after = JSON.stringify(entry.doc, null, 2) + "\n";
    files.push({ path: entry.path, before: entry.before, after, baseSha: entry.baseSha });
  }
  return { files };
}

// Editor agent endpoint. Three request shapes, all behind AUTHORING:
//   { action: "draft",  messages | ops }  -> stage a change, return a diff (no commit)
//   { action: "commit", files }           -> human-confirmed commit via GitHub API
//   { action: "buffer", text, command, selection } -> WYSIWYG edit-agent: rewrite/
//        expand/summarize a buffer selection, return markdown deltas, NEVER commits
async function handleEdit(request, env, ctx, gate = ACCESS) {
  if (!editorAccessOk(request)) return json({ error: "editor role required" }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const action = body.action || "draft";
  const repo = authoringRepo(env);

  // A store authority is written only by its own governed writer (the knowledge
  // operations service: proposal.propose / review / commit) and reaches readers
  // through its declared projections (committed | live). The Worker never writes
  // an authority and never edits a projection of one; it names the writer instead.
  if (Object.hasOwn(config.brain || {}, "authority") && action !== "buffer") {
    const authority = config.brain.authority || {};
    return json({
      error: "record authority adopted; propose changes through its governed writer, not by editing compiled JSON",
      writer: "knowledge-operations",
      projections: authority.projections || null,
    }, 409);
  }

  // A signed proposal token was checked when its draft was; its encoded bytes are
  // not author input.
  if (action !== "buffer" && carriesCredential(env, JSON.stringify({ ...body, proposalToken: undefined }))) {
    return json({ error: "refused: a credential would enter the record or its attribution" }, 422);
  }

  const artifacts = await editableArtifacts(env);

  if (Object.hasOwn(AUTHORING_CFG, "governance") && action !== "buffer") {
    const {governedEdit} = await import("./policy-authoring.js");
    return governedEdit(request, env, body, config, {
      actor: accessEmail, repo: authoringRepo, branch: AUTHORING_BRANCH, artifacts,
      canRead: (path, actor) => gate.canRead(path, actor), get: ghGetFile, put: ghPutFile,
      apply: (doc, op) => applyEditOp(doc, op, artifacts), json,
      agentDraft: AUTHORING_AGENT && modelAvailable(env) ? (input) => draftOpsFromAgent(env, input, artifacts) : null,
    });
  }

  // The files cell has one writer: commit the source JSON (json-commit). Any other
  // storage_mode is refused rather than silently accepted.
  if (AUTHORING_STORAGE !== "json-commit" && action !== "buffer") {
    return json({ error: `storage_mode ${AUTHORING_STORAGE} has no writer; use json-commit or a declared authority` }, 409);
  }

  // Buffer / WYSIWYG edit-agent: operates on the current selection only, returns
  // markdown deltas into the editor buffer, NEVER commits. Gated separately.
  if (action === "buffer") {
    if (!AUTHORING_WYSIWYG_AGENT) return json({ error: "buffer edit-agent not enabled" }, 404);
    if (!modelAvailable(env)) return json({ error: "edit-agent unavailable" }, 503);
    const client = modelClientFactory(env);
    const command = String(body.command || "rewrite");
    const selection = String(body.selection || body.text || "").slice(0, 32000);
    const stream = client.messages.stream({
      model: MODEL,
      max_tokens: 4000,
      system: [{ type: "text", text: editorSystem(artifacts) }],
      messages: [
        {
          role: "user",
          content: `Apply the edit command "${command}" to the following markdown selection and return ONLY the rewritten markdown (no preamble, no fences). Honor the content conventions (no emojis, plain professional prose).\n\n---\n${selection}`,
        },
      ],
    });
    const resp = await stream.finalMessage();
    const out = (resp.content || []).filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
    return json({ markdown: out, committed: false });
  }

  // Commit: human-confirmed write of a previously previewed draft. Optimistic
  // concurrency via the per-file base SHA. No commit reachable without a token.
  if (action === "commit") {
    if (!repo || !env.GITHUB_TOKEN) return json({ error: "commit unavailable: no repo/token configured" }, 503);
    const files = Array.isArray(body.files) ? body.files : [];
    if (!files.length) return json({ error: "no files to commit" }, 400);
    // Enforce the "never raw file writes" design HERE, not just in how a draft
    // happens to be built: a commit reaches this action from the client's own
    // `files` array, so nothing upstream guarantees it came from applyEditOp.
    // Writes are constrained to the known editable artifacts, and every write
    // must carry a base SHA so it is an UPDATE to an existing record, never a
    // blind create — without this a caller could commit any path, e.g. a
    // .github/workflows/*.yml, and escalate through Actions to repo/org secrets.
    const allowedPaths = new Set(Object.values(artifacts).map((a) => a.path));
    const clean = [];
    for (const f of files) {
      const p = String(f.path || "").replace(/^\/+/, "");
      if (p.includes("..") || !allowedPaths.has(p)) {
        return json({ error: `path not editable: ${p || "(empty)"}` }, 422);
      }
      if (!f.baseSha) {
        return json({ error: `base SHA required for ${p} (a commit updates an existing record, never creates)` }, 409);
      }
      clean.push({ path: p, after: f.after, baseSha: f.baseSha });
    }
    // Validate every file before any write (and before a PR-mode branch exists).
    const specs = new Map(Object.values(artifacts).map((a) => [a.path, a]));
    try {
      for (const f of clean) f.after = await checkCommitFile(env, repo, specs.get(f.path), f);
    } catch (err) {
      return json({ error: String(err.message || err) }, err.status || 409);
    }
    const message = String(body.message || "portal: update records").slice(0, 200);
    const pr = AUTHORING_EDITORIAL === "pr";
    const target = pr ? `portal-edit/${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}` : AUTHORING_BRANCH;
    const results = [];
    let pullRequest = null;
    try {
      if (pr) await ghCreateBranch(env, repo, target, AUTHORING_BRANCH);
      for (const f of clean) {
        const r = await ghPutFile(env, repo, f.path, f.after, message, target, f.baseSha);
        results.push({ path: f.path, commit: r.commit && r.commit.sha });
      }
      if (pr) {
        const opened = await ghApi(env, repo, "POST", "/pulls", {
          title: message.split("\n")[0], head: target, base: AUTHORING_BRANCH,
          body: "Opened by the portal editor after an operator confirmed the previewed change.",
        });
        pullRequest = { number: opened.number, url: opened.html_url };
      }
    } catch (err) {
      // No pull request opened, so the working branch (empty, or holding only
      // part of the change) serves nothing: remove it.
      if (pr) {
        await ghApi(env, repo, "DELETE", `/git/refs/heads/${target}`).catch(() => {});
      }
      return json({ error: String(err.message || err) }, err.status || 409);
    }
    return json({ committed: true, editorial: AUTHORING_EDITORIAL, branch: target, pullRequest, files: results });
  }

  // Draft: from explicit typed ops (form/JSON surfaces) or from a conversational
  // instruction (agent surface, gated by authoring_agent). Returns a diff to
  // preview; commits nothing.
  let ops = Array.isArray(body.ops) ? body.ops : null;
  if (!ops) {
    if (!AUTHORING_AGENT) return json({ error: "conversational edit not enabled" }, 404);
    if (!modelAvailable(env)) return json({ error: "edit-agent unavailable" }, 503);
    ops = await draftOpsFromAgent(env, body, artifacts);
    if (!ops.length) return json({ error: "the editor agent produced no change" }, 422);
  }
  let draft;
  try {
    draft = await buildDraft(env, repo, AUTHORING_BRANCH, ops, artifacts);
  } catch (err) {
    return json({ error: String(err.message || err) }, 422);
  }
  // No auto-commit: always return the diff for explicit operator confirmation.
  return json({ committed: false, ops, ...draft });
}

// Run the editor agent over a natural-language instruction, returning the typed
// ops it staged (update_record / add_record / set_status). It has EDIT_TOOLS only
// — never the read TOOLS — and never commits; the worker collects its tool calls
// as the draft ops. Gated by AUTHORING_AGENT.
async function draftOpsFromAgent(env, body, artifacts) {
  const client = modelClientFactory(env);
  const history = Array.isArray(body.messages) ? body.messages.slice(-20) : [];
  const messages = history.map((m) => ({
    role: m.role === "assistant" ? "assistant" : "user",
    content: String(m.content).slice(0, 32000),
  }));
  if (!messages.length && body.instruction) {
    messages.push({ role: "user", content: String(body.instruction).slice(0, 32000) });
  }
  const ops = [];
  for (let turn = 0; turn < MAX_AGENT_TURNS; turn++) {
    const stream = client.messages.stream({
      model: MODEL,
      max_tokens: 8000,
      system: [{ type: "text", text: editorSystem(artifacts) }],
      tools: editTools(artifacts),
      messages,
    });
    const resp = await stream.finalMessage();
    if (resp.stop_reason !== "tool_use") break;
    messages.push({ role: "assistant", content: resp.content });
    const results = [];
    for (const block of resp.content) {
      if (block.type !== "tool_use") continue;
      const inp = block.input || {};
      ops.push({ op: block.name, type: inp.type, id: inp.id, fields: inp.fields, unset: inp.unset, data: inp.data, status: inp.status });
      results.push({ type: "tool_result", tool_use_id: block.id, content: "Draft staged for operator review." });
    }
    messages.push({ role: "user", content: results });
  }
  return ops;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// A response whose body depends on WHO asked (#53). It must never be stored by a
// shared cache and must vary on the Access identity, or one user's filtered copy
// could be handed to another.
function privateJson(obj) {
  return new Response(JSON.stringify(obj), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "private, no-store",
      vary: "Cf-Access-Authenticated-User-Email",
    },
  });
}

// 404, not 403: the response must not confirm that the document exists.
function accessNotFound() {
  return new Response("Not found", {
    status: 404,
    headers: { "content-type": "text/plain", "cache-control": "private, no-store" },
  });
}

// Identity-aware static serving (#53). Returns a Response when this request is
// one the access gate must answer itself, or null to fall through to the normal
// asset path. Reached ONLY when client.config.json carries an `access` block —
// with no such block the caller never invokes it.
async function serveScoped(request, env, url, gate = ACCESS) {
  const clean = normalizePath(url.pathname);
  const email = accessEmail(request);

  // The SPA fetches its own config for branding/pages/assistant. The access
  // rules — the owner list and the restricted paths — are server-only and must
  // never ship to a browser, and nav entries deep-linking a restricted document
  // are dropped for the users who may not read it.
  if (clean === "client.config.json") {
    const r = await env.ASSETS.fetch(request);
    if (!r || !r.ok) return r || null;
    let cfg;
    try {
      cfg = await r.json();
    } catch {
      return accessNotFound(); // unreadable config -> serve nothing rather than raw bytes
    }
    return privateJson(gate.filterConfig(cfg, email));
  }

  // A tool-only policy must not rewrite otherwise unrestricted asset envelopes.
  if (!gate.enabled || gate.pathsEnabled === false) return null;

  // Compiled artifacts are SERVED, and several carry document paths well beyond
  // their obvious list: the knowledge pack's items PLUS its #49 link graph
  // (backlinks / wikilinks / dangling), and the brain's nodes (source, data.path)
  // PLUS its `references` edges (#60 slice 1). Each is filtered per requesting
  // user — rather than 404'd wholesale — so a scoped reader still gets a working
  // portal built only from what they may see. The filter table lives in
  // access.js; adding an artifact there is one line, not another copy of this.
  // An artifact the operator explicitly RESTRICTED is withheld, not quietly
  // downgraded to a filtered copy: an explicit deny must never be
  // reinterpreted as a redaction. Only artifacts the rules leave readable
  // reach the per-user filter below.
  if (!gate.canRead(clean, email)) return accessNotFound();

  if (clean === "app/brain-meta.json" || clean === "app/brain-manifest.json") {
    const response = await env.ASSETS.fetch(request);
    if (!response || !response.ok) return response || accessNotFound();
    if (gate.isOwner(email) && !gate.nodeAllowed) {
      try { return privateJson(await response.json()); } catch { return accessNotFound(); }
    }
    if (!gate.canRead("app/brain.json", email)) return accessNotFound();
    const graphResponse = await env.ASSETS.fetch("https://portal/app/brain.json");
    if (!graphResponse?.ok) return accessNotFound();
    let graph;
    try { graph = await graphResponse.json(); } catch { return accessNotFound(); }
    if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) return accessNotFound();
    if (clean === "app/brain-manifest.json") {
      if (!gate.canRead("brain-schema.json", email)) return accessNotFound();
      const schemaResponse = await env.ASSETS.fetch("https://portal/brain-schema.json");
      if (!schemaResponse?.ok) return accessNotFound();
      let manifest, schema;
      try { manifest = await response.json(); schema = await schemaResponse.json(); }
      catch { return accessNotFound(); }
      const visible = gate.filterBrainManifest(manifest, graph, schema, email);
      return visible ? privateJson(visible) : accessNotFound();
    }
    return privateJson(gate.filterBrainMeta(graph, email));
  }

  if (gate.hasArtifactFilter(clean)) {
    const r = await env.ASSETS.fetch(request);
    if (!r || !r.ok) return r || null;
    let data;
    try {
      data = await r.json();
    } catch {
      return accessNotFound(); // cannot scope what cannot be parsed -> withhold it
    }
    return privateJson(gate.filterArtifact(clean, data, email));
  }

  // Every OTHER served JSON artifact. The filter table understands declared shapes; the
  // portal ships around forty, and a decision/session/deliverable row sourced
  // from a restricted document used to be served in full to everyone while the
  // brain filter dropped the very same node. Unfiltered artifacts now fail
  // CLOSED: if the body mentions a path this reader may not read, they get a
  // 404 instead. A reader allowed to see everything it mentions gets the
  // original response object untouched, so an unscoped portal is unaffected.
  if (clean.endsWith(".json")) {
    const r = await env.ASSETS.fetch(request);
    if (!r || !r.ok) return r || null;
    let data;
    try {
      data = await r.clone().json();
    } catch {
      return r; // not JSON after all (or unparseable) — nothing to scope
    }
    return gate.artifactSafeFor(clean, data, email) ? r : accessNotFound();
  }

  // A raw document fetched by path. On an Access-gated host every authenticated
  // user can otherwise GET any asset, so this is the structural gate that makes
  // the chat/read_doc scoping mean anything.
  // A raw asset fetched by path. The boundary is what the RULES say, not the
  // file suffix: scoping only DOC_EXT left restricted .csv/.pdf/.sql/.yaml
  // and everything under a restricted directory readable by any
  // authenticated user. (DOC_EXT still governs read_doc, where limiting to
  // renderable text is the right rule.) The canRead check above now covers
  // every path, so nothing extension-shaped is left to do here.


  return null;
}

// Explicit trusted instance composition; no config-driven module discovery.
export function createWorker({ access: configured = ACCESS, routes = {} } = {}) {
  const handlers = new Map(Object.entries(routes));
  for (const [path, handler] of handlers) {
    if (!/^\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*$/.test(path) ||
        path === "/api" || path.startsWith("/api/") || typeof handler !== "function") {
      throw new TypeError("Extension routes must be explicit paths outside /api");
    }
  }
  return {
  async canRead(request, env) {
    const access = await withPrincipals(env, configured);
    return access.canRead(new URL(request.url).pathname, accessEmail(request));
  },
  async fetch(request, env, ctx) {
    const access = await withPrincipals(env, configured);
    const url = new URL(request.url);
    const extension = handlers.get(url.pathname);
    if (extension) {
      const email = accessEmail(request);
      if (!access.canRead(url.pathname, email)) return accessNotFound();
      // Identity is bound to this request, never supplied in tool arguments.
      const reads = Object.freeze({
        allows: (name) => access.toolAllowed(name, email),
        call: async (name, input = {}) => {
          if (!TOOLS.some((tool) => tool.name === name)) return "Error: unknown read tool";
          const result = await runToolCall(env, await loadPack(env), {name, input}, email, access);
          return result.text;
        },
      });
      try {
        const response = await extension(request, env, ctx, reads);
        if (!(response instanceof Response)) throw new TypeError("Extension did not return a Response");
        const headers = new Headers(response.headers);
        headers.set("cache-control", "private, no-store");
        const vary = new Set((headers.get("vary") || "").split(",").map(value => value.trim()).filter(Boolean));
        vary.add("Cf-Access-Authenticated-User-Email");
        headers.set("vary", [...vary].join(", "));
        return new Response(response.body, {status: response.status, statusText: response.statusText, headers});
      }
      catch { return new Response('Extension request failed', {status: 500, headers:{"cache-control":"private, no-store"}}); }
    }

    // Presentation preference scope only. Identity comes from the same trusted
    // Access ingress as reads/writes; the opaque key is never an access grant.
    if (url.pathname === "/api/view-preference-scope") {
      if (request.method !== "GET") return new Response("GET only", {status: 405, headers: {"cache-control": "private, no-store"}});
      const email = accessEmail(request);
      return privateJson({scope: email ? await sha256Hex(url.origin + "\n" + email) : null});
    }

    if (url.pathname === "/api/chat") {
      if (request.method !== "POST") return json({ error: "POST only" }, 405);
      try {
        return await handleChat(request, env, ctx, access);
      } catch (err) {
        return json({ error: `agent error: ${err.message || err}` }, 500);
      }
    }

    // Editor agent (#38) — mounted ONLY when features.authoring is on. Default
    // off: the route is unregistered, so /api/edit 404s and the portal is
    // read-only. The write tools live here, never on the read agent above.
    if (AUTHORING && url.pathname === "/api/edit") {
      if (request.method !== "POST") return json({ error: "POST only" }, 405);
      try {
        return await handleEdit(request, env, ctx, access);
      } catch (err) {
        return json({ error: `editor error: ${err.message || err}` }, 500);
      }
    }

    // Identity-aware read scoping (#53). Skipped entirely when client.config.json
    // has no `access` block, so an unscoped portal serves exactly the bytes it
    // always did, with the same headers and no extra work.
    if (access.present) {
      const scoped = await serveScoped(request, env, url, access);
      if (scoped) return scoped;
    }

    const resp = await env.ASSETS.fetch(request);
    const ct = resp.headers.get("content-type") || "";
    if (!ct.includes("text/html")) return resp;

    // No-flash theming: when the kb_prefs cookie names a theme, stamp it onto
    // <html data-theme> before paint. With no cookie (first visit), inject a
    // tiny inline <head> script that resolves prefers-color-scheme synchronously
    // so OS-preference users also avoid the flash. Either way data-theme is set
    // before the body renders; theme.js/bubble.js take over once they load.
    const cookieTheme = themeFromCookie(request);

    return new HTMLRewriter()
      .on("html", {
        element(el) {
          if (cookieTheme) el.setAttribute("data-theme", cookieTheme);
        },
      })
      .on("head", {
        element(el) {
          if (!cookieTheme) {
            el.prepend(`<script>${NOFLASH_SCRIPT}</script>`, { html: true });
          }
        },
      })
      // Cache-bust every page-authored /app js/css reference at serve time, so
      // the ?v= token never has to be baked into the HTML sources.
      .on('script[src^="/app/"]', {
        element(el) {
          const s = el.getAttribute("src");
          if (s) el.setAttribute("src", withV(s));
        },
      })
      .on('link[href^="/app/"]', {
        element(el) {
          const h = el.getAttribute("href");
          if (h) el.setAttribute("href", withV(h));
        },
      })
      .on("body", {
        element(el) {
          el.append(`<script src="${withV("/app/bubble.js")}" defer></script>`, { html: true });
          // Authoring UI (#38) — injected ONLY when features.authoring is on, the
          // same way bubble.js is. Default off => not injected => the page is
          // byte-identical and the portal stays read-only. Injected (never
          // statically referenced) so the portal-link check has nothing to resolve.
          if (AUTHORING) {
            el.append(`<script src="/app/editor.js" defer></script>`, { html: true });
          }
        },
      })
      .transform(resp);
  },
  };
}

export default createWorker();
