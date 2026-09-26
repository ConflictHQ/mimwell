// OpenAI model client for the portal assistant (#438).
//
// worker.js talks to its model through one seam: a client exposing
// `messages.stream(params)` that returns `{ finalMessage(): Promise<Message> }`,
// with Anthropic Messages API shapes on both sides. This adapter keeps that
// contract so the chat loop, the edit-agent and the authoring agent run
// unchanged: it translates the request into an OpenAI Chat Completions call and
// the response back into an Anthropic-shaped message.
//
// Loaded with a dynamic import only when `assistant.provider` is "openai", so a
// brain on the default provider never evaluates it. Uses fetch directly: no SDK
// dependency to pin or bundle.

const DEFAULT_BASE_URL = "https://api.openai.com/v1";

// Anthropic system prompt: a string or a list of text blocks (cache_control and
// other block options have no Chat Completions equivalent and are dropped).
function systemText(system) {
  if (!system) return "";
  if (typeof system === "string") return system;
  return system
    .filter((b) => b && b.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("\n\n");
}

function blockText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return content == null ? "" : String(content);
  return content
    .filter((b) => b && b.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("\n");
}

// Anthropic tools ({name, description, input_schema}) to OpenAI function tools.
export function toOpenAITools(tools) {
  if (!Array.isArray(tools) || !tools.length) return undefined;
  return tools.map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description || "",
      parameters: t.input_schema || { type: "object", properties: {} },
    },
  }));
}

// Anthropic messages to OpenAI chat messages.
//   assistant text + tool_use blocks  -> one assistant message with tool_calls
//   user tool_result blocks           -> one "tool" message per result
//   other user blocks (text)          -> a user message after the tool messages
export function toOpenAIMessages(system, messages) {
  const out = [];
  const sys = systemText(system);
  if (sys) out.push({ role: "system", content: sys });
  for (const m of messages || []) {
    if (typeof m.content === "string") {
      out.push({ role: m.role === "assistant" ? "assistant" : "user", content: m.content });
      continue;
    }
    const blocks = Array.isArray(m.content) ? m.content : [];
    if (m.role === "assistant") {
      const text = blockText(blocks);
      const calls = blocks
        .filter((b) => b && b.type === "tool_use")
        .map((b) => ({
          id: b.id,
          type: "function",
          function: { name: b.name, arguments: JSON.stringify(b.input || {}) },
        }));
      const msg = { role: "assistant", content: text || null };
      if (calls.length) msg.tool_calls = calls;
      out.push(msg);
      continue;
    }
    for (const b of blocks) {
      if (b && b.type === "tool_result") {
        out.push({ role: "tool", tool_call_id: b.tool_use_id, content: blockText(b.content) });
      }
    }
    const text = blockText(blocks.filter((b) => b && b.type !== "tool_result"));
    if (text) out.push({ role: "user", content: text });
  }
  return out;
}

const STOP_REASONS = { tool_calls: "tool_use", function_call: "tool_use", length: "max_tokens" };

// One Chat Completions choice back to an Anthropic-shaped message.
export function fromOpenAIResponse(body) {
  const choice = (body && Array.isArray(body.choices) && body.choices[0]) || {};
  const msg = choice.message || {};
  const content = [];
  if (typeof msg.content === "string" && msg.content) content.push({ type: "text", text: msg.content });
  for (const call of Array.isArray(msg.tool_calls) ? msg.tool_calls : []) {
    if (!call || call.type !== "function" || !call.function) continue;
    let input = {};
    try {
      input = call.function.arguments ? JSON.parse(call.function.arguments) : {};
    } catch {
      input = {};
    }
    content.push({ type: "tool_use", id: call.id, name: call.function.name, input });
  }
  const usage = body && body.usage ? {
    input_tokens: body.usage.prompt_tokens || 0,
    output_tokens: body.usage.completion_tokens || 0,
  } : undefined;
  const stop = content.some((b) => b.type === "tool_use")
    ? "tool_use"
    : STOP_REASONS[choice.finish_reason] || "end_turn";
  return { role: "assistant", content, stop_reason: stop, ...(usage ? { usage } : {}) };
}

// The request body for one call. `thinking` and `output_config` are Anthropic
// options with no portable Chat Completions equivalent; they are not sent.
export function toOpenAIRequest(params) {
  const body = {
    model: params.model,
    messages: toOpenAIMessages(params.system, params.messages),
  };
  if (params.max_tokens) body.max_completion_tokens = params.max_tokens;
  const tools = toOpenAITools(params.tools);
  if (tools) body.tools = tools;
  return body;
}

export function createOpenAIClient({ apiKey, baseUrl, fetchImpl } = {}) {
  const base = String(baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const doFetch = fetchImpl || ((...args) => fetch(...args));
  async function complete(params) {
    const resp = await doFetch(`${base}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(toOpenAIRequest(params)),
    });
    if (!resp.ok) {
      // Report the status and the API's own error message, never the request.
      let detail = "";
      try {
        const err = await resp.json();
        detail = (err && err.error && err.error.message) || "";
      } catch {
        detail = "";
      }
      throw new Error(`OpenAI API error ${resp.status}${detail ? `: ${String(detail).slice(0, 300)}` : ""}`);
    }
    return fromOpenAIResponse(await resp.json());
  }
  return {
    messages: {
      stream(params) {
        return { finalMessage: () => complete(params) };
      },
    },
  };
}
