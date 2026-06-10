/**
 * BrainSpark — Exact Math Engine with provider fallback
 * ------------------------------------------------------------------
 * Claude → OpenAI → Groq, EACH with the SymPy compute tool, so math
 * stays exact no matter which provider answers. All three call the
 * same math service; only the tool-calling protocol differs per vendor.
 *
 * Setup unchanged:
 *   MATH_SERVICE_URL=http://127.0.0.1:7001/compute
 * Call site (in server.js):
 *   const r = await callAIWithMath({ anthropic, openai, groq }, { messages, system, maxTokens });
 */
 
const MATH_SERVICE_URL = process.env.MATH_SERVICE_URL || 'http://127.0.0.1:7001/compute';
 
// ── Tool schema, in BOTH vendor shapes (same parameters) ─────────────
const MATH_PARAMS = {
  type: 'object',
  properties: {
    action:    { type: 'string', enum: ['evaluate','solve','solve_system','diff','integrate','simplify','factor','expand','limit','verify'], description: 'The operation to perform.' },
    expr:      { type: 'string', description: 'Expression or equation, e.g. "3x^2-7x-6=0" or "x^2 sin(x)".' },
    variable:  { type: 'string', description: 'Variable to act on (default "x").' },
    equations: { type: 'array', items: { type: 'string' }, description: 'For solve_system: list of equations.' },
    variables: { type: 'array', items: { type: 'string' }, description: 'For solve_system: list of variables.' },
    lower:     { type: 'string', description: 'For integrate: lower limit.' },
    upper:     { type: 'string', description: 'For integrate: upper limit.' },
    to:        { type: 'string', description: 'For limit: point the variable approaches.' },
    value:     { type: 'string', description: 'For verify: proposed answer to check.' },
  },
  required: ['action'],
};
const TOOL_DESC =
  'Perform EXACT mathematics with a symbolic engine (SymPy). ALWAYS use this for ANY calculation — ' +
  'arithmetic, solving, derivatives, integrals, simplification, factoring, limits, or verifying an answer. ' +
  'Never compute yourself; call this and use its exact result.';
 
const MATH_TOOL_ANTHROPIC = { name: 'compute', description: TOOL_DESC, input_schema: MATH_PARAMS };
const MATH_TOOL_OPENAI    = { type: 'function', function: { name: 'compute', description: TOOL_DESC, parameters: MATH_PARAMS } };
 
const MATH_SYSTEM_RULE =
  '\n\nCRITICAL: You may NOT do arithmetic or algebra in your head. For EVERY calculation, equation, ' +
  'derivative, integral, or numeric answer you MUST call the `compute` tool and use its exact result. ' +
  'Before giving a final numeric/algebraic answer, confirm it with `compute` (action "verify" when applicable). ' +
  'If `compute` returns an error, fix the expression and call again — never guess.';
 
// ── Call the SymPy service ───────────────────────────────────────────
async function runMathTool(input) {
  try {
    const r = await fetch(MATH_SERVICE_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input || {}), signal: AbortSignal.timeout(10000),
    });
    return await r.json();
  } catch (e) {
    return { ok: false, error: 'math service unavailable: ' + e.message };
  }
}
 
// ── Provider loop 1: Anthropic (tool_use / tool_result) ──────────────
async function runAnthropic(anthropic, { messages, system = '', maxTokens = 4000, model = 'claude-opus-4-8' }) {
  const tools = [MATH_TOOL_ANTHROPIC];
  const sys = (system || '') + MATH_SYSTEM_RULE;
  const convo = messages.map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));
  let calls = 0;
  let resp = await anthropic.messages.create({ model, max_tokens: Math.min(maxTokens, 8096), system: sys, tools, messages: convo });
  while (resp.stop_reason === 'tool_use' && calls < 25) {
    const results = [];
    for (const block of resp.content) {
      if (block.type === 'tool_use' && block.name === 'compute') {
        calls++;
        const out = await runMathTool(block.input);
        results.push({ type: 'tool_result', tool_use_id: block.id, content: JSON.stringify(out) });
      }
    }
    convo.push({ role: 'assistant', content: resp.content });
    convo.push({ role: 'user', content: results });
    resp = await anthropic.messages.create({ model, max_tokens: Math.min(maxTokens, 8096), system: sys, tools, messages: convo });
  }
  const text = resp.content.filter(b => b.type === 'text').map(b => b.text).join('').trim();
  return { text, provider: 'claude', toolCalls: calls };
}
 
// ── Provider loop 2+3: OpenAI-compatible (OpenAI AND Groq) ───────────
async function runOpenAIStyle(client, providerName, { messages, system = '', maxTokens = 4000, model }) {
  const tools = [MATH_TOOL_OPENAI];
  const sys = (system || '') + MATH_SYSTEM_RULE;
  const convo = [{ role: 'system', content: sys }, ...messages.map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }))];
  let calls = 0;
  let resp = await client.chat.completions.create({ model, max_tokens: Math.min(maxTokens, 4096), messages: convo, tools, tool_choice: 'auto' });
  let msg = resp.choices[0].message;
  while (msg.tool_calls?.length && calls < 25) {
    convo.push(msg);
    for (const tc of msg.tool_calls) {
      calls++;
      let args = {};
      try { args = JSON.parse(tc.function.arguments || '{}'); } catch {}
      const out = await runMathTool(args);
      convo.push({ role: 'tool', tool_call_id: tc.id, content: JSON.stringify(out) });
    }
    resp = await client.chat.completions.create({ model, max_tokens: Math.min(maxTokens, 4096), messages: convo, tools, tool_choice: 'auto' });
    msg = resp.choices[0].message;
  }
  return { text: (msg.content || '').trim(), provider: providerName, toolCalls: calls };
}
 
// ── Orchestrator: same fallback chain as callAI, but math-aware ──────
async function callAIWithMath(clients, opts = {}) {
  const { anthropic, openai, groq } = clients || {};
  const chain = [
    anthropic && (() => runAnthropic(anthropic, { ...opts, model: opts.model || 'claude-opus-4-8' })),
    openai    && (() => runOpenAIStyle(openai, 'openai', { ...opts, model: opts.openaiModel || 'gpt-4o-mini' })),
    groq      && (() => runOpenAIStyle(groq,   'groq',   { ...opts, model: opts.groqModel   || 'llama-3.3-70b-versatile' })),
  ].filter(Boolean);
 
  let lastErr;
  for (const attempt of chain) {
    try { return await attempt(); }
    catch (e) { lastErr = e; console.warn('[math fallback]', e.message?.slice(0, 100)); }
  }
  throw new Error('All AI providers failed for math: ' + (lastErr?.message || 'unknown'));
}
 
// ── Verify a generated answer key (quiz / paper) ─────────────────────
async function verifyAnswerKey(items) {
  return Promise.all((items || []).map(async (item) => {
    if (!item.equation || item.answer === undefined) return { ...item, verified: null };
    const out = await runMathTool({ action: 'verify', expr: item.equation, value: String(item.answer), variable: item.variable || 'x' });
    return { ...item, verified: out.ok ? out.satisfies : null, residual: out.residual };
  }));
}
 
module.exports = { runMathTool, callAIWithMath, verifyAnswerKey, MATH_TOOL_ANTHROPIC, MATH_TOOL_OPENAI, MATH_SYSTEM_RULE };
 