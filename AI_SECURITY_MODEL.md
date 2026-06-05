# AI Security Model

How Capybara_AI keeps AI/agent features safe. Aligned with the OWASP Top 10 for
LLM Applications 2025 (mapping:
[`docs/security/LLM_TOP_10_MAPPING.md`](./docs/security/LLM_TOP_10_MAPPING.md)).
Everything here is implemented in `src/ai/` and `src/net/ssrfGuard.ts` and
covered by `tests/ai/`.

## Principles

1. **Server is the boundary, not the prompt.** Prompt-level instructions are
   defense in depth; the authoritative controls are server-side allowlists,
   capability scopes, approvals, and the SSRF guard.
2. **Default deny.** No tool runs unless registered; no fs/network/shell access
   unless explicitly scoped; no dangerous action without human approval.
3. **No caller-controlled endpoints.** The model/provider endpoint is server
   configuration only.

## Provider abstraction (`src/ai/providers/`)

- `LlmProvider` is selected by **id** from a server-configured registry
  (`LLM_PROVIDERS`). A `ChatRequest` has **no** endpoint/base_url field; extra
  fields a caller smuggles in are ignored. This closes the
  SSRF-via-`base_url` class of bug (proven in `tests/ai/provider.test.ts`).
- Default target is **local** inference (Ollama/vLLM, OpenAI-compatible). Cloud
  providers can be added behind the same interface (P1) — only then does prompt
  content leave the host.

## Tool sandbox (`src/ai/tools/`)

### Allowlist registry
A tool that is not registered cannot be invoked; lookups of unknown or
non-string names throw (`registry.ts`). `executeTool` returns
`decision: 'denied', reason: 'not_allowlisted'`.

### Capability scopes (default empty)
Each tool declares the scopes it needs; the runtime hands it capabilities that
enforce them:
- **fs** (`scopes/fs.scope.ts`): `none|read|readwrite` + `allowedPaths`. Paths
  are resolved and `realpath`-checked to be inside an allowed root — `..`
  traversal and symlink escape are rejected. Write requires `readwrite`.
- **network** (`scopes/network.scope.ts`): host must be in `allowedHosts` **and**
  pass the SSRF guard (`src/net/ssrfGuard.ts`), which blocks private, loopback,
  link-local, CGNAT, and cloud-metadata (`169.254.169.254`) targets unless the
  scope explicitly opts into private ranges.
- **shell** (`scopes/shell.scope.ts`): **deny by default**. No P0 tool has a
  shell scope. When granted, only exact-match allowlisted executables run, via
  `execFile` with an argv array (never a shell string → no injection).
- **secrets**: only the named secrets a tool lists are injected; tools never see
  `process.env`.

### Timeouts
Every invocation runs under an `AbortController` with the tool's `timeoutMs`; a
tool exceeding it returns `ok:false, error:'timeout'`.

### Human-approval workflow (`approval.ts`)
Tools flagged `dangerous: true` cannot execute inline. `executeTool` returns
`decision: 'pending_approval'` and the handler does **not** run until an
approval exists for the **exact** invocation (tool name + canonical-args hash).
This guarantees **no autonomous destructive actions**. The P0 gate is an
in-memory/DB-backed `ApprovalGate`; P1 adds an authorized approve/deny endpoint
+ notifications. Proven in `tests/ai/sandbox.test.ts`.

### Redaction (`src/ai/redaction/redactor.ts`)
Before content is sent to a model or recorded in an invocation, a conservative
pattern-based redactor masks emails, bearer tokens, API-key shapes, JWTs, and
PEM private-key blocks. Tool-invocation records store **redacted** arguments.

## Prompt-injection defenses (`src/ai/prompt/`)

- `wrapUntrusted(source, content)` wraps any external/tool/retrieved content as
  `role: user` DATA between explicit "UNTRUSTED DATA" markers with
  `trusted: false`; it is never placed in the system role.
- `SYSTEM_SAFETY_POLICY` is prepended to sessions, stating that retrieved
  content is data, tools are allowlisted, and dangerous actions need approval —
  mirroring what the server enforces.
- Because enforcement is server-side, a successful injection still cannot reach
  an un-allowlisted capability or trigger a dangerous action without a human.

## Mapping to LLM Top 10 (2025)

| Risk | Control |
|---|---|
| LLM01 Prompt Injection | Untrusted-context wrapping + server-side allowlist/approval |
| LLM02 Sensitive Info Disclosure | Redaction before model/log; secrets not exposed to tools |
| LLM05 Improper Output Handling | Outputs treated as data; tool outputs scoped/redacted |
| LLM06 Excessive Agency | Default-deny scopes; human approval; no shell by default |
| LLM07 System Prompt Leakage | Policy forbids; secrets never in prompts; redaction |
| LLM08 Vector/Embedding (future) | N/A in P0 (no RAG yet) |
| LLM10 Unbounded Consumption | Per-tool timeouts; HTTP rate limits; request timeouts |

Full mapping with file references:
[`docs/security/LLM_TOP_10_MAPPING.md`](./docs/security/LLM_TOP_10_MAPPING.md).

## Known limitation

In-process tools are **trusted code** constrained by capability scopes — strong
against accidental over-reach and prompt-injection-driven misuse, but not a
kernel sandbox. Executing untrusted/arbitrary code requires process/microVM
isolation, tracked as **P2**. Until then, only register tools you trust.
