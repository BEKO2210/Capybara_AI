# OWASP Top 10 for LLM Applications (2025) — Mapping

How Capybara_AI addresses each risk. Status: ✅ controlled · 🟡 partial ·
➖ not applicable in P0. Evidence cites implementing modules and tests.
Design detail in [`AI_SECURITY_MODEL.md`](../../AI_SECURITY_MODEL.md).

| ID | Risk | Status | Controls & evidence |
|---|---|---|---|
| **LLM01** | Prompt Injection | ✅/🟡 | Untrusted content wrapped as data, not instructions (`src/ai/prompt/untrustedContext.ts`); system safety preamble (`policy.ts`). Authoritative defense is server-side: even a successful injection cannot reach an un-allowlisted tool/capability or run a dangerous action without human approval (`src/ai/tools/`). `tests/ai/sandbox.test.ts` |
| **LLM02** | Sensitive Information Disclosure | ✅ | Pattern-based redaction of emails/tokens/keys/JWT/PEM before model calls and in invocation records (`src/ai/redaction/redactor.ts`); tools never receive `process.env`; only explicitly-scoped secrets injected. `tests/ai/sandbox.test.ts` |
| **LLM03** | Supply Chain | ✅ | Lockfile + `npm ci --ignore-scripts`, `npm audit`, OSV, gitleaks, CycloneDX SBOM. [`SUPPLY_CHAIN_SECURITY.md`](../../SUPPLY_CHAIN_SECURITY.md), `.github/workflows/security.yml` |
| **LLM04** | Data & Model Poisoning | ➖/🟡 | No training/fine-tuning or RAG ingestion in P0. Retrieved content (when added) is already treated as untrusted; provider/model is operator-controlled. |
| **LLM05** | Improper Output Handling | ✅ | Model/tool output is treated as untrusted data, never executed; tool outputs are scoped and redacted; no eval of model output. `src/ai/tools/sandbox.ts` |
| **LLM06** | Excessive Agency | ✅ | Default-deny capability scopes (fs/network/shell), allowlist-only tool registry, per-tool timeouts, and **mandatory human approval for dangerous tools** — no autonomous destructive actions. `src/ai/tools/`, `tests/ai/sandbox.test.ts` |
| **LLM07** | System Prompt Leakage | ✅/🟡 | Safety policy forbids revealing system prompts/secrets; secrets are never placed in prompts; redaction reduces accidental echo. Server controls don't depend on prompt secrecy. `src/ai/prompt/policy.ts` |
| **LLM08** | Vector & Embedding Weaknesses | ➖ | No vector store / embeddings / RAG in P0. Will inherit tenant isolation + untrusted-content handling when added (P1). |
| **LLM09** | Misinformation / Overreliance | 🟡 | Out of band for the platform; mitigated operationally (human approval for consequential actions; outputs are advisory). |
| **LLM10** | Unbounded Consumption | ✅ | Per-tool wall-clock timeouts (`sandbox.ts`); HTTP per-route rate limiting (`src/http/security.ts`); provider request timeout (`LLM_REQUEST_TIMEOUT_MS`). `tests/ai/sandbox.test.ts`, `tests/http/security.test.ts` |

### Cross-cutting: SSRF (server-side request forgery)

The classic LLM-app SSRF (caller supplies the model `base_url`, or a tool fetches
an internal/metadata URL) is closed two ways: provider endpoints are
server-config-only (`src/ai/providers/registry.ts`) and tool egress passes
through `src/net/ssrfGuard.ts`, which blocks private/loopback/link-local/CGNAT
and `169.254.169.254`. `tests/ai/provider.test.ts`, `tests/ai/ssrf.test.ts`.

## Residual / roadmap

- Untrusted/arbitrary **code-execution** tools require process/microVM isolation
  (P2). Until then, register only trusted tools (capability scopes still apply).
- RAG/embedding features (LLM04/LLM08) will need ingestion-time provenance and
  per-tenant index isolation when introduced (P1).
