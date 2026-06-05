import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { requirePermission } from '../../rbac/guard.js';
import { clearanceForRole } from '../../rbac/roles.js';
import type { LlmProvider } from '../../ai/providers/provider.interface.js';
import type { AppDatabase } from '../../db/client.js';
import { recordMetering } from '../../admin/metering.js';
import type { Role } from '../../db/schema/index.js';
import '../aiResponseEnvelope.js';

const bodySchema = z.object({
  message: z.string().min(1).max(8_000),
  providerId: z.string().optional(),
});

export interface CompletionsDeps {
  db: AppDatabase;
  resolveProvider: (id: string) => LlmProvider;
  providerId: string;
  rateLimit?: { max: number; timeWindow: number };
}

/** Cheap heuristic token estimate (≈4 chars/token). */
function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Direct (non-RAG) LLM completion. Server-only provider selection (by id). The
 * response is wrapped in the EU AI Act transparency envelope via reply.aiEnvelope.
 */
export function registerCompletionsRoute(app: FastifyInstance, deps: CompletionsDeps): void {
  const routeOpts = {
    preHandler: requirePermission('ai:invoke'),
    ...(deps.rateLimit ? { config: { rateLimit: deps.rateLimit } } : {}),
  };

  app.post('/api/chat/completions', routeOpts, async (req, reply) => {
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid request' });

    const id = parsed.data.providerId ?? deps.providerId;
    let provider: LlmProvider;
    try {
      provider = deps.resolveProvider(id);
    } catch {
      return reply.code(404).send({ error: 'unknown provider' });
    }

    const result = await provider.chat({ messages: [{ role: 'user', content: parsed.data.message }] });

    // Billing-ready metering on every LLM call.
    const ctx = req.authContext!;
    await recordMetering(
      deps.db,
      { orgId: ctx.orgId, userId: ctx.userId, clearance: clearanceForRole(ctx.role as Role) },
      {
        eventType: 'LLM_CALL', model: result.model, provider: id,
        metadata: { tokensIn: estimateTokens(parsed.data.message), tokensOut: estimateTokens(result.content) },
      },
    );

    return reply.aiEnvelope({ content: result.content, model: result.model }, { model: result.model, provider: id });
  });
}
