import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { requirePermission } from '../../rbac/guard.js';
import type { LlmProvider } from '../../ai/providers/provider.interface.js';
import '../aiResponseEnvelope.js';

const bodySchema = z.object({
  message: z.string().min(1).max(8_000),
  providerId: z.string().optional(),
});

export interface CompletionsDeps {
  resolveProvider: (id: string) => LlmProvider;
  providerId: string;
  rateLimit?: { max: number; timeWindow: number };
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
    return reply.aiEnvelope({ content: result.content, model: result.model }, { model: result.model, provider: id });
  });
}
