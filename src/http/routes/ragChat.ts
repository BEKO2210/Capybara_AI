import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { clearanceForRole } from '../../rbac/roles.js';
import { requirePermission } from '../../rbac/guard.js';
import { withTenantContext } from '../../tenancy/scope.js';
import { encryptSecret, deriveTenantKey } from '../../lib/crypto.js';
import { conversations, messages } from '../../db/schema/index.js';
import { searchDocuments, type SearchDeps, type SearchResult } from '../../documents/search.js';
import type { LlmProvider, ChatMessage } from '../../ai/providers/provider.interface.js';
import { ensureInventoryEntry } from '../../compliance/inventory.js';
import { buildAiMeta } from '../aiResponseEnvelope.js';

const NO_DOCS_MESSAGE = 'Keine relevanten Dokumente gefunden';

const bodySchema = z.object({
  message: z.string().min(1).max(8_000),
  conversationId: z.string().uuid().optional(),
});

export interface RagChatDeps {
  searchDeps: SearchDeps;
  resolveProvider: (id: string) => LlmProvider;
  providerId: string;
  rateLimit?: { max: number; timeWindow: number };
}

function sse(reply: FastifyReply, payload: string): Promise<void> {
  return new Promise((resolve) => {
    const ok = reply.raw.write(payload);
    if (ok) resolve();
    else reply.raw.once('drain', resolve);
  });
}

function toSources(results: SearchResult[]): Array<Record<string, unknown>> {
  return results.map((r) => ({
    documentId: r.documentId,
    title: r.documentTitle,
    chunkIndex: r.chunkIndex,
    similarity: Number(r.similarity.toFixed(4)),
    classification: r.classification,
  }));
}

function buildMessages(userMessage: string, results: SearchResult[]): ChatMessage[] {
  const context = results
    .map((r, i) => `[${i + 1}] (${r.documentTitle}, chunk ${r.chunkIndex}) ${r.content}`)
    .join('\n\n');
  return [
    {
      role: 'system',
      content:
        'Answer ONLY using the provided context. If the context is insufficient, say so. ' +
        'Cite sources by their [n] markers. Do not invent sources.',
    },
    { role: 'user', content: `Context:\n${context}\n\nQuestion: ${userMessage}` },
  ];
}

export function registerRagChatRoute(app: FastifyInstance, deps: RagChatDeps): void {
  const routeOpts = {
    preHandler: requirePermission('document:query'),
    ...(deps.rateLimit ? { config: { rateLimit: deps.rateLimit } } : {}),
  };

  app.post('/api/chat/rag', routeOpts, async (req, reply) => {
    const ctx = req.authContext!; // requirePermission guarantees presence
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid request' });

    const clearance = clearanceForRole(ctx.role);
    const tenantKey = deriveTenantKey(deps.searchDeps.masterKey, ctx.orgId);
    const results = await searchDocuments(deps.searchDeps, {
      query: parsed.data.message,
      orgId: ctx.orgId,
      userId: ctx.userId,
      clearance,
      ip: req.ip,
    });

    const model = deps.providerId;
    const sources = toSources(results);

    reply.hijack();
    const res = reply.raw;
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    let clientClosed = false;
    res.on('close', () => {
      if (!res.writableFinished) clientClosed = true;
    });

    let answer = '';
    try {
      if (results.length === 0) {
        // Never hallucinate sources when nothing was retrieved.
        answer = NO_DOCS_MESSAGE;
        await sse(reply, `data: ${JSON.stringify({ delta: NO_DOCS_MESSAGE, done: false })}\n\n`);
      } else {
        const provider = deps.resolveProvider(deps.providerId);
        for await (const chunk of provider.chatStream({ messages: buildMessages(parsed.data.message, results) })) {
          if (clientClosed || res.writableEnded) break;
          if (chunk.delta) {
            answer += chunk.delta;
            await sse(reply, `data: ${JSON.stringify({ delta: chunk.delta, done: false })}\n\n`);
          }
          if (chunk.done) break;
        }
      }

      // EU AI Act transparency: full ai_meta envelope (Art. 50), linked to the
      // KI-Inventar entry for this model.
      const entry = await ensureInventoryEntry(
        deps.searchDeps.db,
        { orgId: ctx.orgId, userId: ctx.userId, clearance: clearanceForRole(ctx.role) },
        { modelName: model, provider: model },
      );
      const metadata = buildAiMeta({
        model,
        provider: model,
        sources,
        inventoryEntryId: entry.id,
        riskClass: entry.riskClass,
        humanOversightRequired: entry.humanOversightRequired,
      });
      if (!clientClosed && !res.writableEnded) {
        await sse(reply, `event: metadata\ndata: ${JSON.stringify(metadata)}\n\n`);
        await sse(reply, 'event: done\ndata: {}\n\n');
      }

      // Persist the turn (best-effort; encrypted content).
      await persistTurn(deps, ctx, parsed.data.conversationId, parsed.data.message, answer, sources, model, tenantKey);
    } catch {
      if (!res.writableEnded) {
        res.write(`event: error\ndata: ${JSON.stringify({ error: 'rag_failed' })}\n\n`);
      }
    } finally {
      if (!res.writableEnded) res.end();
    }
  });
}

async function persistTurn(
  deps: RagChatDeps,
  ctx: { orgId: string; userId: string; role: import('../../db/schema/index.js').Role },
  conversationId: string | undefined,
  userMessage: string,
  answer: string,
  sources: Array<Record<string, unknown>>,
  model: string,
  tenantKey: Buffer,
): Promise<void> {
  await withTenantContext(
    deps.searchDeps.db,
    { orgId: ctx.orgId, userId: ctx.userId, clearance: clearanceForRole(ctx.role) },
    async (tx) => {
      let convId = conversationId;
      if (convId) {
        const exists = await tx.select({ id: conversations.id }).from(conversations).where(eq(conversations.id, convId)).limit(1);
        if (!exists[0]) convId = undefined;
      }
      if (!convId) {
        const [c] = await tx
          .insert(conversations)
          .values({ orgId: ctx.orgId, userId: ctx.userId })
          .returning({ id: conversations.id });
        convId = c!.id;
      }
      await tx.insert(messages).values([
        {
          conversationId: convId,
          orgId: ctx.orgId,
          userId: ctx.userId,
          role: 'user',
          contentEncrypted: encryptSecret(userMessage, tenantKey),
        },
        {
          conversationId: convId,
          orgId: ctx.orgId,
          userId: ctx.userId,
          role: 'assistant',
          contentEncrypted: encryptSecret(answer, tenantKey),
          sourcesJson: sources,
          modelUsed: model,
        },
      ]);
    },
  );
}
