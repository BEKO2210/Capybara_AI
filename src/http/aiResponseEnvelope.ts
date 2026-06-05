import type { FastifyInstance, FastifyReply } from 'fastify';
import type { AppDatabase } from '../db/client.js';
import { clearanceForRole } from '../rbac/roles.js';
import { ensureInventoryEntry } from '../compliance/inventory.js';

/**
 * EU AI Act Art. 50 transparency envelope. Every AI response is wrapped with an
 * `ai_meta` block that marks it AI-generated, identifies model/provider, links
 * to the KI-Inventar entry, and states the human-oversight + compliance status.
 */
export interface AiMeta {
  ai_generated: true;
  model: string;
  provider: string;
  timestamp: string;
  sources: unknown[];
  confidence: null;
  inventory_entry_id: string | null;
  human_oversight: {
    required: boolean;
    approved_by: string | null;
    approved_at: string | null;
  };
  compliance: {
    eu_ai_act: true;
    risk_class: string;
    transparency_label: 'KI-generierter Inhalt';
  };
}

export interface AiMetaInput {
  model: string;
  provider: string;
  sources?: unknown[];
  inventoryEntryId?: string | null;
  riskClass?: string;
  humanOversightRequired?: boolean;
  approvedBy?: string | null;
  approvedAt?: string | null;
}

export function buildAiMeta(input: AiMetaInput): AiMeta {
  return {
    ai_generated: true,
    model: input.model,
    provider: input.provider,
    timestamp: new Date().toISOString(),
    sources: input.sources ?? [],
    confidence: null,
    inventory_entry_id: input.inventoryEntryId ?? null,
    human_oversight: {
      required: input.humanOversightRequired ?? false,
      approved_by: input.approvedBy ?? null,
      approved_at: input.approvedAt ?? null,
    },
    compliance: {
      eu_ai_act: true,
      risk_class: input.riskClass ?? 'LIMITED',
      transparency_label: 'KI-generierter Inhalt',
    },
  };
}

declare module 'fastify' {
  interface FastifyReply {
    /** Wrap `data` with an auto-populated ai_meta envelope and send it. */
    aiEnvelope(data: unknown, meta: AiMetaInput): Promise<void>;
  }
}

/**
 * Registers the `reply.aiEnvelope(data, meta)` decorator. It auto-creates/looks
 * up the KI-Inventar entry for the model and fills inventory_entry_id, risk
 * class, and human-oversight default from it.
 */
export function registerAiEnvelope(app: FastifyInstance, deps: { db: AppDatabase }): void {
  app.decorateReply(
    'aiEnvelope',
    async function (this: FastifyReply, data: unknown, meta: AiMetaInput): Promise<void> {
      const ctx = this.request.authContext;
      let enriched: AiMetaInput = meta;
      if (ctx) {
        const entry = await ensureInventoryEntry(
          deps.db,
          { orgId: ctx.orgId, userId: ctx.userId, clearance: clearanceForRole(ctx.role) },
          { modelName: meta.model, provider: meta.provider },
        );
        enriched = {
          ...meta,
          inventoryEntryId: meta.inventoryEntryId ?? entry.id,
          riskClass: meta.riskClass ?? entry.riskClass,
          humanOversightRequired: meta.humanOversightRequired ?? entry.humanOversightRequired,
        };
      }
      await this.send({ data, ai_meta: buildAiMeta(enriched) });
    },
  );
}
