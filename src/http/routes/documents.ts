import type { FastifyInstance } from 'fastify';
import multipart from '@fastify/multipart';
import { clearanceForRole } from '../../rbac/roles.js';
import { requirePermission } from '../../rbac/guard.js';
import { CLASSIFICATIONS, type Classification } from '../../db/schema/index.js';
import { ingestDocument, nextVersionFor, IngestError, type IngestDeps } from '../../documents/ingest.js';
import {
  listDocuments,
  getDocument,
  getVersions,
  softDeleteDocument,
  setLegalHold,
  LegalHoldError,
} from '../../documents/lifecycle.js';

export interface DocumentRoutesDeps extends IngestDeps {
  maxUploadBytes: number;
}

function isClassification(v: unknown): v is Classification {
  return typeof v === 'string' && (CLASSIFICATIONS as readonly string[]).includes(v);
}

export async function registerDocumentRoutes(app: FastifyInstance, deps: DocumentRoutesDeps): Promise<void> {
  await app.register(multipart, { limits: { fileSize: deps.maxUploadBytes, files: 1 } });

  const ctxOf = (req: { authContext?: { orgId: string; userId: string; role: import('../../db/schema/index.js').Role } }) => {
    const a = req.authContext!;
    return { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role) };
  };

  async function handleUpload(req: import('fastify').FastifyRequest, reply: import('fastify').FastifyReply, parentId?: string, version?: number): Promise<unknown> {
    const ctx = ctxOf(req);
    const file = await req.file();
    if (!file) return reply.code(400).send({ error: 'no file' });
    const buffer = await file.toBuffer();
    if (file.file.truncated || buffer.length > deps.maxUploadBytes) {
      return reply.code(413).send({ error: 'file too large' });
    }
    const fields = file.fields as Record<string, { value?: string } | undefined>;
    const rawClass = fields['classification']?.value;
    const classification: Classification = isClassification(rawClass) ? rawClass : 'INTERNAL';
    const title = fields['title']?.value ?? file.filename ?? 'untitled';

    try {
      const result = await ingestDocument(deps, {
        orgId: ctx.orgId,
        userId: ctx.userId,
        clearance: ctx.clearance,
        title,
        mimeType: file.mimetype,
        classification,
        data: buffer,
        ip: req.ip,
        ...(parentId ? { parentId } : {}),
        ...(version ? { version } : {}),
      });
      return reply.code(201).send(result);
    } catch (err) {
      if (err instanceof IngestError) {
        const status = err.code === 'unsupported_type' ? 415 : err.code === 'classification_exceeds_clearance' ? 403 : 422;
        return reply.code(status).send({ error: err.code });
      }
      throw err;
    }
  }

  app.post('/api/documents/upload', { preHandler: requirePermission('document:upload') }, (req, reply) =>
    handleUpload(req, reply),
  );

  app.post<{ Params: { id: string } }>(
    '/api/documents/:id/upload',
    { preHandler: requirePermission('document:upload') },
    async (req, reply) => {
      const info = await nextVersionFor(deps.db, ctxOf(req), req.params.id);
      if (!info) return reply.code(404).send({ error: 'not found' });
      return handleUpload(req, reply, info.parentId, info.version);
    },
  );

  app.get('/api/documents', { preHandler: requirePermission('document:read') }, async (req) => {
    const q = req.query as { limit?: string; offset?: string };
    return listDocuments(deps.db, ctxOf(req), {
      ...(q.limit ? { limit: Number(q.limit) } : {}),
      ...(q.offset ? { offset: Number(q.offset) } : {}),
    });
  });

  app.get<{ Params: { id: string } }>(
    '/api/documents/:id',
    { preHandler: requirePermission('document:read') },
    async (req, reply) => {
      const result = await getDocument(deps.db, ctxOf(req), req.params.id);
      if (!result) return reply.code(404).send({ error: 'not found' });
      return result;
    },
  );

  app.get<{ Params: { id: string } }>(
    '/api/documents/:id/versions',
    { preHandler: requirePermission('document:read') },
    async (req) => getVersions(deps.db, ctxOf(req), req.params.id),
  );

  app.delete<{ Params: { id: string } }>(
    '/api/documents/:id',
    { preHandler: requirePermission('document:delete') },
    async (req, reply) => {
      try {
        const ok = await softDeleteDocument(deps.db, ctxOf(req), req.params.id, req.ip);
        if (!ok) return reply.code(404).send({ error: 'not found' });
        return { deleted: true };
      } catch (err) {
        if (err instanceof LegalHoldError) return reply.code(409).send({ error: 'legal_hold' });
        throw err;
      }
    },
  );

  app.post<{ Params: { id: string } }>(
    '/api/documents/:id/hold',
    { preHandler: requirePermission('document:hold') },
    async (req, reply) => {
      const ok = await setLegalHold(deps.db, ctxOf(req), req.params.id, true);
      if (!ok) return reply.code(404).send({ error: 'not found' });
      return { legalHold: true };
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/api/documents/:id/hold',
    { preHandler: requirePermission('document:release_hold') },
    async (req, reply) => {
      const ok = await setLegalHold(deps.db, ctxOf(req), req.params.id, false);
      if (!ok) return reply.code(404).send({ error: 'not found' });
      return { legalHold: false };
    },
  );
}
