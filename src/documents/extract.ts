import { PDFParse } from 'pdf-parse';
import mammoth from 'mammoth';
import * as XLSX from 'xlsx';

export type DocKind = 'pdf' | 'docx' | 'xlsx' | 'txt' | 'md' | 'eml';

/** Allowlisted MIME types → document kind. Unknown types are rejected (null). */
const MIME_MAP: Record<string, DocKind> = {
  'application/pdf': 'pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
  'text/plain': 'txt',
  'text/markdown': 'md',
  'message/rfc822': 'eml',
};

export function detectKind(mimeType: string): DocKind | null {
  return MIME_MAP[mimeType.split(';')[0]!.trim().toLowerCase()] ?? null;
}

/** Extract plain text from a supported document buffer. */
export async function extractText(buffer: Buffer, kind: DocKind): Promise<string> {
  switch (kind) {
    case 'pdf': {
      const parser = new PDFParse({ data: new Uint8Array(buffer) });
      const result = await parser.getText();
      return result.text;
    }
    case 'docx': {
      const result = await mammoth.extractRawText({ buffer });
      return result.value;
    }
    case 'xlsx': {
      const wb = XLSX.read(buffer, { type: 'buffer' });
      const first = wb.SheetNames[0];
      if (!first) return '';
      const sheet = wb.Sheets[first];
      return sheet ? XLSX.utils.sheet_to_csv(sheet) : '';
    }
    case 'txt':
    case 'md':
      return buffer.toString('utf8');
    case 'eml':
      return extractEml(buffer.toString('utf8'));
  }
}

/** Minimal EML extraction: Subject header + body text (no attachments). */
function extractEml(raw: string): string {
  const normalized = raw.replace(/\r\n/g, '\n');
  const splitIdx = normalized.indexOf('\n\n');
  const headerBlock = splitIdx === -1 ? normalized : normalized.slice(0, splitIdx);
  const body = splitIdx === -1 ? '' : normalized.slice(splitIdx + 2);
  const subjectMatch = headerBlock.match(/^subject:\s*(.*)$/im);
  const subject = subjectMatch?.[1]?.trim() ?? '';
  // Strip a leading HTML body crudely; keep text.
  const text = body.replace(/<[^>]+>/g, ' ').replace(/\s+\n/g, '\n').trim();
  return subject ? `${subject}\n\n${text}` : text;
}
