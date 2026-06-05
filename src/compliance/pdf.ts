import PDFDocument from 'pdfkit';
import type { AiInventoryEntry } from '../db/schema/index.js';

/** Render a pdfkit document to a Buffer, stamping a footer on every page. */
function renderToBuffer(footer: string, build: (doc: PDFKit.PDFDocument) => void): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 50, bufferPages: true, size: 'A4' });
  const chunks: Buffer[] = [];
  doc.on('data', (c: Buffer) => chunks.push(c));
  const done = new Promise<Buffer>((resolve) => doc.on('end', () => resolve(Buffer.concat(chunks))));

  build(doc);

  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(range.start + i);
    doc.fontSize(8).fillColor('#666').text(footer, 50, doc.page.height - 40, {
      align: 'center',
      width: doc.page.width - 100,
    });
    doc.fillColor('black');
  }
  doc.end();
  return done;
}

const INVENTORY_FOOTER = 'Erstellt durch Capybara_AI — KI-generiertes Dokument';
const REPORT_FOOTER =
  'Erstellt durch Capybara_AI | KI-generiertes Dokument | Kein Ersatz für rechtliche Beratung';

function fmtDate(d: Date | string): string {
  const date = typeof d === 'string' ? new Date(d) : d;
  return date.toISOString().slice(0, 10);
}

/** KI-Inventar PDF (EU AI Act Art. 4). */
export function renderInventoryPdf(params: {
  orgName: string;
  generatedBy: string;
  entries: AiInventoryEntry[];
}): Promise<Buffer> {
  return renderToBuffer(INVENTORY_FOOTER, (doc) => {
    doc.fontSize(18).text('KI-Inventar gemäß Art. 4 EU AI Act', { align: 'left' });
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#333');
    doc.text(`Organisation: ${params.orgName}`);
    doc.text(`Exportdatum: ${fmtDate(new Date())}`);
    doc.text(`Erstellt von: ${params.generatedBy}`);
    doc.fillColor('black').moveDown(1);

    if (params.entries.length === 0) {
      doc.fontSize(11).text('Keine KI-Inventar-Einträge vorhanden.');
    }

    for (const e of params.entries) {
      doc.fontSize(12).fillColor('#000').text(`${e.modelName} (${e.provider})`, { underline: true });
      doc.fontSize(10).fillColor('#222');
      doc.text(`Modell: ${e.modelName}`);
      doc.text(`Anbieter: ${e.provider}`);
      doc.text(`Zweck: ${e.purpose || '—'}`);
      doc.text(`Risikoklasse: ${e.riskClass}`);
      doc.text(`Im Einsatz seit: ${fmtDate(e.inUseSince)}`);
      doc.text(`Menschliche Aufsicht: ${e.humanOversightRequired ? 'Ja' : 'Nein'}`);
      doc.text(`Verarbeitete Datenkategorien: ${(e.dataCategoriesProcessed ?? []).join(', ') || '—'}`);
      doc.text(`Rechtsgrundlage: ${e.legalBasis || '—'}`);
      doc.fillColor('black').moveDown(0.8);
    }
  });
}

export interface ComplianceReportData {
  orgName: string;
  generatedBy: string;
  inventory: AiInventoryEntry[];
  audit: {
    aiQueries: number;
    documentsProcessed: number;
    oversight: { pending: number; approved: number; rejected: number };
    gdprErasures: number;
    securityEventsByType: Record<string, number>;
  };
}

/** Comprehensive KI-Compliance-Bericht PDF (5 sections). */
export function renderCompliancePdf(data: ComplianceReportData): Promise<Buffer> {
  return renderToBuffer(REPORT_FOOTER, (doc) => {
    // Cover
    doc.fontSize(24).text('KI-Compliance-Bericht', { align: 'center' });
    doc.moveDown(1);
    doc.fontSize(12);
    doc.text(`Organisation: ${data.orgName}`, { align: 'center' });
    doc.text(`Erstellt am: ${fmtDate(new Date())}`, { align: 'center' });
    doc.text(`Erstellt von: ${data.generatedBy}`, { align: 'center' });
    doc.moveDown(1);
    doc.fontSize(11).fillColor('#a00').text('Vertraulich — Nur für interne Verwendung', { align: 'center' });
    doc.fillColor('black');

    // Section 1 — KI-Inventar
    doc.addPage();
    doc.fontSize(16).text('Abschnitt 1 — KI-Inventar');
    doc.moveDown(0.5).fontSize(10);
    if (data.inventory.length === 0) doc.text('Keine Einträge.');
    for (const e of data.inventory) {
      doc.text(`• ${e.modelName} (${e.provider}) — Risikoklasse ${e.riskClass}, Aufsicht: ${e.humanOversightRequired ? 'Ja' : 'Nein'}`);
    }

    // Section 2 — Audit-Übersicht
    doc.addPage();
    doc.fontSize(16).text('Abschnitt 2 — Audit-Übersicht (letzte 90 Tage)');
    doc.moveDown(0.5).fontSize(10);
    doc.text(`KI-Abfragen gesamt: ${data.audit.aiQueries}`);
    doc.text(`Verarbeitete Dokumente: ${data.audit.documentsProcessed}`);
    doc.text(`Menschliche Aufsicht — ausstehend: ${data.audit.oversight.pending}, genehmigt: ${data.audit.oversight.approved}, abgelehnt: ${data.audit.oversight.rejected}`);
    doc.text(`DSGVO-Löschungen: ${data.audit.gdprErasures}`);
    doc.moveDown(0.3).text('Sicherheitsereignisse nach Typ:');
    const types = Object.entries(data.audit.securityEventsByType);
    if (types.length === 0) doc.text('  keine');
    for (const [type, n] of types) doc.text(`  ${type}: ${n}`);

    // Section 3 — Datenschutz & Rechtsgrundlagen
    doc.addPage();
    doc.fontSize(16).text('Abschnitt 3 — Datenschutz & Rechtsgrundlagen');
    doc.moveDown(0.5).fontSize(10);
    const dataMap: [string, string, string][] = [
      ['Nutzerkonto (E-Mail, Passwort-Hash)', 'Vertrag', 'Lebensdauer des Kontos'],
      ['Dokumente + Chunks (verschlüsselt)', 'Berechtigtes Interesse / Vertrag', 'betreiberdefiniert / Aufbewahrungsdatum'],
      ['Chat-Nachrichten (verschlüsselt)', 'Vertrag', 'betreiberdefiniert'],
      ['Zugriffs-/Audit-Protokoll (Hash der Anfrage)', 'Berechtigtes Interesse (Sicherheit)', 'betreiberdefiniert'],
    ];
    doc.text('Datenkarte (Zusammenfassung):');
    for (const [d, basis, ret] of dataMap) doc.text(`  • ${d} — Rechtsgrundlage: ${basis}; Aufbewahrung: ${ret}`);
    doc.moveDown(0.3).text('Verschlüsselung ruhender Daten per AES-256-GCM (pro-Mandant-Schlüssel).');

    // Section 4 — Technische Schutzmaßnahmen
    doc.addPage();
    doc.fontSize(16).text('Abschnitt 4 — Technische Schutzmaßnahmen');
    doc.moveDown(0.5).fontSize(10);
    for (const m of [
      'Verschlüsselung ruhender Daten (AES-256-GCM) ✓',
      'Verschlüsselung der Übertragung (TLS in Produktion erforderlich) ✓',
      'Mandantentrennung: PostgreSQL Row-Level Security ✓',
      'Zugriffskontrolle: RBAC (owner/admin/member/viewer) ✓',
      'Audit-Log: manipulationssicher, append-only (Hash-Kette) ✓',
      'Menschliche Aufsicht: erzwungen für HIGH/CRITICAL-Tools ✓',
      'Datenresidenz: self-hosted, kein externer Transfer ohne Konfiguration ✓',
    ]) doc.text(`  ${m}`);

    // Section 5 — Offene Punkte
    doc.addPage();
    doc.fontSize(16).text('Abschnitt 5 — Offene Punkte');
    doc.moveDown(0.5).fontSize(10);
    for (const g of [
      'SAML 2.0: geplant für P2',
      'microVM-Sandbox: geplant für P2',
      'BSI-C5-Zertifizierung: nicht vorhanden',
      'SCIM-Provisionierung: geplant für P2',
    ]) doc.text(`  • ${g}`);
  });
}
