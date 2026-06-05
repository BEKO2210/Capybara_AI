import { connect } from 'node:net';

/** Result of a virus scan. */
export interface ScanResult {
  clean: boolean;
  signature?: string;
}

export type Scanner = (data: Buffer) => Promise<ScanResult>;

/**
 * Scan a buffer via the ClamAV daemon's INSTREAM command over a unix socket.
 * Fails CLOSED: any connection/protocol error rejects (a configured-but-broken
 * scanner must not allow unscanned uploads through).
 */
export function createClamavScanner(socketPath: string): Scanner {
  return (data: Buffer) =>
    new Promise<ScanResult>((resolve, reject) => {
      const sock = connect(socketPath);
      const chunks: Buffer[] = [];
      sock.on('error', (err) => reject(new Error(`clamav scan failed: ${err.message}`)));
      sock.on('connect', () => {
        sock.write('zINSTREAM\0');
        const size = Buffer.alloc(4);
        size.writeUInt32BE(data.length, 0);
        sock.write(size);
        sock.write(data);
        sock.write(Buffer.from([0, 0, 0, 0])); // zero-length chunk = end
      });
      sock.on('data', (d: Buffer) => chunks.push(d));
      sock.on('end', () => {
        const reply = Buffer.concat(chunks).toString('utf8');
        if (/\bOK\0?$/.test(reply.trim())) resolve({ clean: true });
        else {
          const m = reply.match(/:\s*(.+)\s+FOUND/);
          resolve({ clean: false, ...(m?.[1] ? { signature: m[1] } : {}) });
        }
      });
    });
}
