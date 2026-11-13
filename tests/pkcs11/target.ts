import { readFileSync } from 'node:fs';
import { createServer, Server } from 'node:https';
import { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { TLSSocket } from 'node:tls';

export interface TargetStats {
  handshakes: number;
  requests: number;
}

export interface Target {
  url: string;
  stats(): TargetStats;
  resetStats(): void;
  close(): Promise<void>;
}

/**
 * An HTTPS target that only accepts clients presenting a certificate issued by
 * the test CA. Connections are kept alive so connection reuse is observable
 * through the handshake count.
 */
export const startTarget = async ({
  pkiDir,
  port = 0
}: {
  pkiDir: string;
  port?: number;
}): Promise<Target> => {
  const stats: TargetStats = { handshakes: 0, requests: 0 };

  const server: Server = createServer(
    {
      key: readFileSync(join(pkiDir, 'server.key')),
      cert: readFileSync(join(pkiDir, 'server.pem')),
      ca: readFileSync(join(pkiDir, 'ca.pem')),
      requestCert: true,
      rejectUnauthorized: true,
      keepAliveTimeout: 30_000
    },
    (req, res) => {
      stats.requests++;
      const socket = req.socket as TLSSocket;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          subject: socket.getPeerCertificate().subject?.CN,
          protocol: socket.getProtocol()
        })
      );
    }
  );
  server.on('secureConnection', () => stats.handshakes++);

  await new Promise<void>((resolve) => server.listen(port, resolve));

  return {
    url: `https://localhost:${(server.address() as AddressInfo).port}/`,
    stats: () => ({ ...stats }),
    resetStats: () => {
      stats.handshakes = 0;
      stats.requests = 0;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      })
  };
};

if (require.main === module) {
  void startTarget({
    pkiDir: process.env.PKCS11_TEST_DIR,
    port: Number(process.env.PKCS11_TEST_TARGET_PORT ?? 8443)
  }).then(({ url }) =>
    process.stdout.write(`mTLS target listening on ${url}\n`)
  );
}
