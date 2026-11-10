import { Server, Socket } from 'socket.io';
import parser from 'socket.io-msgpack-parser';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';

/**
 * Smoke test for a built Repeater (executable, npm install or Docker image):
 * stands in for the Bright cloud on localhost:8000, waits for the Repeater to
 * connect, sends it one request and checks the response.
 *
 * Usage: repeater-smoke.ts <target url> <expected status or errorCode> -- <repeater command...>
 * The command must include `repeater --hostname localhost`, so the Repeater
 * connects to ws://localhost:8000/workstations.
 */

interface Response {
  statusCode?: number;
  errorCode?: string;
  message?: string;
  body?: string;
}

const CLOUD_PORT = 8000;
const TIMEOUT_MS = 60_000;

const [url, expected, separator, command, ...args]: string[] =
  process.argv.slice(2);

if (!url || !expected || separator !== '--' || !command) {
  process.stderr.write(
    'Usage: repeater-smoke.ts <target url> <expected status or errorCode> -- <repeater command...>\n'
  );
  process.exit(2);
}

const fail = (message: string): never => {
  process.stderr.write(`SMOKE FAILED: ${message}\n`);
  process.exit(1);
};

const sendRequest = (socket: Socket): Promise<Response> =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('no response to the request')),
      TIMEOUT_MS
    );
    socket.emit(
      'request',
      { protocol: 'http', url, method: 'GET', headers: {} },
      (response: Response) => {
        clearTimeout(timer);
        resolve(response);
      }
    );
  });

const main = async (): Promise<void> => {
  const http = createServer();
  const io = new Server(http, {
    parser,
    path: '/api/ws/v1',
    transports: ['websocket']
  });

  const deployed = new Promise<Socket>((resolve) =>
    io.of('/workstations').on('connection', (socket: Socket) =>
      socket.on('deploy', ({ repeaterId }: { repeaterId: string }) => {
        socket.emit('deployed', { repeaterId });
        resolve(socket);
      })
    )
  );

  // All interfaces: "localhost" may resolve to ::1 or 127.0.0.1 depending on the OS.
  http.listen(CLOUD_PORT);
  await once(http, 'listening');

  const repeater = spawn(command, args, { stdio: 'inherit' });
  const exited = once(repeater, 'exit').then(([code]: unknown[]) =>
    fail(`the Repeater exited early with code ${code}`)
  );
  const timeout = new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new Error('the Repeater did not connect')),
      TIMEOUT_MS
    )
  );

  try {
    const socket = await Promise.race([deployed, exited, timeout]);
    const response = await sendRequest(socket);
    process.stdout.write(`SMOKE RESPONSE ${JSON.stringify(response)}\n`);

    const actual = /^\d+$/.test(expected)
      ? String(response.statusCode)
      : response.errorCode;

    if (actual !== expected) {
      fail(`expected ${expected}, got ${actual}`);
    }

    process.stdout.write(`SMOKE PASSED: ${expected}\n`);
  } catch (e) {
    fail((e as Error).message);
  } finally {
    repeater.removeAllListeners('exit');
    repeater.kill();
    void io.close();
  }
};

void main().then(
  () => process.exit(0),
  (e: Error) => fail(e.message)
);
