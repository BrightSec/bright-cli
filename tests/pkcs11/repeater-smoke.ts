import { Server, Socket } from 'socket.io';
import parser from 'socket.io-msgpack-parser';
import { ChildProcess, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';

/**
 * Smoke test for a built Repeater (executable, npm install or Docker image):
 * stands in for the Bright cloud on localhost:8000, waits for the Repeater to
 * connect, sends it one request and checks the response.
 *
 * Usage: repeater-smoke.ts <target url> <expected status, errorCode or "error"> -- <repeater command...>
 * "error" accepts any errorCode, as long as no HTTP status came back.
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
    'Usage: repeater-smoke.ts <target url> <expected status, errorCode or "error"> -- <repeater command...>\n'
  );
  process.exit(2);
}

let repeater: ChildProcess | undefined;

// Every outcome ends the process, so the Repeater must not outlive it.
const finish = (code: number, message: string): never => {
  if (repeater && repeater.exitCode === null) {
    repeater.removeAllListeners('exit');
    repeater.kill();
  }
  (code ? process.stderr : process.stdout).write(`${message}\n`);
  process.exit(code);
};

const fail = (message: string): never => finish(1, `SMOKE FAILED: ${message}`);

const matches = (response: Response): boolean => {
  if (expected === 'error') {
    return !!response.errorCode && response.statusCode === undefined;
  }

  return /^\d+$/.test(expected)
    ? String(response.statusCode) === expected
    : response.errorCode === expected;
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
    io.of('/workstations').on('connection', (client: Socket) =>
      client.on('deploy', ({ repeaterId }: { repeaterId: string }) => {
        client.emit('deployed', { repeaterId });
        resolve(client);
      })
    )
  );

  // All interfaces: "localhost" may resolve to ::1 or 127.0.0.1 depending on the OS.
  http.listen(CLOUD_PORT);
  await once(http, 'listening');

  repeater = spawn(command, args, { stdio: 'inherit' });
  repeater.once('error', (e: Error) =>
    fail(`cannot start the Repeater: ${e.message}`)
  );
  repeater.once('exit', (code: number | null) =>
    fail(`the Repeater exited early with code ${code}`)
  );
  const timeout = new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new Error('the Repeater did not connect')),
      TIMEOUT_MS
    )
  );

  const socket = await Promise.race([deployed, timeout]);
  const response = await sendRequest(socket);
  process.stdout.write(`SMOKE RESPONSE ${JSON.stringify(response)}\n`);

  if (!matches(response)) {
    fail(
      `expected ${expected}, got ${
        response.errorCode ?? `status ${response.statusCode}`
      }`
    );
  }

  finish(0, `SMOKE PASSED: ${expected}`);
};

process.once('SIGINT', () => fail('interrupted'));
process.once('SIGTERM', () => fail('terminated'));

main().catch((e: Error) => fail(e.message));
