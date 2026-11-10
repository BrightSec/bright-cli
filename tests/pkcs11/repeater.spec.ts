import { RepeaterJob, RepeaterResult, RESULT_MARKER } from './repeater';
import { startTarget, Target } from './target';
import { Pkcs11Cert } from '../../src/RequestExecutor/Pkcs11Cert';
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { promisify } from 'node:util';

const env = {
  pkiDir: process.env.PKCS11_TEST_DIR,
  module: process.env.PKCS11_TEST_MODULE,
  token: process.env.PKCS11_TEST_TOKEN,
  pin: process.env.PKCS11_TEST_PIN,
  provider: process.env.PKCS11_TEST_PROVIDER_LIB
};

// Each job runs in its own process: logins and module state are process-wide.
const run = async (job: RepeaterJob): Promise<RepeaterResult> => {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      '-r',
      'ts-node/register/transpile-only',
      join(__dirname, 'repeater.ts'),
      JSON.stringify(job)
    ],
    {
      env: { ...process.env, CARD_PIN: env.pin, WRONG_PIN: '0000' },
      maxBuffer: 16 * 1024 * 1024
    }
  );
  const line = stdout
    .split('\n')
    .find((x: string) => x.startsWith(RESULT_MARKER));

  return JSON.parse(line.slice(RESULT_MARKER.length)) as RepeaterResult;
};

describe('HttpRequestExecutor', () => {
  let target: Target;

  const cert = (overrides: Partial<Pkcs11Cert> = {}): Pkcs11Cert => ({
    hostname: 'localhost',
    pinEnv: 'CARD_PIN',
    token: env.token,
    cert: 'token',
    maxConcurrency: 1,
    ...overrides
  });

  const urls = (count: number, url = target.url): string[] =>
    Array.from({ length: count }, () => url);

  beforeAll(async () => {
    if (!env.pkiDir || !env.provider || !process.env.SOFTHSM2_CONF) {
      throw new Error(
        'Run tests/pkcs11/setup.sh and load tests/pkcs11/.work/pkcs11.env first.'
      );
    }
    target = await startTarget({ pkiDir: env.pkiDir });
  });

  afterAll(() => target?.close());

  beforeEach(() => target.resetStats());

  describe('execute', () => {
    it('should complete sequential requests on one connection with a single login', async () => {
      // act
      const result = await run({
        urls: urls(30),
        pkcs11: { certs: [cert()], module: env.module, provider: env.provider }
      });

      // assert
      expect(result.responses).toHaveLength(30);
      for (const { statusCode, errorCode, body } of result.responses) {
        expect({ statusCode, errorCode }).toEqual({
          statusCode: 200,
          errorCode: undefined
        });
        expect(JSON.parse(body)).toMatchObject({
          subject: 'bright-pkcs11-client'
        });
      }
      expect(result.logins).toBe(1);
      expect(target.stats().handshakes).toBe(1);
    });

    it('should run at most maxConcurrency connections in parallel', async () => {
      // act
      const result = await run({
        urls: urls(40),
        concurrency: 6,
        pkcs11: {
          certs: [cert({ maxConcurrency: 2 })],
          module: env.module,
          provider: env.provider
        }
      });

      // assert
      expect(
        result.responses.filter(({ statusCode }) => statusCode === 200)
      ).toHaveLength(40);
      expect(result.logins).toBe(1);
      expect(target.stats().handshakes).toBeLessThanOrEqual(2);
    });

    it('should send the certificate from a file with the key on the token', async () => {
      // act
      const result = await run({
        urls: urls(5),
        pkcs11: {
          certs: [cert({ cert: join(env.pkiDir, 'client.pem') })],
          module: env.module,
          provider: env.provider
        }
      });

      // assert
      expect(result.responses.map(({ statusCode }) => statusCode)).toEqual([
        200, 200, 200, 200, 200
      ]);
    });

    it('should report a wrong PIN on every request after a single login attempt', async () => {
      // act
      const result = await run({
        urls: urls(5),
        pkcs11: {
          certs: [cert({ pinEnv: 'WRONG_PIN' })],
          module: env.module,
          provider: env.provider
        }
      });

      // assert
      expect(result.responses.map(({ errorCode }) => errorCode)).toEqual(
        Array(5).fill('PKCS11_PIN_INCORRECT')
      );
      expect(result.logins).toBe(1);
      expect(target.stats().requests).toBe(0);
    });

    it('should report a token that is not present', async () => {
      // act
      const result = await run({
        urls: urls(1),
        pkcs11: {
          certs: [cert({ token: 'missing' })],
          module: env.module,
          provider: env.provider
        }
      });

      // assert
      expect(result.responses[0]).toMatchObject({
        errorCode: 'PKCS11_TOKEN_NOT_FOUND'
      });
    });

    it('should share one login between targets that use the same token', async () => {
      // arrange
      const ip = target.url.replace('localhost', '127.0.0.1');

      // act
      const result = await run({
        urls: [...urls(5), ...urls(5, ip)],
        concurrency: 2,
        pkcs11: {
          certs: [cert(), cert({ hostname: '127.0.0.1' })],
          module: env.module,
          provider: env.provider
        }
      });

      // assert
      expect(
        result.responses.filter(({ statusCode }) => statusCode === 200)
      ).toHaveLength(10);
      expect(result.logins).toBe(1);
    });
  });
});
