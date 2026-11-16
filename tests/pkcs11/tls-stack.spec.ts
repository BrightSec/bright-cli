import { ClientJob, ClientResult, CurlOptions, RESULT_MARKER } from './client';
import { startTarget, Target } from './target';
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { promisify } from 'node:util';

const env = {
  pkiDir: process.env.PKCS11_TEST_DIR,
  token: process.env.PKCS11_TEST_TOKEN,
  object: process.env.PKCS11_TEST_OBJECT,
  pin: process.env.PKCS11_TEST_PIN,
  provider: process.env.PKCS11_TEST_PROVIDER,
  engine: process.env.PKCS11_TEST_ENGINE
};

const keyUri = `pkcs11:token=${env.token};object=${env.object};type=private`;
const certUri = `pkcs11:token=${env.token};object=${env.object};type=cert`;
// Providers ignore KEYPASSWD, so the PIN travels in the key URI.
const providerKey = (pin: string): CurlOptions => ({
  SSLENGINE: env.provider,
  SSLKEYTYPE: 'PROV',
  SSLKEY: `${keyUri}?pin-value=${pin}`
});

// Every job runs in its own process: the PKCS#11 module is process-wide and
// curl's provider finalizes it when an easy handle closes, which breaks later
// handshakes in the same process.
const run = async (job: Omit<ClientJob, 'url'>, target: Target) => {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      '-r',
      'ts-node/register/transpile-only',
      join(__dirname, 'client.ts'),
      JSON.stringify({ ...job, url: target.url })
    ],
    { env: process.env, maxBuffer: 16 * 1024 * 1024 }
  );
  const line = stdout
    .split('\n')
    .find((x: string) => x.startsWith(RESULT_MARKER));

  return JSON.parse(line.slice(RESULT_MARKER.length)) as ClientResult;
};

describe('PKCS#11 client certificates (SoftHSM2)', () => {
  let target: Target;

  beforeAll(async () => {
    if (!env.pkiDir || !process.env.SOFTHSM2_CONF) {
      throw new Error(
        'Run tests/pkcs11/setup.sh and load tests/pkcs11/.work/pkcs11.env first.'
      );
    }
    target = await startTarget({ pkiDir: env.pkiDir });
  });

  afterAll(() => target?.close());

  beforeEach(() => target.resetStats());

  it('completes the handshake with the certificate and the key on the token through the OpenSSL provider', async () => {
    const result = await run(
      {
        curlOptions: {
          ...providerKey(env.pin),
          SSLCERTTYPE: 'PROV',
          SSLCERT: certUri
        }
      },
      target
    );

    expect(result.errors).toEqual([]);
    expect(JSON.parse(result.bodies[0])).toMatchObject({
      subject: 'bright-pkcs11-client'
    });
  });

  it('completes the handshake with a certificate file and the key on the token through the OpenSSL provider', async () => {
    const result = await run(
      {
        curlOptions: {
          ...providerKey(env.pin),
          SSLCERT: join(env.pkiDir, 'client.pem')
        }
      },
      target
    );

    expect(result.errors).toEqual([]);
    expect(JSON.parse(result.bodies[0])).toMatchObject({
      subject: 'bright-pkcs11-client'
    });
  });

  (env.engine ? it : it.skip)(
    'completes the handshake through the OpenSSL engine',
    async () => {
      const result = await run(
        {
          curlOptions: {
            SSLENGINE: env.engine,
            SSLKEYTYPE: 'ENG',
            SSLKEY: keyUri,
            KEYPASSWD: env.pin,
            SSLCERT: join(env.pkiDir, 'client.pem')
          }
        },
        target
      );

      expect(result.errors).toEqual([]);
      expect(JSON.parse(result.bodies[0])).toMatchObject({
        subject: 'bright-pkcs11-client'
      });
    }
  );

  it('is rejected by the target when no client certificate is presented', async () => {
    const result = await run({ curlOptions: {} }, target);

    expect(result.succeeded).toBe(0);
    expect(result.failed).toBe(1);
  });

  it('fails with CURLE_SSL_CERTPROBLEM when the PIN is wrong', async () => {
    const result = await run(
      {
        curlOptions: {
          ...providerKey('0000'),
          SSLCERT: join(env.pkiDir, 'client.pem')
        }
      },
      target
    );

    expect(result.succeeded).toBe(0);
    expect(result.errors).toMatchObject([{ curlCode: 58 }]);
    expect(target.stats().handshakes).toBe(0);
  });

  it('keeps completing fresh handshakes in one process when the easy handles are long-lived', async () => {
    const result = await run(
      {
        curlOptions: {
          ...providerKey(env.pin),
          SSLCERT: join(env.pkiDir, 'client.pem')
        },
        requests: 30,
        concurrency: 2,
        persistentHandles: true
      },
      target
    );

    expect(result.errors).toEqual([]);
    expect(target.stats()).toEqual({ handshakes: 30, requests: 30 });
  });

  it('signs once per pooled connection when connections are reused', async () => {
    const pool = 2;

    const result = await run(
      {
        curlOptions: {
          ...providerKey(env.pin),
          SSLCERT: join(env.pkiDir, 'client.pem')
        },
        requests: 20,
        pool
      },
      target
    );

    expect(result.errors).toEqual([]);
    expect(result.succeeded).toBe(20);
    expect(target.stats()).toEqual({ handshakes: pool, requests: 20 });
  });
});
