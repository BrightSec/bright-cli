import { Pkcs11Client, Pkcs11ClientDependencies } from './Pkcs11Client';
import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import { Pkcs11ModuleLoader } from './Pkcs11Module';
import { Pkcs11Cert } from '../Pkcs11Cert';
import { delimiter } from 'node:path';

describe('Pkcs11Client', () => {
  const cert = (overrides: Partial<Pkcs11Cert> = {}): Pkcs11Cert => ({
    hostname: 'example.com',
    pinEnv: 'CARD_PIN',
    cert: 'token',
    maxConcurrency: 1,
    ...overrides
  });

  const dependencies = (
    overrides: Partial<Pkcs11ClientDependencies> = {}
  ): Pkcs11ClientDependencies => ({
    loader: {
      load: jest.fn(() => {
        throw new Error('no card');
      })
    } as Pkcs11ModuleLoader,
    locateProvider: () => '/opt/ossl/pkcs11prov.so',
    writeConfig: () => ({ path: '/tmp/x/openssl.cnf', name: 'pkcs11prov' }),
    env: {},
    platform: 'linux',
    ...overrides
  });

  describe('constructor', () => {
    it('should point OPENSSL_CONF at the generated config', () => {
      // arrange
      const env: NodeJS.ProcessEnv = { OPENSSL_CONF: '/etc/ssl/openssl.cnf' };

      // act
      new Pkcs11Client(
        { module: '/opt/vendor.so', certs: [cert()] },
        dependencies({ env })
      );

      // assert
      expect(env.OPENSSL_CONF).toBe('/tmp/x/openssl.cnf');
    });

    it('should put the provider directory first in PATH on Windows', () => {
      // arrange
      const env: NodeJS.ProcessEnv = { PATH: 'C:/Windows' };

      // act
      new Pkcs11Client(
        { module: '/opt/vendor.so', certs: [cert()] },
        dependencies({
          env,
          platform: 'win32',
          locateProvider: () => 'C:/Bright/pkcs11prov.dll'
        })
      );

      // assert
      expect(env.PATH).toBe(`C:/Bright${delimiter}C:/Windows`);
    });

    it('should make OpenSSL read the live environment on Windows', () => {
      // arrange
      const env: NodeJS.ProcessEnv = {};

      // act
      new Pkcs11Client(
        { module: '/opt/vendor.so', certs: [cert()] },
        dependencies({ env, platform: 'win32' })
      );

      // assert
      expect(env).toMatchObject({
        OPENSSL_CONF: '/tmp/x/openssl.cnf',
        OPENSSL_WIN32_UTF8: '1'
      });
    });
  });

  describe('match', () => {
    const certs = [
      cert({ hostname: 'example.com' }),
      cert({ hostname: '*.example.org', port: '8443' })
    ];
    const client = new Pkcs11Client(
      { module: '/opt/vendor.so', certs },
      dependencies()
    );

    it.each([
      { url: 'https://example.com/a', expected: [certs[0]] },
      { url: 'https://api.example.org:8443/', expected: [certs[1]] },
      { url: 'https://api.example.org/', expected: [] },
      { url: 'http://example.com/', expected: [] },
      { url: 'https://other.com/', expected: [] }
    ])(
      'should match $url',
      ({ url, expected }: { url: string; expected: Pkcs11Cert[] }) => {
        // act
        const result = client.match(url);

        // assert
        expect(result).toEqual(expected);
      }
    );
  });

  describe('identity', () => {
    it('should reject every request when the setup failed', async () => {
      // arrange
      const client = new Pkcs11Client(
        { module: '/opt/vendor.so', certs: [cert()] },
        dependencies({
          locateProvider: () => {
            throw new Pkcs11Error(
              Pkcs11ErrorCode.MODULE_LOAD_FAILED,
              'provider not found'
            );
          }
        })
      );

      // act
      const result = client.identity(cert());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.MODULE_LOAD_FAILED,
        message: 'provider not found'
      });
    });
  });

  describe('warmUp', () => {
    it('should check every certificate without an unhandled rejection', async () => {
      // arrange
      const deps = dependencies();
      const certs = [cert(), cert({ hostname: 'other.com' })];
      const client = new Pkcs11Client(
        { module: '/opt/vendor.so', certs },
        deps
      );

      // act
      client.warmUp();
      await new Promise((resolve) => setImmediate(resolve));

      // assert
      expect(deps.loader.load).toHaveBeenCalledTimes(2);
    });
  });

  describe('pool', () => {
    it('should keep one pool per certificate', () => {
      // arrange
      const client = new Pkcs11Client(
        { module: '/opt/vendor.so', certs: [cert()] },
        dependencies()
      );
      const first = cert();
      const second = cert({ maxConcurrency: 2 });

      // act
      const pools = [
        client.pool(first),
        client.pool(first),
        client.pool(second)
      ];

      // assert
      expect(pools[0]).toBe(pools[1]);
      expect(pools[0]).not.toBe(pools[2]);
    });
  });
});
