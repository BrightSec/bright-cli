import { Pkcs11Client, Pkcs11ClientDependencies } from './Pkcs11Client';
import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import { Pkcs11Module, Pkcs11ModuleLoader } from './Pkcs11Module';
import { Pkcs11PinPromptCancelledError } from './Pkcs11PinPrompt';
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
    prompt: { interactive: false, ask: jest.fn() },
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

    it('should not set the Windows-only variables on other platforms', () => {
      // arrange
      const env: NodeJS.ProcessEnv = { PATH: '/usr/bin' };

      // act
      new Pkcs11Client(
        { module: '/opt/vendor.so', certs: [cert()] },
        dependencies({ env, platform: 'linux' })
      );

      // assert
      expect(env).toEqual({
        PATH: '/usr/bin',
        OPENSSL_CONF: '/tmp/x/openssl.cnf'
      });
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

  describe('start', () => {
    const CKF_LOGIN_REQUIRED = 0x4;
    const certificate = {
      handle: Buffer.from('cert'),
      label: 'client',
      id: Buffer.from('01', 'hex'),
      value: Buffer.from('not a DER certificate')
    };
    const key = {
      handle: Buffer.from('key'),
      label: 'client',
      id: Buffer.from('01', 'hex')
    };

    const card = (tokens: { label: string; flags: number }[]) => ({
      tokens: jest.fn(() =>
        tokens.map(({ label, flags }) => ({
          slot: Buffer.from(label),
          label,
          serial: `${label}-serial`,
          flags
        }))
      ),
      mechanisms: jest.fn((): number[] => []),
      openSession: jest.fn(() => Buffer.from('session')),
      closeSession: jest.fn(),
      login: jest.fn(),
      findPrivateKeys: jest.fn(() => [key]),
      findCertificates: jest.fn(() => [certificate]),
      publicKeyAttributes: jest.fn(() => ({}))
    });

    const prompt = (...answers: string[]) => ({
      interactive: true,
      ask: jest.fn(() => Promise.resolve(answers.shift() ?? ''))
    });

    const create = (
      certs: Pkcs11Cert[],
      module: Pkcs11Module | Error,
      overrides: Partial<Pkcs11ClientDependencies> = {}
    ) =>
      new Pkcs11Client(
        { module: '/opt/vendor.so', certs },
        dependencies({
          loader: {
            load: jest.fn(() => {
              if (module instanceof Error) {
                throw module;
              }

              return module;
            })
          },
          ...overrides
        })
      );

    it('should ask once for each entry without a PIN source whose token needs a login', async () => {
      // arrange
      const module = card([
        { label: 'locked', flags: CKF_LOGIN_REQUIRED },
        { label: 'open', flags: 0 }
      ]);
      const typed = cert({ pinEnv: undefined, token: 'locked' });
      const open = cert({ pinEnv: undefined, token: 'open' });
      const fromEnv = cert({ hostname: 'env.example.com', token: 'locked' });
      const terminal = prompt('1234');
      const client = create([typed, open, fromEnv], module, {
        prompt: terminal,
        env: { CARD_PIN: '1234' }
      });

      // act
      await client.start();

      // assert
      expect(terminal.ask).toHaveBeenCalledTimes(1);
      expect(terminal.ask).toHaveBeenCalledWith(
        'Enter the PKCS#11 PIN for example.com (token "locked"): '
      );
      await expect(client.identity(typed)).resolves.toMatchObject({
        keyUri: expect.stringContaining('?pin-value=1234')
      });
      expect(module.login).toHaveBeenCalledWith(expect.any(Buffer), '1234');
    });

    it('should never ask again, even when a request needs a PIN that was not entered', async () => {
      // arrange
      const module = card([{ label: 'card', flags: CKF_LOGIN_REQUIRED }]);
      const entry = cert({ pinEnv: undefined });
      const terminal = prompt('');
      const client = create([entry], module, { prompt: terminal });

      // act
      await client.start();
      await client.start();
      const result = client.identity(entry);

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_UNAVAILABLE
      });
      expect(terminal.ask).toHaveBeenCalledTimes(1);
      expect(module.login).not.toHaveBeenCalled();
    });

    it('should ask for the PIN of a token that is not inserted yet', async () => {
      // arrange
      const terminal = prompt('1234');
      const client = create([cert({ pinEnv: undefined })], card([]), {
        prompt: terminal
      });

      // act
      await client.start();

      // assert
      expect(terminal.ask).toHaveBeenCalledTimes(1);
    });

    it('should not ask when the PKCS#11 module cannot be loaded', async () => {
      // arrange
      const terminal = prompt('1234');
      const client = create(
        [cert({ pinEnv: undefined })],
        new Error('no such file'),
        { prompt: terminal }
      );

      // act
      await client.start();

      // assert
      expect(terminal.ask).not.toHaveBeenCalled();
    });

    it('should not ask without a terminal', async () => {
      // arrange
      const module = card([{ label: 'card', flags: CKF_LOGIN_REQUIRED }]);
      const entry = cert({ pinEnv: undefined });
      const terminal = { interactive: false, ask: jest.fn() };
      const client = create([entry], module, { prompt: terminal });

      // act
      await client.start();

      // assert
      expect(terminal.ask).not.toHaveBeenCalled();
      await expect(client.identity(entry)).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_UNAVAILABLE
      });
    });

    it('should stop asking when the user cancels the input', async () => {
      // arrange
      const module = card([{ label: 'card', flags: CKF_LOGIN_REQUIRED }]);
      const terminal = {
        interactive: true,
        ask: jest.fn(() => Promise.reject(new Pkcs11PinPromptCancelledError()))
      };
      const client = create(
        [
          cert({ pinEnv: undefined }),
          cert({ hostname: 'other.com', pinEnv: undefined })
        ],
        module,
        { prompt: terminal }
      );

      // act
      const result = client.start();

      // assert
      await expect(result).rejects.toBeInstanceOf(
        Pkcs11PinPromptCancelledError
      );
      expect(terminal.ask).toHaveBeenCalledTimes(1);
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
