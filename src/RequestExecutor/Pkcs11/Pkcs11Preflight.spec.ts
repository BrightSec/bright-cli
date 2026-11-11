import { Pkcs11Preflight } from './Pkcs11Preflight';
import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import {
  Pkcs11CertificateInfo,
  Pkcs11Module,
  Pkcs11ModuleError,
  Pkcs11ModuleLoader,
  Pkcs11PrivateKeyInfo,
  Pkcs11Token
} from './Pkcs11Module';
import { Pkcs11Cert } from '../Pkcs11Cert';

const CKF_LOGIN_REQUIRED = 0x4;
const CKF_USER_PIN_FINAL_TRY = 0x20000;
const CKF_USER_PIN_LOCKED = 0x40000;
const CKK_RSA = 0x0;
const CKK_EC = 0x3;
const CKM_RSA_PKCS_PSS = 0xd;
const MODULE = '/usr/lib/vendor-pkcs11.so';
const PIN = '1234';

interface FakeCard {
  tokens?: Pkcs11Token[];
  keys?: Pkcs11PrivateKeyInfo[];
  certs?: Pkcs11CertificateInfo[];
  mechanisms?: number[];
  login?: jest.Mock;
}

const token = (
  label = 'card',
  flags = CKF_LOGIN_REQUIRED,
  serial = `${label}-serial`
): Pkcs11Token => ({
  slot: Buffer.from(serial),
  label,
  serial,
  flags
});

const key = (
  label: string,
  id?: string,
  keyType = CKK_EC
): Pkcs11PrivateKeyInfo => ({
  handle: Buffer.from(label),
  label,
  id: id === undefined ? undefined : Buffer.from(id, 'hex'),
  keyType
});

const certificate = (label: string, id?: string): Pkcs11CertificateInfo => ({
  handle: Buffer.from(`cert ${label}`),
  label,
  id: id === undefined ? undefined : Buffer.from(id, 'hex'),
  value: Buffer.from(`not a DER certificate: ${label}`)
});

const PIV_CERT_LABEL = 'X.509 Certificate for PIV Authentication';
const PIV_ATTESTATION_LABEL = 'X.509 Certificate for PIV Attestation 9a';

const matches = (
  object: { label?: string; id?: Buffer },
  filter: { label?: string; id?: Buffer }
): boolean =>
  (filter.label === undefined || object.label === filter.label) &&
  (filter.id === undefined || !!object.id?.equals(filter.id));

const fakeModule = ({
  tokens = [token()],
  keys = [key('client', '01')],
  certs = [certificate('client', '01')],
  mechanisms = [CKM_RSA_PKCS_PSS],
  login = jest.fn()
}: FakeCard = {}) => ({
  tokens: jest.fn(() => tokens),
  mechanisms: jest.fn(() => mechanisms),
  openSession: jest.fn(() => Buffer.from('session')),
  closeSession: jest.fn(),
  login,
  findPrivateKeys: jest.fn((_: Buffer, filter) =>
    keys.filter((k) => matches(k, filter))
  ),
  findCertificates: jest.fn((_: Buffer, filter) =>
    certs.filter((c) => matches(c, filter))
  )
});

const descriptor = (overrides: Partial<Pkcs11Cert> = {}): Pkcs11Cert => ({
  hostname: 'example.com',
  pinEnv: 'CARD_PIN',
  cert: 'token',
  maxConcurrency: 1,
  ...overrides
});

describe('Pkcs11Preflight', () => {
  const target = { module: MODULE, provider: 'pkcs11prov' };
  const env = { CARD_PIN: PIN };

  const create = (
    module: Pkcs11Module,
    options: {
      now?: () => number;
      readFile?: (path: string) => string;
    } = {}
  ) => {
    const loader: Pkcs11ModuleLoader = { load: jest.fn(() => module) };

    return {
      loader,
      preflight: new Pkcs11Preflight(loader, target, {
        env,
        retryAfterMs: 1000,
        ...options
      })
    };
  };

  describe('identity', () => {
    it('should resolve the key and the certificate on the token', async () => {
      // arrange
      const { preflight } = create(fakeModule());

      // act
      const identity = await preflight.identity(descriptor());

      // assert
      expect(identity).toEqual({
        provider: 'pkcs11prov',
        keyUri:
          'pkcs11:token=card;serial=card-serial;id=%01;object=client;type=private?pin-value=1234',
        certificate: Buffer.from('not a DER certificate: client'),
        certFile: undefined,
        tls12Only: false
      });
    });

    it('should log in once for concurrent callers', async () => {
      // arrange
      const module = fakeModule();
      const { preflight } = create(module);
      const cert = descriptor();

      // act
      await Promise.all(
        Array.from({ length: 5 }, () => preflight.identity(cert))
      );
      await preflight.identity(cert);

      // assert
      expect(module.login).toHaveBeenCalledTimes(1);
      expect(module.login).toHaveBeenCalledWith(expect.any(Buffer), PIN);
    });

    it('should share one login between certificates on the same token', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('a', '01'), key('b', '02')],
        certs: [certificate('a', '01'), certificate('b', '02')]
      });
      const { preflight } = create(module);

      // act
      await preflight.identity(descriptor({ object: 'a' }));
      await preflight.identity(
        descriptor({ hostname: 'other.com', object: 'b' })
      );

      // assert
      expect(module.login).toHaveBeenCalledTimes(1);
    });

    it('should never retry a rejected PIN', async () => {
      // arrange
      const module = fakeModule({
        login: jest.fn(() => {
          throw new Pkcs11ModuleError('CKR_PIN_INCORRECT');
        })
      });
      let now = 0;
      const { preflight } = create(module, { now: () => now });
      const cert = descriptor();

      // act
      const first = preflight.identity(cert);
      await expect(first).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_INCORRECT,
        retryable: false
      });
      now = 60_000;
      const second = preflight.identity(cert);
      const sibling = preflight.identity(descriptor({ hostname: 'other.com' }));

      // assert
      await expect(second).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_INCORRECT
      });
      await expect(sibling).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_INCORRECT
      });
      expect(module.login).toHaveBeenCalledTimes(1);
      expect(module.closeSession).toHaveBeenCalledTimes(1);
    });

    it('should not retry a login that failed with a generic error', async () => {
      // arrange
      const module = fakeModule({
        login: jest.fn(() => {
          throw new Pkcs11ModuleError('CKR_FUNCTION_FAILED');
        })
      });
      let now = 0;
      const { preflight } = create(module, { now: () => now });
      const cert = descriptor();
      await expect(preflight.identity(cert)).rejects.toMatchObject({
        code: Pkcs11ErrorCode.TOKEN_NOT_FOUND,
        retryable: false
      });

      // act
      now = 60_000;
      const result = preflight.identity(descriptor({ hostname: 'other.com' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.TOKEN_NOT_FOUND
      });
      expect(module.login).toHaveBeenCalledTimes(1);
    });

    it('should reject a second entry on the same token with a different PIN', async () => {
      // arrange
      const module = fakeModule();
      const { preflight } = create(module, { readFile: () => '9999' });
      await preflight.identity(descriptor());

      // act
      const result = preflight.identity(
        descriptor({
          hostname: 'other.com',
          pinEnv: undefined,
          pinFile: '/run/other-pin'
        })
      );

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_INCORRECT,
        message: expect.stringContaining('different PIN')
      });
      expect(module.login).toHaveBeenCalledTimes(1);
    });

    it('should refuse to choose between tokens with the same label', async () => {
      // arrange
      const module = fakeModule({
        tokens: [
          token('PIV Card', CKF_LOGIN_REQUIRED, 'A1'),
          token('PIV Card', CKF_LOGIN_REQUIRED, 'B2')
        ]
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor({ token: 'PIV Card' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.TOKEN_NOT_FOUND,
        message:
          'Several tokens are labelled "PIV Card" (serials A1, B2); leave only one of them connected.'
      });
      expect(module.login).not.toHaveBeenCalled();
    });

    it('should report a loader error as it is', async () => {
      // arrange
      const error = new Pkcs11Error(
        Pkcs11ErrorCode.MODULE_LOAD_FAILED,
        'The pkcs11js native addon is not available'
      );
      const loader: Pkcs11ModuleLoader = {
        load: jest.fn(() => {
          throw error;
        })
      };
      const preflight = new Pkcs11Preflight(loader, target, {
        env
      });

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toBe(error);
    });

    it('should not put the PIN into the error message', async () => {
      // arrange
      const module = fakeModule({
        login: jest.fn(() => {
          throw new Pkcs11ModuleError('CKR_PIN_INCORRECT', `bad pin ${PIN}`);
        })
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toThrow(
        expect.objectContaining({
          message: expect.not.stringContaining(PIN)
        })
      );
    });

    it.each([
      { flag: CKF_USER_PIN_LOCKED, name: 'locked' },
      { flag: CKF_USER_PIN_FINAL_TRY, name: 'on its final try' }
    ])(
      'should refuse to log in when the PIN is $name',
      async ({ flag }: { flag: number }) => {
        // arrange
        const module = fakeModule({
          tokens: [token('card', CKF_LOGIN_REQUIRED + flag)]
        });
        const { preflight } = create(module);

        // act
        const result = preflight.identity(descriptor());

        // assert
        await expect(result).rejects.toMatchObject({
          code: Pkcs11ErrorCode.PIN_LOCKED
        });
        expect(module.openSession).not.toHaveBeenCalled();
        expect(module.login).not.toHaveBeenCalled();
      }
    );

    it('should treat an already logged-in token as logged in', async () => {
      // arrange
      const module = fakeModule({
        login: jest.fn(() => {
          throw new Pkcs11ModuleError('CKR_USER_ALREADY_LOGGED_IN');
        })
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).resolves.toMatchObject({ provider: 'pkcs11prov' });
    });

    it('should skip the login when the token does not require one', async () => {
      // arrange
      const module = fakeModule({ tokens: [token('card', 0)] });
      const { preflight } = create(module);

      // act
      await preflight.identity(descriptor());

      // assert
      expect(module.login).not.toHaveBeenCalled();
    });

    it('should retry a retryable failure only after the retry delay', async () => {
      // arrange
      const tokens: Pkcs11Token[] = [];
      const module = fakeModule({ tokens });
      let now = 0;
      const { preflight } = create(module, { now: () => now });
      const cert = descriptor();
      await expect(preflight.identity(cert)).rejects.toMatchObject({
        code: Pkcs11ErrorCode.TOKEN_NOT_FOUND,
        retryable: true
      });
      tokens.push(token());

      // act
      now = 500;
      const early = preflight.identity(cert);
      await expect(early).rejects.toMatchObject({
        code: Pkcs11ErrorCode.TOKEN_NOT_FOUND
      });
      now = 1500;
      const late = preflight.identity(cert);

      // assert
      await expect(late).resolves.toMatchObject({ provider: 'pkcs11prov' });
      expect(module.tokens).toHaveBeenCalledTimes(2);
    });

    it('should list the tokens found when the configured one is missing', async () => {
      // arrange
      const module = fakeModule({ tokens: [token('a'), token('bb')] });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor({ token: 'c' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.TOKEN_NOT_FOUND,
        message: 'Token "c" not found; found: "a", "bb".'
      });
    });

    it('should require "token" when several tokens are present', async () => {
      // arrange
      const module = fakeModule({ tokens: [token('a'), token('bb')] });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.TOKEN_NOT_FOUND,
        message: expect.stringContaining('Set "token"')
      });
    });

    it('should report a module that cannot be loaded', async () => {
      // arrange
      const loader: Pkcs11ModuleLoader = {
        load: jest.fn(() => {
          throw new Pkcs11ModuleError(
            'CKR_LIBRARY_LOAD_FAILED',
            'no such file'
          );
        })
      };
      const preflight = new Pkcs11Preflight(loader, target, {
        env
      });

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.MODULE_LOAD_FAILED,
        message: `Cannot load the PKCS#11 module ${MODULE}: no such file`
      });
    });

    it('should report a missing PIN environment variable without opening a session', async () => {
      // arrange
      const module = fakeModule();
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor({ pinEnv: 'MISSING_PIN' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_UNAVAILABLE
      });
      expect(module.openSession).not.toHaveBeenCalled();
    });

    it('should strip the trailing newline from the PIN file', async () => {
      // arrange
      const module = fakeModule();
      const { preflight } = create(module, {
        readFile: () => `${PIN}\r\n`
      });

      // act
      await preflight.identity(
        descriptor({ pinEnv: undefined, pinFile: '/run/pin' })
      );

      // assert
      expect(module.login).toHaveBeenCalledWith(expect.any(Buffer), PIN);
    });

    it('should choose the only key that has a certificate', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('orphan', '09'), key('client', '01')],
        certs: [certificate('client', '01')]
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor());

      // assert
      expect(identity.keyUri).toContain('id=%01;');
    });

    it('should fall back to the PIV authentication key', async () => {
      // arrange
      const module = fakeModule({
        keys: [
          key('Private key for Digital Signature', '02'),
          key(Pkcs11Preflight.PIV_KEY_LABEL, '01')
        ],
        certs: [
          certificate('X.509 Certificate for Digital Signature', '02'),
          certificate(PIV_CERT_LABEL, '01')
        ]
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor());

      // assert
      expect(identity.keyUri).toContain('id=%01;');
      expect(identity.certificate).toEqual(
        certificate(PIV_CERT_LABEL, '01').value
      );
    });

    it('should find the PIV certificate by label when the key has no id', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('other'), key(Pkcs11Preflight.PIV_KEY_LABEL)],
        certs: [certificate(PIV_CERT_LABEL, '01')]
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor());

      // assert
      expect(identity.certificate).toEqual(
        certificate(PIV_CERT_LABEL, '01').value
      );
    });

    it('should choose the PIV authentication certificate over the attestation certificate with the same id', async () => {
      // arrange
      const module = fakeModule({
        keys: [key(Pkcs11Preflight.PIV_KEY_LABEL, '01', CKK_RSA)],
        certs: [
          certificate(PIV_ATTESTATION_LABEL, '01'),
          certificate(PIV_CERT_LABEL, '01')
        ]
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor({ id: '01' }));

      // assert
      expect(identity.certificate).toEqual(
        certificate(PIV_CERT_LABEL, '01').value
      );
    });

    it('should choose the certificate labelled like the key among those with its id', async () => {
      // arrange
      const module = fakeModule({
        certs: [certificate('other', '01'), certificate('client', '01')]
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor());

      // assert
      expect(identity.certificate).toEqual(certificate('client', '01').value);
    });

    it('should refuse to choose between certificates with the id and label of the key', async () => {
      // arrange
      const module = fakeModule({
        certs: [certificate('client', '01'), certificate('client', '01')]
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message:
          'Several certificates belong to key "client" (id 01): "client" (id 01), "client" (id 01); set "cert" to a PEM file with the one example.com accepts.'
      });
    });

    it('should refuse a selector that matches several keys', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('client', '01'), key('client', '02')],
        certs: [certificate('client', '01'), certificate('client', '02')]
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor({ object: 'client' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message:
          'Several private keys have label "client": "client" (id 01), "client" (id 02); set both "object" and "id" to choose one.'
      });
    });

    it('should refuse a key whose id and label another key shares', async () => {
      // arrange
      const module = fakeModule({
        keys: [
          key(Pkcs11Preflight.PIV_KEY_LABEL, '01'),
          key(Pkcs11Preflight.PIV_KEY_LABEL, '01')
        ],
        certs: [certificate(PIV_CERT_LABEL, '01')]
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message: `Several private keys on the token share the id and label of "${Pkcs11Preflight.PIV_KEY_LABEL}" (id 01), so the OpenSSL provider cannot tell them apart.`
      });
    });

    it('should list the keys when it cannot choose one', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('a', '01'), key('b', '02')],
        certs: [certificate('a', '01'), certificate('b', '02')]
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message:
          'Cannot choose a private key; set "object" or "id". Keys found: "a" (id 01), "b" (id 02).'
      });
    });

    it('should use the key selected by "id"', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('a', '01'), key('b', '02')],
        certs: [certificate('a', '01'), certificate('b', '02')]
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor({ id: '02' }));

      // assert
      expect(identity.keyUri).toContain('id=%02;');
      expect(module.findPrivateKeys).toHaveBeenCalledWith(expect.any(Buffer), {
        label: undefined,
        id: Buffer.from([2])
      });
    });

    it('should report a selector that matches no key', async () => {
      // arrange
      const { preflight } = create(fakeModule());

      // act
      const result = preflight.identity(descriptor({ object: 'missing' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message: 'No private key with label "missing" on the token.'
      });
    });

    it('should report a key without a certificate on the token', async () => {
      // arrange
      const module = fakeModule({ certs: [] });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor({ object: 'client' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message: expect.stringContaining('set "cert" to a PEM file')
      });
    });

    it('should use the certificate file when "cert" is a path', async () => {
      // arrange
      const module = fakeModule({ certs: [] });
      const { preflight } = create(module, { readFile: () => 'PEM' });

      // act
      const identity = await preflight.identity(
        descriptor({ cert: '/etc/client.pem' })
      );

      // assert
      expect(identity).toMatchObject({
        certificate: undefined,
        certFile: '/etc/client.pem'
      });
    });

    it.each([
      { keyType: CKK_RSA, mechanisms: [], tls12Only: true },
      { keyType: CKK_RSA, mechanisms: [CKM_RSA_PKCS_PSS], tls12Only: false },
      { keyType: CKK_EC, mechanisms: [], tls12Only: false }
    ])(
      'should set tls12Only to $tls12Only for key type $keyType with mechanisms $mechanisms',
      async ({
        keyType,
        mechanisms,
        tls12Only
      }: {
        keyType: number;
        mechanisms: number[];
        tls12Only: boolean;
      }) => {
        // arrange
        const module = fakeModule({
          keys: [key('client', '01', keyType)],
          mechanisms
        });
        const { preflight } = create(module);

        // act
        const identity = await preflight.identity(descriptor());

        // assert
        expect(identity.tls12Only).toBe(tls12Only);
      }
    );

    it('should wrap an unexpected failure into a retryable error', async () => {
      // arrange
      const module = fakeModule();
      module.findPrivateKeys.mockImplementation(() => {
        throw new Error('boom');
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toBeInstanceOf(Pkcs11Error);
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.MODULE_LOAD_FAILED,
        retryable: true
      });
    });
  });
});
