import { Pkcs11Preflight } from './Pkcs11Preflight';
import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import {
  Pkcs11CertificateInfo,
  Pkcs11Module,
  Pkcs11ModuleError,
  Pkcs11ModuleLoader,
  Pkcs11PrivateKeyInfo,
  Pkcs11PublicKeyAttributes,
  Pkcs11Token
} from './Pkcs11Module';
import { Pkcs11PinStore } from './Pkcs11PinStore';
import {
  ATTESTATION,
  CLIENT,
  EC_CLIENT,
  OTHER
} from './__fixtures__/certificates';
import { Pkcs11Cert } from '../Pkcs11Cert';
import { X509Certificate } from 'node:crypto';

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
  publicKeys?: Map<Pkcs11PrivateKeyInfo, Pkcs11PublicKeyAttributes>;
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

const der = (pem: string): Buffer => new X509Certificate(pem).raw;

// Without a PEM, the value cannot be parsed, as with a token that stores
// something other than X.509; the key is then found by id alone.
const certificate = (
  label: string,
  id?: string,
  pem?: string
): Pkcs11CertificateInfo => ({
  handle: Buffer.from(`cert ${label}`),
  label,
  id: id === undefined ? undefined : Buffer.from(id, 'hex'),
  value: pem ? der(pem) : Buffer.from(`not a DER certificate: ${label}`)
});

// DER of the P-256 named-curve OID (1.2.840.10045.3.1.7).
const P256 = Buffer.from('06082a8648ce3d030107', 'hex');

const publicHalf = (pem: string): Pkcs11PublicKeyAttributes => {
  const jwk = new X509Certificate(pem).publicKey.export({ format: 'jwk' });
  const bytes = (value?: string) => Buffer.from(value ?? '', 'base64url');

  return jwk.kty === 'RSA'
    ? { modulus: bytes(jwk.n), publicExponent: bytes(jwk.e) }
    : {
        ecParams: P256,
        // DER OCTET STRING around the uncompressed point, as PKCS#11 specifies
        ecPoint: Buffer.concat([
          Buffer.from([0x04, 0x41, 0x04]),
          bytes(jwk.x),
          bytes(jwk.y)
        ])
      };
};

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
  login = jest.fn(),
  publicKeys = new Map()
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
  ),
  publicKeyAttributes: jest.fn(
    (_: Buffer, k: Pkcs11PrivateKeyInfo) => publicKeys.get(k) ?? {}
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
      platform?: NodeJS.Platform;
      pins?: Pkcs11PinStore;
      moduleHint?: string;
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
    const hint = 'The PKCS#11 library C:/x.dll was selected automatically.';

    it('should append the module hint when the wanted token is missing', async () => {
      // arrange
      const { preflight } = create(fakeModule({ tokens: [] }), {
        moduleHint: hint
      });

      // act
      const result = preflight.identity(descriptor({ token: 'card' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.TOKEN_NOT_FOUND,
        retryable: true,
        message: expect.stringMatching(
          /^Token "card" not found; .* The PKCS#11 library C:\/x\.dll was selected automatically\.$/
        )
      });
    });

    it('should not append the module hint to a rejected PIN', async () => {
      // arrange
      const module = fakeModule({
        login: jest.fn(() => {
          throw new Pkcs11ModuleError('CKR_PIN_INCORRECT');
        })
      });
      const { preflight } = create(module, { moduleHint: hint });

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_INCORRECT,
        message: expect.not.stringContaining(hint)
      });
    });

    it('should leave messages unchanged without a module hint', async () => {
      // arrange
      const { preflight } = create(fakeModule({ tokens: [] }));

      // act
      const result = preflight.identity(descriptor({ token: 'card' }));

      // assert
      await expect(result).rejects.toMatchObject({
        message:
          'Token "card" not found; no token is present (is the card inserted?).'
      });
    });

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
      await preflight.identity(descriptor({ label: 'a' }));
      await preflight.identity(
        descriptor({ hostname: 'other.com', label: 'b' })
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

    it('should log in with the PIN typed at startup for an entry without a PIN source', async () => {
      // arrange
      const module = fakeModule();
      const pins = new Pkcs11PinStore();
      const cert = descriptor({ pinEnv: undefined });
      pins.set(cert, '5678');
      const { preflight } = create(module, { pins });

      // act
      const identity = await preflight.identity(cert);

      // assert
      expect(module.login).toHaveBeenCalledWith(expect.any(Buffer), '5678');
      expect(identity.keyUri).toContain('?pin-value=5678');
    });

    it('should not retry an entry whose PIN was not typed at startup', async () => {
      // arrange
      const module = fakeModule();
      let now = 0;
      const { preflight } = create(module, {
        now: () => now,
        pins: new Pkcs11PinStore()
      });
      const cert = descriptor({ pinEnv: undefined });
      await expect(preflight.identity(cert)).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_UNAVAILABLE,
        retryable: false,
        message: expect.stringContaining('asks only then')
      });
      now = 60_000;

      // act
      const result = preflight.identity(cert);

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.PIN_UNAVAILABLE
      });
      expect(module.openSession).not.toHaveBeenCalled();
    });

    it('should select the certificate by "label" and use the key holding its public key', async () => {
      // arrange
      const authKey = key(Pkcs11Preflight.PIV_KEY_LABEL, '01', CKK_RSA);
      const module = fakeModule({
        keys: [authKey],
        certs: [
          certificate(PIV_ATTESTATION_LABEL, '01', ATTESTATION),
          certificate(PIV_CERT_LABEL, '01', CLIENT)
        ],
        publicKeys: new Map([[authKey, publicHalf(CLIENT)]])
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(
        descriptor({ label: PIV_CERT_LABEL })
      );

      // assert
      expect(identity.certificate).toEqual(der(CLIENT));
      expect(identity.keyUri).toContain('id=%01;');
      expect(module.findCertificates).toHaveBeenCalledWith(expect.any(Buffer), {
        label: PIV_CERT_LABEL,
        id: undefined
      });
    });

    it('should select the certificate by "id"', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('a', '01'), key('b', '02')],
        certs: [certificate('a', '01'), certificate('b', '02')]
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor({ id: '02' }));

      // assert
      expect(identity.certificate).toEqual(certificate('b', '02').value);
      expect(identity.keyUri).toContain('id=%02;');
    });

    it('should choose the PIV authentication certificate on a YubiKey with attestation certificates', async () => {
      // arrange
      const authKey = key(Pkcs11Preflight.PIV_KEY_LABEL, '01', CKK_RSA);
      const signKey = key('Private key for Digital Signature', '02', CKK_RSA);
      const module = fakeModule({
        keys: [authKey, signKey],
        certs: [
          certificate(PIV_ATTESTATION_LABEL, '01', ATTESTATION),
          certificate(PIV_CERT_LABEL, '01', CLIENT),
          certificate('X.509 Certificate for PIV Attestation 9c', '02', OTHER),
          certificate('X.509 Certificate for Digital Signature', '02', OTHER)
        ],
        publicKeys: new Map([
          [authKey, publicHalf(CLIENT)],
          [signKey, publicHalf(OTHER)]
        ])
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor());

      // assert
      expect(identity.certificate).toEqual(der(CLIENT));
      expect(identity.keyUri).toContain('id=%01;');
    });

    it('should choose the certificate labelled like its key among several with the key id', async () => {
      // arrange
      const module = fakeModule({
        certs: [certificate('other', '01'), certificate('client', '01')]
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor({ id: '01' }));

      // assert
      expect(identity.certificate).toEqual(certificate('client', '01').value);
    });

    it('should use the key holding the certificate public key when their ids differ', async () => {
      // arrange
      const holder = key('holder', '09', CKK_RSA);
      const module = fakeModule({
        keys: [key('stranger', '01', CKK_RSA), holder],
        certs: [certificate('client', '01', CLIENT)],
        publicKeys: new Map([[holder, publicHalf(CLIENT)]])
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor());

      // assert
      expect(identity.keyUri).toContain('id=%09;object=holder;');
    });

    it('should match an EC key through its public key object', async () => {
      // arrange
      const ecKey = key('ec', '05');
      const module = fakeModule({
        keys: [ecKey],
        certs: [certificate('client-ec', '07', EC_CLIENT)],
        publicKeys: new Map([[ecKey, publicHalf(EC_CLIENT)]])
      });
      const { preflight } = create(module);

      // act
      const identity = await preflight.identity(descriptor());

      // assert
      expect(identity.keyUri).toContain('id=%05;');
      expect(identity.certificate).toEqual(der(EC_CLIENT));
    });

    it('should refuse a certificate whose key with the same id holds another public key', async () => {
      // arrange
      const stranger = key('client', '01', CKK_RSA);
      const module = fakeModule({
        keys: [stranger],
        certs: [certificate('client', '01', CLIENT)],
        publicKeys: new Map([[stranger, publicHalf(OTHER)]])
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message: expect.stringMatching(
          /^No private key on token "card" holds the public key of certificate "client" \(id 01\), subject "CN=client", issuer "CN=Test CA", valid until .+ GMT\.$/
        )
      });
    });

    it('should explain an ambiguous choice with an example that selects one by "label"', async () => {
      // arrange
      const module = fakeModule({
        certs: [
          certificate('client 2026', '01'),
          certificate('client 2027', '01')
        ]
      });
      const { preflight } = create(module, { platform: 'linux' });

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message: [
          'Several certificates on token "card" can be used for example.com:',
          '  1. "client 2026" (id 01)',
          '  2. "client 2027" (id 01)',
          'Choose one with "label" and restart the Repeater, for example:',
          `  --pkcs11-cert '{"hostname":"example.com","pinEnv":"CARD_PIN","label":"client 2026"}'`
        ].join('\n')
      });
    });

    it('should quote the example for cmd.exe on Windows', async () => {
      // arrange
      const module = fakeModule({
        certs: [
          certificate('client 2026', '01'),
          certificate('client 2027', '01')
        ]
      });
      const { preflight } = create(module, {
        platform: 'win32',
        readFile: () => PIN
      });

      // act
      const result = preflight.identity(
        descriptor({ pinEnv: undefined, pinFile: 'C:\\card\\pin.txt' })
      );

      // assert
      await expect(result).rejects.toMatchObject({
        message: expect.stringContaining(
          '--pkcs11-cert "{\\"hostname\\":\\"example.com\\",\\"pinFile\\":\\"C:\\\\card\\\\pin.txt\\",\\"label\\":\\"client 2026\\"}"'
        )
      });
    });

    it('should keep the other fields of the entry in the example', async () => {
      // arrange
      const module = fakeModule({
        certs: [
          certificate('client 2026', '01'),
          certificate('client 2027', '01')
        ]
      });
      const { preflight } = create(module, { platform: 'linux' });

      // act
      const result = preflight.identity(
        descriptor({ port: '8443', token: 'card', id: '01', maxConcurrency: 2 })
      );

      // assert
      await expect(result).rejects.toMatchObject({
        message: expect.stringContaining(
          `--pkcs11-cert '{"hostname":"example.com","port":"8443","pinEnv":"CARD_PIN","token":"card","id":"01","label":"client 2026","maxConcurrency":2}'`
        )
      });
    });

    it('should suggest "id" when the candidates share a label', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('client', '01'), key('client', '02')],
        certs: [certificate('client', '01'), certificate('client', '02')]
      });
      const { preflight } = create(module, { platform: 'linux' });

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        message: expect.stringContaining(
          `Choose one with "id" and restart the Repeater, for example:\n  --pkcs11-cert '{"hostname":"example.com","pinEnv":"CARD_PIN","id":"01"}'`
        )
      });
    });

    it('should suggest a certificate file when the candidates share both id and label', async () => {
      // arrange
      const module = fakeModule({
        certs: [certificate('client', '01'), certificate('client', '01')]
      });
      const { preflight } = create(module);

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        message: expect.stringContaining(
          'Their labels and ids are the same; set "cert" to a PEM file with the one example.com accepts and restart the Repeater.'
        )
      });
    });

    it('should list the certificates on the token when the selector matches none', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('a', '01'), key('b', '02')],
        certs: [certificate('a', '01'), certificate('b', '02')]
      });
      const { preflight } = create(module, { platform: 'linux' });

      // act
      const result = preflight.identity(descriptor({ label: 'missing' }));

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message: [
          'No certificate with label "missing" on token "card".',
          'Certificates on the token:',
          '  1. "a" (id 01)',
          '  2. "b" (id 02)',
          'Choose one with "label" and restart the Repeater, for example:',
          `  --pkcs11-cert '{"hostname":"example.com","pinEnv":"CARD_PIN","label":"a"}'`
        ].join('\n')
      });
    });

    it('should report a token without certificates', async () => {
      // arrange
      const { preflight } = create(fakeModule({ certs: [] }));

      // act
      const result = preflight.identity(descriptor());

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message:
          'Token "card" holds no certificates. Set "cert" to a PEM file with the certificate for example.com.'
      });
    });

    it('should refuse a key whose id and label another key shares', async () => {
      // arrange
      const holder = key(Pkcs11Preflight.PIV_KEY_LABEL, '01', CKK_RSA);
      const twin = key(Pkcs11Preflight.PIV_KEY_LABEL, '01', CKK_RSA);
      const module = fakeModule({
        keys: [holder, twin],
        certs: [certificate(PIV_CERT_LABEL, '01', CLIENT)],
        publicKeys: new Map([
          [holder, publicHalf(CLIENT)],
          [twin, publicHalf(OTHER)]
        ])
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

    it('should use a certificate file with the key holding its public key', async () => {
      // arrange
      const holder = key('b', '02', CKK_RSA);
      const other = key('a', '01', CKK_RSA);
      const module = fakeModule({
        keys: [other, holder],
        certs: [],
        publicKeys: new Map([
          [other, publicHalf(OTHER)],
          [holder, publicHalf(CLIENT)]
        ])
      });
      const { preflight } = create(module, { readFile: () => CLIENT });

      // act
      const identity = await preflight.identity(
        descriptor({ cert: '/etc/client.pem' })
      );

      // assert
      expect(identity).toMatchObject({
        keyUri: expect.stringContaining('id=%02;'),
        certificate: undefined,
        certFile: '/etc/client.pem'
      });
    });

    it('should narrow the keys by "id" for a certificate file when the token hides their public keys', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('a', '01'), key('b', '02')],
        certs: []
      });
      const { preflight } = create(module, { readFile: () => CLIENT });

      // act
      const identity = await preflight.identity(
        descriptor({ cert: '/etc/client.pem', id: '02' })
      );

      // assert
      expect(identity.keyUri).toContain('id=%02;');
    });

    it('should explain which keys may belong to a certificate file', async () => {
      // arrange
      const module = fakeModule({
        keys: [key('a', '01'), key('b', '02')],
        certs: []
      });
      const { preflight } = create(module, {
        readFile: () => CLIENT,
        platform: 'linux'
      });

      // act
      const result = preflight.identity(
        descriptor({ cert: '/etc/client.pem' })
      );

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message: [
          'Several private keys on token "card" may belong to the certificate in /etc/client.pem, and the token does not expose their public keys to tell:',
          '  1. "a" (id 01)',
          '  2. "b" (id 02)',
          'Choose one with "label" and restart the Repeater, for example:',
          `  --pkcs11-cert '{"hostname":"example.com","pinEnv":"CARD_PIN","label":"a","cert":"/etc/client.pem"}'`
        ].join('\n')
      });
    });

    it('should report a certificate file whose public key no key on the token holds', async () => {
      // arrange
      const other = key('a', '01', CKK_RSA);
      const module = fakeModule({
        keys: [other],
        certs: [],
        publicKeys: new Map([[other, publicHalf(OTHER)]])
      });
      const { preflight } = create(module, { readFile: () => CLIENT });

      // act
      const result = preflight.identity(
        descriptor({ cert: '/etc/client.pem' })
      );

      // assert
      await expect(result).rejects.toMatchObject({
        code: Pkcs11ErrorCode.KEY_NOT_FOUND,
        message:
          'No private key on token "card" holds the public key of the certificate in /etc/client.pem. Keys found:\n  1. "a" (id 01)'
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

  describe('requiresPin', () => {
    it.each([
      { flags: CKF_LOGIN_REQUIRED, expected: true },
      { flags: 0, expected: false }
    ])(
      'should return $expected for token flags $flags without opening a session',
      ({ flags, expected }) => {
        // arrange
        const module = fakeModule({ tokens: [token('card', flags)] });
        const { preflight } = create(module);

        // act
        const result = preflight.requiresPin(descriptor({ pinEnv: undefined }));

        // assert
        expect(result).toBe(expected);
        expect(module.openSession).not.toHaveBeenCalled();
      }
    );

    it('should throw when the token is not present', () => {
      // arrange
      const { preflight } = create(fakeModule({ tokens: [] }));

      // act
      const act = () =>
        preflight.requiresPin(descriptor({ pinEnv: undefined }));

      // assert
      expect(act).toThrow(
        expect.objectContaining({ code: Pkcs11ErrorCode.TOKEN_NOT_FOUND })
      );
    });
  });
});
