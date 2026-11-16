import { BinaryArch } from './BinaryArch';
import { DefaultPkcs11ModuleLocator } from './Pkcs11ModuleLocator';
import { Pkcs11ModuleNotFoundError } from './Pkcs11ModuleNotFoundError';
import { Pkcs11ProbeResult } from './Pkcs11ModuleProbe';
import { Pkcs11Cert } from '../Pkcs11Cert';
import { logger } from '../../Utils';

describe('DefaultPkcs11ModuleLocator', () => {
  const env: NodeJS.ProcessEnv = {
    'ProgramFiles': 'C:\\Program Files',
    'ProgramFiles(x86)': 'C:\\Program Files (x86)',
    'SystemRoot': 'C:\\Windows'
  };
  const SAC_IDPRIME =
    'C:\\Program Files\\SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS1164.dll';
  const SAC_IDPRIME_32 =
    'C:\\Program Files\\SafeNet\\Authentication\\SAC\\x32\\IDPrimePKCS11.dll';
  const SAC_ETOKEN = 'C:\\Windows\\System32\\eTPKCS11.dll';
  const IDGO =
    'C:\\Program Files (x86)\\Gemalto\\IDGo 800 PKCS#11\\IDPrimePKCS1164.dll';
  const YUBICO =
    'C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll';
  const BIT4ID_X = 'C:\\Windows\\System32\\bit4xpki.dll';
  const BIT4ID_I = 'C:\\Windows\\System32\\bit4ipki.dll';
  const OPENSC =
    'C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll';

  const cert = (overrides: Partial<Pkcs11Cert> = {}): Pkcs11Cert => ({
    hostname: 'example.com',
    pinEnv: 'CARD_PIN',
    maxConcurrency: 1,
    ...overrides
  });

  const loaded = (...labels: string[]): Pkcs11ProbeResult => ({
    ok: true,
    library: 'Vendor PKCS#11',
    tokens: labels.map((label: string, i: number) => ({
      label,
      serial: String(i)
    }))
  });

  const failed = (
    reason: 'missing-dependency' | 'crashed' | 'timeout' | 'init-failed',
    detail: string
  ): Pkcs11ProbeResult => ({ ok: false, reason, detail });

  // Files on the fake machine: path → architecture, and what probing each x64 file returns.
  const machine = (
    files: Record<string, BinaryArch>,
    results: Record<string, Pkcs11ProbeResult> = {}
  ) => {
    const probe = jest.fn(
      (path: string, _env: NodeJS.ProcessEnv): Pkcs11ProbeResult =>
        results[path] ?? loaded()
    );
    const locator = new DefaultPkcs11ModuleLocator({
      platform: 'win32',
      env: { ...env, CARD_PIN: '1234' },
      exists: (path: string) => path in files,
      readArch: (path: string) => files[path],
      probe
    });

    return { locator, probe };
  };

  let log: jest.SpyInstance;
  let warn: jest.SpyInstance;

  beforeEach(() => {
    log = jest.spyOn(logger, 'log').mockImplementation();
    warn = jest.spyOn(logger, 'warn').mockImplementation();
    jest.spyOn(logger, 'debug').mockImplementation();
  });

  afterEach(() => jest.restoreAllMocks());

  describe('locate', () => {
    it('should connect the SafeNet Authentication Client IDPrime library and log it', () => {
      // arrange
      const { locator } = machine(
        { [SAC_IDPRIME]: 'x64' },
        { [SAC_IDPRIME]: loaded('card') }
      );

      // act
      const result = locator.locate([cert()]);

      // assert
      expect(result).toEqual({
        path: SAC_IDPRIME,
        product: 'Thales SafeNet Authentication Client (IDPrime)',
        library: 'Vendor PKCS#11',
        tokens: [{ label: 'card', serial: '0' }],
        alternatives: []
      });
      expect(log).toHaveBeenCalledWith(
        `PKCS#11: --pkcs11-module is not set; connected the Thales SafeNet Authentication Client (IDPrime) library ${SAC_IDPRIME} (1 token present). To keep this choice, pass --pkcs11-module "${SAC_IDPRIME}".`
      );
      expect(warn).not.toHaveBeenCalled();
    });

    it('should prefer a later library that shows a token over an earlier one that does not', () => {
      // arrange
      const { locator } = machine(
        { [SAC_IDPRIME]: 'x64', [OPENSC]: 'x64' },
        { [SAC_IDPRIME]: loaded(), [OPENSC]: loaded('PIV_II') }
      );

      // act
      const result = locator.locate([cert()]);

      // assert
      expect(result).toMatchObject({
        path: OPENSC,
        alternatives: [SAC_IDPRIME]
      });
      expect(log).toHaveBeenCalledWith(
        expect.stringContaining(
          `Other usable PKCS#11 libraries found: ${SAC_IDPRIME}.`
        )
      );
    });

    it('should pick the library that shows the token named in --pkcs11-cert', () => {
      // arrange
      const { locator } = machine(
        { [SAC_ETOKEN]: 'x64', [YUBICO]: 'x64' },
        { [SAC_ETOKEN]: loaded('eToken'), [YUBICO]: loaded('YubiKey PIV') }
      );

      // act
      const result = locator.locate([cert({ token: 'YubiKey PIV' })]);

      // assert
      expect(result.path).toBe(YUBICO);
    });

    it('should prefer a later library that shows every token named in --pkcs11-cert', () => {
      // arrange
      const { locator } = machine(
        { [SAC_ETOKEN]: 'x64', [OPENSC]: 'x64' },
        { [SAC_ETOKEN]: loaded('a'), [OPENSC]: loaded('a', 'b') }
      );

      // act
      const result = locator.locate([
        cert({ hostname: 'a.example.com', token: 'a' }),
        cert({ hostname: 'b.example.com', token: 'b' })
      ]);

      // assert
      expect(result).toMatchObject({
        path: OPENSC,
        alternatives: [SAC_ETOKEN]
      });
    });

    it('should pick the library that shows the most named tokens and warn about the rest', () => {
      // arrange
      const { locator } = machine(
        { [SAC_ETOKEN]: 'x64', [YUBICO]: 'x64' },
        { [SAC_ETOKEN]: loaded('a'), [YUBICO]: loaded('b', 'c') }
      );

      // act
      const result = locator.locate([
        cert({ token: 'a' }),
        cert({ token: 'b' }),
        cert({ token: 'c' })
      ]);

      // assert
      expect(result.path).toBe(YUBICO);
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining('no PKCS#11 library found shows token "a"')
      );
    });

    it("should try a product's next library when the first one does not show the token", () => {
      // arrange
      const { locator } = machine(
        { [BIT4ID_X]: 'x64', [BIT4ID_I]: 'x64' },
        { [BIT4ID_X]: loaded(), [BIT4ID_I]: loaded('card') }
      );

      // act
      const result = locator.locate([cert()]);

      // assert
      expect(result).toMatchObject({
        path: BIT4ID_I,
        product: 'Bit4id Universal Middleware',
        alternatives: [BIT4ID_X]
      });
    });

    it('should not pass the PIN variables of --pkcs11-cert to the probe', () => {
      // arrange
      const { locator, probe } = machine(
        { [SAC_IDPRIME]: 'x64' },
        { [SAC_IDPRIME]: loaded('card') }
      );

      // act
      locator.locate([cert({ pinEnv: 'card_pin' })]);

      // assert
      const probeEnv = probe.mock.calls[0][1];
      expect(probeEnv).toEqual(env);
    });

    it('should stop probing once a library shows a token', () => {
      // arrange
      const { locator, probe } = machine(
        { [SAC_IDPRIME]: 'x64', [OPENSC]: 'x64' },
        { [SAC_IDPRIME]: loaded('card') }
      );

      // act
      locator.locate([cert()]);

      // assert
      expect(probe).toHaveBeenCalledTimes(1);
    });

    it('should pick the first library that loads and warn when no token is present', () => {
      // arrange
      const { locator } = machine({ [SAC_ETOKEN]: 'x64', [OPENSC]: 'x64' });

      // act
      const result = locator.locate([cert()]);

      // assert
      expect(result).toMatchObject({
        path: SAC_ETOKEN,
        alternatives: [OPENSC]
      });
      expect(warn).toHaveBeenCalledWith(
        'PKCS#11: no token is present in the Thales SafeNet Authentication Client (eToken) library yet; insert the card.'
      );
    });

    it('should warn when no library shows the token named in --pkcs11-cert', () => {
      // arrange
      const { locator } = machine(
        { [SAC_IDPRIME]: 'x64' },
        { [SAC_IDPRIME]: loaded('card') }
      );

      // act
      const result = locator.locate([cert({ token: 'other' })]);

      // assert
      expect(result.path).toBe(SAC_IDPRIME);
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining('no PKCS#11 library found shows token "other"')
      );
    });

    it('should continue after a library that crashes or hangs', () => {
      // arrange
      const { locator } = machine(
        { [SAC_IDPRIME]: 'x64', [SAC_ETOKEN]: 'x64', [OPENSC]: 'x64' },
        {
          [SAC_IDPRIME]: failed('crashed', 'exited with code 0xC0000005'),
          [SAC_ETOKEN]: failed('timeout', 'no answer within 15 s'),
          [OPENSC]: loaded('card')
        }
      );

      // act
      const result = locator.locate([cert()]);

      // assert
      expect(result.path).toBe(OPENSC);
    });

    it('should never probe a file that is not x64', () => {
      // arrange
      const { locator, probe } = machine(
        { [SAC_IDPRIME]: 'x86', [SAC_IDPRIME_32]: 'x86', [OPENSC]: 'x64' },
        { [OPENSC]: loaded('card') }
      );

      // act
      locator.locate([cert()]);

      // assert
      expect(
        probe.mock.calls.map(([path]: [string, NodeJS.ProcessEnv]) => path)
      ).toEqual([OPENSC]);
    });

    it('should not probe a library whose path the OpenSSL config cannot hold', () => {
      // arrange
      const { locator, probe } = machine({ [IDGO]: 'x64' });

      // act
      const act = () => locator.locate([cert()]);

      // assert
      expect(act).toThrow(
        expect.objectContaining({
          message: expect.stringContaining(
            `- ${IDGO}: its path contains a character the OpenSSL PKCS#11 provider cannot read`
          )
        })
      );
      expect(probe).not.toHaveBeenCalled();
    });

    it('should tell the user to install the x64 build when only the 32-bit one is installed', () => {
      // arrange
      const { locator } = machine({ [SAC_IDPRIME_32]: 'x86' });

      // act
      const act = () => locator.locate([cert()]);

      // assert
      expect(act).toThrow(Pkcs11ModuleNotFoundError);
      expect(act).toThrow(
        `- ${SAC_IDPRIME_32}: this is the 32-bit version. Bright CLI is 64-bit and needs the 64-bit (x64) version of Thales SafeNet Authentication Client (IDPrime).`
      );
    });

    it('should tell the user to reinstall the software when a dependency is missing', () => {
      // arrange
      const { locator } = machine(
        { [YUBICO]: 'x64' },
        { [YUBICO]: failed('missing-dependency', 'Win32 error 126') }
      );

      // act
      const act = () => locator.locate([cert()]);

      // assert
      expect(act).toThrow(
        `- ${YUBICO}: a DLL that this library depends on is missing. Reinstall the 64-bit Yubico PIV Tool as an administrator.`
      );
    });

    it('should explain what to do when no library is installed', () => {
      // arrange
      const { locator } = machine({});

      // act
      const act = () => locator.locate([cert()]);

      // assert
      expect(act).toThrow(
        expect.objectContaining({
          name: 'Pkcs11ModuleNotFoundError',
          message: expect.stringMatching(
            /^No PKCS#11 library for your smart card was found, and --pkcs11-module is not set\.\n\nBright CLI checked \d+ standard locations of 13 smart-card software packages\. None of them has a PKCS#11 library\.\n\nWhat to do:/
          )
        })
      );
      expect(act).toThrow(
        '--pkcs11-module "C:\\Program Files\\<Vendor>\\<library>.dll"'
      );
    });

    it.each(['linux', 'darwin'] as NodeJS.Platform[])(
      'should not search on %s',
      (platform: NodeJS.Platform) => {
        // arrange
        const exists = jest.fn(() => true);
        const locator = new DefaultPkcs11ModuleLocator({ platform, exists });

        // act
        const result = locator.locate([cert()]);

        // assert
        expect(result).toBeUndefined();
        expect(exists).not.toHaveBeenCalled();
      }
    );
  });
});
