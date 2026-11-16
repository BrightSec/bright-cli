/* eslint-disable @typescript-eslint/naming-convention -- the fake mirrors pkcs11js method names */
import { Pkcs11ModuleProbe } from './Pkcs11ModuleProbe';
import { Pkcs11jsBinding } from './Pkcs11jsModule';
import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';

describe('Pkcs11ModuleProbe', () => {
  const CKF_TOKEN_INITIALIZED = 0x400;
  const slot = Buffer.from('slot');
  const freeSlot = Buffer.from('free');

  const fakeLib = (overrides: Record<string, jest.Mock> = {}) => ({
    load: jest.fn(),
    close: jest.fn(),
    C_Initialize: jest.fn(),
    C_Finalize: jest.fn(),
    C_GetInfo: jest.fn(() => ({
      manufacturerID: 'SafeNet, Inc.                   ',
      libraryDescription: 'SafeNet eToken PKCS#11          '
    })),
    C_GetSlotList: jest.fn(() => [slot, freeSlot]),
    C_GetTokenInfo: jest.fn((s: Buffer) =>
      s === slot
        ? {
            label: 'card                            ',
            serialNumber: '0123456789      ',
            flags: CKF_TOKEN_INITIALIZED
          }
        : { label: '', serialNumber: '', flags: 0 }
    ),
    ...overrides
  });

  const probeWith = (lib: ReturnType<typeof fakeLib>) =>
    new Pkcs11ModuleProbe(
      () => ({ PKCS11: jest.fn(() => lib) } as unknown as Pkcs11jsBinding)
    );

  describe('probe', () => {
    it('should report the library and the initialized tokens present, then unload it', () => {
      // arrange
      const lib = fakeLib();

      // act
      const result = probeWith(lib).probe(
        'C:\\Windows\\System32\\eTPKCS11.dll'
      );

      // assert
      expect(result).toEqual({
        ok: true,
        library: 'SafeNet, Inc. SafeNet eToken PKCS#11',
        tokens: [{ label: 'card', serial: '0123456789' }]
      });
      expect(lib.load).toHaveBeenCalledWith(
        'C:\\Windows\\System32\\eTPKCS11.dll'
      );
      expect(lib.C_GetSlotList).toHaveBeenCalledWith(true);
      expect(lib.C_Finalize).toHaveBeenCalled();
      expect(lib.close).toHaveBeenCalled();
    });

    it.each([
      { error: 'Win32 error 126', reason: 'missing-dependency' },
      { error: 'Win32 error 193', reason: 'wrong-architecture' },
      { error: 'Win32 error 127', reason: 'not-pkcs11' },
      {
        error: 'dlsym(0x1, C_GetFunctionList): symbol not found',
        reason: 'not-pkcs11'
      },
      { error: 'Win32 error 5', reason: 'load-failed' }
    ])(
      'should classify a load failure "$error" as $reason',
      ({ error, reason }) => {
        // arrange
        const lib = fakeLib({
          load: jest.fn(() => {
            throw new Error(error);
          })
        });

        // act
        const result = probeWith(lib).probe('C:\\x.dll');

        // assert
        expect(result).toEqual({ ok: false, reason, detail: error });
        expect(lib.C_Initialize).not.toHaveBeenCalled();
      }
    );

    it('should report a failed initialization and still unload the library', () => {
      // arrange
      const lib = fakeLib({
        C_Initialize: jest.fn(() => {
          throw new Error('CKR_DEVICE_ERROR:48');
        })
      });

      // act
      const result = probeWith(lib).probe('C:\\x.dll');

      // assert
      expect(result).toEqual({
        ok: false,
        reason: 'init-failed',
        detail: 'CKR_DEVICE_ERROR:48'
      });
      expect(lib.close).toHaveBeenCalled();
    });

    it('should report a missing native addon', () => {
      // arrange
      const probe = new Pkcs11ModuleProbe(() => {
        throw new Pkcs11Error(
          Pkcs11ErrorCode.MODULE_LOAD_FAILED,
          'The pkcs11js native addon is not available'
        );
      });

      // act
      const result = probe.probe('C:\\x.dll');

      // assert
      expect(result).toEqual({
        ok: false,
        reason: 'load-failed',
        detail: 'The pkcs11js native addon is not available'
      });
    });
  });

  describe('run', () => {
    it('should print the result on one line after the marker', () => {
      // arrange
      const write = jest.fn();

      // act
      probeWith(fakeLib()).run(['C:\\x.dll'], write);

      // assert
      expect(write).toHaveBeenCalledWith(
        `PKCS11_PROBE_RESULT ${JSON.stringify({
          ok: true,
          library: 'SafeNet, Inc. SafeNet eToken PKCS#11',
          tokens: [{ label: 'card', serial: '0123456789' }]
        })}\n`
      );
    });

    it('should report a missing library path', () => {
      // arrange
      const write = jest.fn();

      // act
      probeWith(fakeLib()).run([], write);

      // assert
      expect(write).toHaveBeenCalledWith(
        expect.stringContaining('"reason":"load-failed"')
      );
    });
  });
});
