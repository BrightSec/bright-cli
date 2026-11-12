import {
  Pkcs11ModuleDiscovery,
  Pkcs11ModuleReport
} from './Pkcs11ModuleReport';

describe('Pkcs11ModuleReport', () => {
  const discovery = (
    overrides: Partial<Pkcs11ModuleDiscovery> = {}
  ): Pkcs11ModuleDiscovery => ({
    path: 'C:\\Windows\\System32\\eTPKCS11.dll',
    product: 'Thales SafeNet Authentication Client (eToken)',
    library: 'SafeNet, Inc. SafeNet eToken PKCS#11',
    tokens: [],
    alternatives: [],
    ...overrides
  });

  describe('connected', () => {
    it('should count several tokens', () => {
      // act
      const result = Pkcs11ModuleReport.connected(
        discovery({
          tokens: [
            { label: 'a', serial: '1' },
            { label: 'b', serial: '2' }
          ]
        })
      );

      // assert
      expect(result).toContain('(2 tokens present)');
    });
  });

  describe('runtimeHint', () => {
    it('should name the other libraries that loaded', () => {
      // act
      const result = Pkcs11ModuleReport.runtimeHint(
        discovery({ alternatives: ['C:\\Program Files\\OpenSC\\opensc.dll'] })
      );

      // assert
      expect(result).toBe(
        'The PKCS#11 library C:\\Windows\\System32\\eTPKCS11.dll was selected automatically because --pkcs11-module is not set. ' +
          'If your card needs a different library, set --pkcs11-module to it. Other libraries found: C:\\Program Files\\OpenSC\\opensc.dll.'
      );
    });
  });

  describe('describeRejection', () => {
    it.each([
      {
        rejection: { reason: 'architecture' as const, arch: 'arm64' as const },
        expected:
          'this library is built for arm64. Bright CLI needs the 64-bit (x64) version of OpenSC.'
      },
      {
        rejection: {
          reason: 'architecture' as const,
          arch: 'unknown' as const
        },
        expected: 'this is not a Windows library.'
      },
      {
        rejection: { reason: 'not-pkcs11' as const, detail: 'Win32 error 127' },
        expected: 'this file is not a PKCS#11 library.'
      },
      {
        rejection: {
          reason: 'init-failed' as const,
          detail: 'CKR_DEVICE_ERROR'
        },
        expected:
          'it loaded, but did not start (CKR_DEVICE_ERROR). Reinstall the 64-bit OpenSC as an administrator.'
      },
      {
        rejection: { reason: 'load-failed' as const, detail: 'Win32 error 5' },
        expected: 'Windows could not load it (Win32 error 5).'
      }
    ])('should explain $rejection.reason', ({ rejection, expected }) => {
      // act
      const result = Pkcs11ModuleReport.describeRejection('OpenSC', rejection);

      // assert
      expect(result).toBe(expected);
    });
  });
});
