import { Pkcs11ProviderLocator } from './Pkcs11ProviderLocator';
import { Pkcs11ErrorCode } from './Pkcs11Error';
import { join } from 'node:path';

describe('Pkcs11ProviderLocator', () => {
  describe('candidates', () => {
    it('should look next to the executable on Windows', () => {
      // arrange
      const execPath = join('C:', 'Bright', 'bright-cli.exe');

      // act
      const result = Pkcs11ProviderLocator.candidates({
        platform: 'win32',
        execPath
      });

      // assert
      expect(result).toEqual([join('C:', 'Bright', 'pkcs11prov.dll')]);
    });

    it('should look in the Homebrew module directories on macOS', () => {
      // act
      const result = Pkcs11ProviderLocator.candidates({ platform: 'darwin' });

      // assert
      expect(result).toContain(
        join('/opt/homebrew/lib/ossl-modules', 'pkcs11.dylib')
      );
    });

    it('should prefer pkcs11-provider over libp11 on Linux', () => {
      // act
      const result = Pkcs11ProviderLocator.candidates({ platform: 'linux' });

      // assert
      expect(result.slice(0, 2)).toEqual([
        join('/usr/lib/x86_64-linux-gnu/ossl-modules', 'pkcs11.so'),
        join('/usr/lib/x86_64-linux-gnu/ossl-modules', 'pkcs11prov.so')
      ]);
    });
  });

  describe('locate', () => {
    it('should return the explicit provider without checking it', () => {
      // arrange
      const exists = jest.fn(() => false);

      // act
      const result = Pkcs11ProviderLocator.locate('/custom/pkcs11.so', {
        exists
      });

      // assert
      expect(result).toBe('/custom/pkcs11.so');
      expect(exists).not.toHaveBeenCalled();
    });

    it('should return the first candidate that exists', () => {
      // arrange
      const expected = join('/usr/lib64/ossl-modules', 'pkcs11prov.so');

      // act
      const result = Pkcs11ProviderLocator.locate(undefined, {
        platform: 'linux',
        exists: (path: string) => path === expected
      });

      // assert
      expect(result).toBe(expected);
    });

    it('should fail with the locations it looked in', () => {
      // act
      const act = () =>
        Pkcs11ProviderLocator.locate(undefined, {
          platform: 'linux',
          exists: () => false
        });

      // assert
      expect(act).toThrow(
        expect.objectContaining({
          code: Pkcs11ErrorCode.MODULE_LOAD_FAILED,
          message: expect.stringContaining('pass --pkcs11-provider')
        })
      );
    });
  });
});
