import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

export interface Pkcs11ProviderLocatorOptions {
  platform?: NodeJS.Platform;
  execPath?: string;
  exists?: (path: string) => boolean;
}

/** Finds the OpenSSL PKCS#11 provider plugin (pkcs11-provider or libp11). */
export class Pkcs11ProviderLocator {
  private static readonly LINUX_DIRS = [
    '/usr/lib/x86_64-linux-gnu/ossl-modules',
    '/usr/lib/aarch64-linux-gnu/ossl-modules',
    '/usr/lib64/ossl-modules',
    '/usr/lib/ossl-modules'
  ];
  private static readonly MACOS_DIRS = [
    '/opt/homebrew/lib/ossl-modules',
    '/usr/local/lib/ossl-modules'
  ];

  public static candidates({
    platform = process.platform,
    execPath = process.execPath
  }: Pkcs11ProviderLocatorOptions = {}): string[] {
    switch (platform) {
      case 'win32':
        // Shipped next to bright-cli.exe.
        return [join(dirname(execPath), 'pkcs11prov.dll')];
      case 'darwin':
        return Pkcs11ProviderLocator.MACOS_DIRS.flatMap((dir: string) => [
          join(dir, 'pkcs11.dylib'),
          join(dir, 'pkcs11prov.dylib')
        ]);
      default:
        return Pkcs11ProviderLocator.LINUX_DIRS.flatMap((dir: string) => [
          join(dir, 'pkcs11.so'),
          join(dir, 'pkcs11prov.so')
        ]);
    }
  }

  /**
   * @returns `explicit` when given, otherwise the first default location that exists.
   * @throws Pkcs11Error when no provider is found.
   */
  public static locate(
    explicit?: string,
    options: Pkcs11ProviderLocatorOptions = {}
  ): string {
    if (explicit) {
      return explicit;
    }

    const exists = options.exists ?? existsSync;
    const candidates = Pkcs11ProviderLocator.candidates(options);
    const found = candidates.find((path: string) => exists(path));

    if (!found) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.MODULE_LOAD_FAILED,
        `OpenSSL PKCS#11 provider not found (looked in ${candidates.join(
          ', '
        )}). Install pkcs11-provider or libp11, or pass --pkcs11-provider.`
      );
    }

    return found;
  }
}
