import { posix, win32 } from 'node:path';

export interface Pkcs11ModuleCandidate {
  /** Card software as users know it, for messages. */
  product: string;
  downloadUrl?: string;
  /**
   * Tried in order. A file here that turns out not to be x64 is reported,
   * never loaded, so vendors that mix both in one folder can be listed.
   */
  x64: readonly string[];
  /** Known 32-bit locations, checked only to tell the user to install the x64 build. */
  x86: readonly string[];
}

/**
 * Well-known locations of vendor PKCS#11 libraries, by platform, in the order
 * they are tried. Only folders that need administrator rights to write: no
 * PATH, no working directory, no bare DLL names.
 *
 * Paths of the SafeNet Authentication Client come from its 10.8 R9 and 10.9 GA
 * x64 MSI tables. OpenSC goes last: its generic drivers also claim cards
 * that a vendor library on the same machine serves better.
 */
const CANDIDATES: Readonly<
  Partial<Record<NodeJS.Platform, readonly Pkcs11ModuleCandidate[]>>
> = {
  win32: [
    {
      product: 'Thales SafeNet Authentication Client (IDPrime)',
      x64: [
        '%ProgramFiles%\\SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS1164.dll'
      ],
      x86: [
        '%ProgramFiles%\\SafeNet\\Authentication\\SAC\\x32\\IDPrimePKCS11.dll'
      ]
    },
    {
      product: 'Thales SafeNet Authentication Client (eToken)',
      x64: ['%SystemRoot%\\System32\\eTPKCS11.dll'],
      x86: ['%SystemRoot%\\SysWOW64\\eTPKCS11.dll']
    },
    {
      product: 'Thales IDGo 800',
      // The x64 build lives in the (x86) folder; SAC installs it there too.
      x64: [
        '%ProgramFiles(x86)%\\Gemalto\\IDGo 800 PKCS#11\\IDPrimePKCS1164.dll',
        '%ProgramFiles%\\Gemalto\\IDGo 800 PKCS#11\\IDPrimePKCS1164.dll'
      ],
      x86: ['%ProgramFiles(x86)%\\Gemalto\\IDGo 800 PKCS#11\\IDPrimePKCS11.dll']
    },
    {
      product: 'Gemalto Classic Client',
      x64: [
        '%ProgramFiles%\\SafeNet\\Authentication\\SAC\\x64\\ClassicClientPKCS1164.dll',
        '%ProgramFiles%\\Gemalto\\Classic Client\\BIN\\gclib.dll'
      ],
      x86: [
        '%ProgramFiles%\\SafeNet\\Authentication\\SAC\\x32\\ClassicClientPKCS11.dll',
        '%ProgramFiles(x86)%\\Gemalto\\Classic Client\\BIN\\gclib.dll'
      ]
    },
    {
      product: 'HID ActivClient',
      x64: [
        '%ProgramFiles%\\HID Global\\ActivClient\\acpkcs211.dll',
        '%ProgramFiles%\\ActivIdentity\\ActivClient\\acpkcs211.dll'
      ],
      x86: ['%ProgramFiles(x86)%\\HID Global\\ActivClient\\acpkcs211.dll']
    },
    {
      product: 'Yubico PIV Tool',
      downloadUrl: 'https://developers.yubico.com/yubico-piv-tool/Releases/',
      x64: [
        '%ProgramFiles%\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll',
        '%SystemRoot%\\System32\\libykcs11-1.dll'
      ],
      x86: ['%ProgramFiles(x86)%\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll']
    },
    {
      product: 'Feitian ePass2003',
      x64: ['%SystemRoot%\\System32\\eps2003csp11.dll'],
      x86: ['%SystemRoot%\\SysWOW64\\eps2003csp11.dll']
    },
    {
      product: 'Bit4id Universal Middleware',
      x64: [
        '%SystemRoot%\\System32\\bit4xpki.dll',
        '%SystemRoot%\\System32\\bit4ipki.dll',
        '%SystemRoot%\\System32\\bit4opki.dll'
      ],
      x86: [
        '%SystemRoot%\\SysWOW64\\bit4xpki.dll',
        '%SystemRoot%\\SysWOW64\\bit4ipki.dll',
        '%SystemRoot%\\SysWOW64\\bit4opki.dll'
      ]
    },
    {
      product: 'Athena IDProtect',
      x64: ['%SystemRoot%\\System32\\asepkcs.dll'],
      x86: []
    },
    {
      product: 'A.E.T. SafeSign',
      x64: ['%SystemRoot%\\System32\\aetpkss1.dll'],
      x86: []
    },
    {
      product: 'Atos CardOS API',
      x64: [
        '%SystemRoot%\\System32\\siecap11.dll',
        '%SystemRoot%\\System32\\cardos11_64.dll',
        '%SystemRoot%\\System32\\cardos11.dll'
      ],
      x86: []
    },
    {
      product: 'cryptovision sc/interface',
      x64: ['%SystemRoot%\\System32\\cvP11.dll'],
      x86: []
    },
    {
      product: 'OpenSC',
      downloadUrl: 'https://github.com/OpenSC/OpenSC/releases',
      x64: [
        '%ProgramFiles%\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
        '%SystemRoot%\\System32\\opensc-pkcs11.dll'
      ],
      x86: [
        '%ProgramFiles(x86)%\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
        '%SystemRoot%\\SysWOW64\\opensc-pkcs11.dll'
      ]
    }
  ]
};

const lookup = (env: NodeJS.ProcessEnv, name: string): string | undefined => {
  // Windows variable names are case-insensitive; a plain object is not.
  const key = Object.keys(env).find(
    (candidate: string) => candidate.toLowerCase() === name.toLowerCase()
  );

  return key ? env[key] : undefined;
};

const expand = (
  template: string,
  env: NodeJS.ProcessEnv,
  normalize: (path: string) => string
): string | undefined => {
  let missing = false;
  const expanded = template.replace(/%([^%]+)%/g, (_: string, name: string) => {
    const value = lookup(env, name);
    missing = missing || !value;

    return value ?? '';
  });

  return missing ? undefined : normalize(expanded);
};

/**
 * @returns the candidates for `platform` with environment variables expanded;
 * paths whose variable is not set are left out. Empty where discovery is not supported.
 */
export const resolvePkcs11ModuleCandidates = (
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  candidates: readonly Pkcs11ModuleCandidate[] = CANDIDATES[platform] ?? []
): Pkcs11ModuleCandidate[] => {
  const { normalize } = platform === 'win32' ? win32 : posix;
  // A variable set to a relative or network path would turn a well-known
  // location into one anybody may write to.
  const isLocalAbsolute = (path: string): boolean =>
    platform === 'win32' ? /^[A-Za-z]:\\/.test(path) : posix.isAbsolute(path);
  const resolve = (paths: readonly string[]): string[] =>
    paths
      .map((path: string) => expand(path, env, normalize))
      .filter(
        (path: string | undefined): path is string =>
          !!path && isLocalAbsolute(path)
      );

  return candidates.map((candidate: Pkcs11ModuleCandidate) => ({
    ...candidate,
    x64: resolve(candidate.x64),
    x86: resolve(candidate.x86)
  }));
};
