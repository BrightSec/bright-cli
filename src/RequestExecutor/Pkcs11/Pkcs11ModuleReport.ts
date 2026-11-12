import { BinaryArch } from './BinaryArch';
import { Pkcs11ProbeFailure, Pkcs11ProbeToken } from './Pkcs11ModuleProbe';

/** The library the Repeater picked because --pkcs11-module was not set. */
export interface Pkcs11ModuleDiscovery {
  path: string;
  product: string;
  /** Manufacturer and description the library reports about itself. */
  library: string;
  tokens: Pkcs11ProbeToken[];
  /** Other libraries that loaded, in the order they were tried. */
  alternatives: string[];
}

export type Pkcs11ModuleRejection =
  | { reason: 'architecture'; arch: BinaryArch }
  | { reason: 'unsupported-path' }
  | { reason: Pkcs11ProbeFailure; detail: string };

export interface Pkcs11ModuleDiagnostic {
  path: string;
  product: string;
  rejection: Pkcs11ModuleRejection;
}

export interface Pkcs11ModuleSearchSummary {
  diagnostics: Pkcs11ModuleDiagnostic[];
  /** Locations looked at, including those where no file was found. */
  checked: number;
  products: number;
}

/** Texts of the PKCS#11 library discovery, for logs and errors. */
export class Pkcs11ModuleReport {
  public static connected(discovery: Pkcs11ModuleDiscovery): string {
    const alternatives = discovery.alternatives.length
      ? ` Other usable PKCS#11 libraries found: ${discovery.alternatives.join(
          ', '
        )}.`
      : '';

    return (
      `PKCS#11: --pkcs11-module is not set; connected the ${
        discovery.product
      } library ${discovery.path} (${Pkcs11ModuleReport.describeTokens(
        discovery.tokens
      )}). To keep this choice, pass --pkcs11-module "${discovery.path}".` +
      alternatives
    );
  }

  /** @returns a warning when the chosen library does not show the wanted token yet, otherwise undefined. */
  public static missingToken(
    discovery: Pkcs11ModuleDiscovery,
    wantedLabels: string[]
  ): string | undefined {
    if (!discovery.tokens.length) {
      return `PKCS#11: no token is present in the ${discovery.product} library yet; insert the card.`;
    }

    const labels = discovery.tokens.map(({ label }) => label);

    if (
      !wantedLabels.length ||
      wantedLabels.some((label: string) => labels.includes(label))
    ) {
      return undefined;
    }

    return `PKCS#11: none of the PKCS#11 libraries found shows token ${wantedLabels
      .map((label: string) => `"${label}"`)
      .join(' or ')}; the ${discovery.product} library has ${labels
      .map((label: string) => `"${label}"`)
      .join(', ')}.`;
  }

  public static runtimeHint(discovery: Pkcs11ModuleDiscovery): string {
    const alternatives = discovery.alternatives.length
      ? ` Other libraries found: ${discovery.alternatives.join(', ')}.`
      : '';

    return (
      `The PKCS#11 library ${discovery.path} was selected automatically because --pkcs11-module is not set. ` +
      `If your card needs a different library, set --pkcs11-module to it.${alternatives}`
    );
  }

  public static notFound({
    diagnostics,
    checked,
    products
  }: Pkcs11ModuleSearchSummary): string {
    const found = diagnostics.length
      ? [
          ' Found, but not usable:',
          ...diagnostics.map(
            ({ path, product, rejection }: Pkcs11ModuleDiagnostic) =>
              `  - ${path}: ${Pkcs11ModuleReport.describeRejection(
                product,
                rejection
              )}`
          )
        ]
      : [' None of them has a PKCS#11 library.'];

    return [
      'No PKCS#11 library for your smart card was found, and --pkcs11-module is not set.',
      '',
      `Bright CLI checked ${checked} standard locations of ${products} smart-card software packages.${found[0]}`,
      ...found.slice(1),
      '',
      'What to do:',
      "  1. Install the 64-bit version of your card vendor's software, for example:",
      '       SafeNet eToken or IDPrime: Thales SafeNet Authentication Client',
      '       US CAC: HID ActivClient',
      '       YubiKey: Yubico PIV Tool, https://developers.yubico.com/yubico-piv-tool/Releases/',
      '       Other PIV/CAC cards and YubiKey: OpenSC (x64), https://github.com/OpenSC/OpenSC/releases',
      '  2. Find its PKCS#11 library: a DLL, usually with "pkcs11" or "p11" in its name. In PowerShell:',
      '       Get-ChildItem "$env:ProgramFiles", "${env:ProgramFiles(x86)}" -Recurse -Include *pkcs11*.dll, *p11*.dll -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName',
      '       Get-ChildItem "$env:SystemRoot\\System32\\*" -Include *pkcs11*.dll, *p11*.dll | Select-Object -ExpandProperty FullName',
      '  3. Pass its full path to the Repeater:',
      '       --pkcs11-module "C:\\Program Files\\<Vendor>\\<library>.dll"',
      '',
      'Run with --log-level verbose to see every location that was checked.'
    ].join('\n');
  }

  public static describeRejection(
    product: string,
    rejection: Pkcs11ModuleRejection
  ): string {
    switch (rejection.reason) {
      case 'architecture':
        return Pkcs11ModuleReport.describeArchitecture(product, rejection.arch);
      case 'wrong-architecture':
        return Pkcs11ModuleReport.describeArchitecture(product, 'x86');
      case 'unsupported-path':
        return 'its path contains a character the OpenSSL PKCS#11 provider cannot read ("#", "$", ";" or a quote), so the Repeater cannot use it.';
      case 'missing-dependency':
        return `a DLL that this library depends on is missing. ${Pkcs11ModuleReport.reinstall(
          product
        )}`;
      case 'not-pkcs11':
        return 'this file is not a PKCS#11 library.';
      case 'init-failed':
        return `it loaded, but did not start (${
          rejection.detail
        }). ${Pkcs11ModuleReport.reinstall(product)}`;
      case 'crashed':
        return `it crashed while loading (${rejection.detail}).`;
      case 'timeout':
        return `it did not answer while loading (${rejection.detail}).`;
      default:
        return `Windows could not load it (${rejection.detail}).`;
    }
  }

  private static describeArchitecture(product: string, arch: BinaryArch) {
    switch (arch) {
      case 'x86':
        return `this is the 32-bit version. Bright CLI is 64-bit and needs the 64-bit (x64) version of ${product}.`;
      case 'unknown':
        return 'this is not a Windows library.';
      default:
        return `this library is built for ${arch}. Bright CLI needs the 64-bit (x64) version of ${product}.`;
    }
  }

  private static reinstall(product: string): string {
    return `Reinstall the 64-bit ${product} as an administrator.`;
  }

  private static describeTokens(tokens: Pkcs11ProbeToken[]): string {
    switch (tokens.length) {
      case 0:
        return 'no token present';
      case 1:
        return '1 token present';
      default:
        return `${tokens.length} tokens present`;
    }
  }
}
