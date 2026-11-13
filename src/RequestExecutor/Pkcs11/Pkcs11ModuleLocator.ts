import { BinaryArch, readBinaryArch } from './BinaryArch';
import {
  Pkcs11ModuleCandidate,
  resolvePkcs11ModuleCandidates
} from './Pkcs11ModuleCandidates';
import {
  isProbeFailed,
  Pkcs11ProbeResult,
  Pkcs11ProbeToken
} from './Pkcs11ModuleProbe';
import { Pkcs11ModuleNotFoundError } from './Pkcs11ModuleNotFoundError';
import { Pkcs11ModuleProbeRunner } from './Pkcs11ModuleProbeRunner';
import {
  Pkcs11ModuleDiagnostic,
  Pkcs11ModuleDiscovery,
  Pkcs11ModuleReport
} from './Pkcs11ModuleReport';
import { Pkcs11OpenSslConfig } from './Pkcs11OpenSslConfig';
import { Pkcs11Cert } from '../Pkcs11Cert';
import { logger } from '../../Utils';
import { statSync } from 'node:fs';

export interface Pkcs11ModuleLocator {
  /**
   * Finds the vendor PKCS#11 library when --pkcs11-module is not set.
   *
   * @returns undefined where discovery is not supported.
   * @throws Pkcs11ModuleNotFoundError when no usable library is found.
   */
  locate(certs: Pkcs11Cert[]): Pkcs11ModuleDiscovery | undefined;
}

export const Pkcs11ModuleLocator: unique symbol = Symbol('Pkcs11ModuleLocator');

export interface DefaultPkcs11ModuleLocatorOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  /** Unexpanded candidates; the platform's built-in list by default. */
  candidates?: readonly Pkcs11ModuleCandidate[];
  exists?: (path: string) => boolean;
  readArch?: (path: string) => BinaryArch;
  /** `env` is the locator's environment without the PIN variables of `--pkcs11-cert`. */
  probe?: (path: string, env: NodeJS.ProcessEnv) => Pkcs11ProbeResult;
  isConfigSafe?: (path: string) => boolean;
  now?: () => number;
}

interface LoadedModule {
  candidate: Pkcs11ModuleCandidate;
  path: string;
  library: string;
  tokens: Pkcs11ProbeToken[];
}

const isFile = (path: string): boolean => {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
};

export class DefaultPkcs11ModuleLocator implements Pkcs11ModuleLocator {
  private readonly platform: NodeJS.Platform;
  private readonly env: NodeJS.ProcessEnv;
  private readonly candidates?: readonly Pkcs11ModuleCandidate[];
  private readonly exists: (path: string) => boolean;
  private readonly readArch: (path: string) => BinaryArch;
  private readonly probe: (
    path: string,
    env: NodeJS.ProcessEnv
  ) => Pkcs11ProbeResult;
  private readonly isConfigSafe: (path: string) => boolean;
  private readonly now: () => number;

  constructor({
    platform = process.platform,
    env = process.env,
    candidates,
    exists = isFile,
    readArch = readBinaryArch,
    probe,
    isConfigSafe = Pkcs11OpenSslConfig.isSafePath,
    now = Date.now
  }: DefaultPkcs11ModuleLocatorOptions = {}) {
    this.platform = platform;
    this.env = env;
    this.candidates = candidates;
    this.exists = exists;
    this.readArch = readArch;
    this.probe =
      probe ??
      ((path: string, probeEnv: NodeJS.ProcessEnv) =>
        new Pkcs11ModuleProbeRunner({ env: probeEnv, platform }).probe(path));
    this.isConfigSafe = isConfigSafe;
    this.now = now;
  }

  public locate(certs: Pkcs11Cert[]): Pkcs11ModuleDiscovery | undefined {
    const candidates = resolvePkcs11ModuleCandidates(
      this.platform,
      this.env,
      this.candidates
    );

    if (!candidates.length) {
      return undefined;
    }

    const wantedLabels = [
      ...new Set(
        certs.map(({ token }: Pkcs11Cert) => token).filter(Boolean) as string[]
      )
    ];
    const probeEnv = this.withoutPins(certs);
    const checked = candidates.reduce(
      (count: number, { x64, x86 }: Pkcs11ModuleCandidate) =>
        count + x64.length + x86.length,
      0
    );
    const diagnostics: Pkcs11ModuleDiagnostic[] = candidates.flatMap(
      (candidate: Pkcs11ModuleCandidate) => this.inspect32Bit(candidate)
    );
    // A product may ship several libraries for different card families
    // (Bit4id), so one that loads without the wanted token does not end the search.
    const paths = candidates.flatMap((candidate: Pkcs11ModuleCandidate) =>
      candidate.x64.map((path: string) => ({ candidate, path }))
    );
    const loaded: LoadedModule[] = [];

    for (const { candidate, path } of paths) {
      const module = this.load(candidate, path, probeEnv, diagnostics);

      if (!module) {
        continue;
      }

      loaded.push(module);

      // All certificates share one library, so it must show every wanted token.
      if (this.coverage(module, wantedLabels) === this.full(wantedLabels)) {
        return this.select(module, loaded, wantedLabels);
      }
    }

    if (loaded.length) {
      return this.select(this.best(loaded, wantedLabels), loaded, wantedLabels);
    }

    throw new Pkcs11ModuleNotFoundError(
      Pkcs11ModuleReport.notFound({
        diagnostics,
        checked,
        products: candidates.length
      })
    );
  }

  /** @returns how many wanted labels `module` shows; without labels, 1 when it shows any token. */
  private coverage(module: LoadedModule, wantedLabels: string[]): number {
    const labels = module.tokens.map(({ label }: Pkcs11ProbeToken) => label);

    return wantedLabels.length
      ? wantedLabels.filter((label: string) => labels.includes(label)).length
      : Math.min(labels.length, 1);
  }

  private full(wantedLabels: string[]): number {
    return wantedLabels.length || 1;
  }

  // Ties go to the library tried first.
  private best(loaded: LoadedModule[], wantedLabels: string[]): LoadedModule {
    return loaded.reduce((best: LoadedModule, module: LoadedModule) =>
      this.coverage(module, wantedLabels) > this.coverage(best, wantedLabels)
        ? module
        : best
    );
  }

  // The probed library runs in the child process and could read the PIN there.
  private withoutPins(certs: Pkcs11Cert[]): NodeJS.ProcessEnv {
    const names = certs
      .map(({ pinEnv }: Pkcs11Cert) => pinEnv?.toUpperCase())
      .filter(Boolean);

    return Object.fromEntries(
      Object.entries(this.env).filter(
        ([name]: [string, string | undefined]) =>
          !names.includes(name.toUpperCase())
      )
    );
  }

  private select(
    module: LoadedModule,
    loaded: LoadedModule[],
    wantedLabels: string[]
  ): Pkcs11ModuleDiscovery {
    const discovery: Pkcs11ModuleDiscovery = {
      path: module.path,
      product: module.candidate.product,
      library: module.library,
      tokens: module.tokens,
      alternatives: loaded
        .filter((other: LoadedModule) => other !== module)
        .map(({ path }: LoadedModule) => path)
    };

    logger.log(Pkcs11ModuleReport.connected(discovery));

    const warning = Pkcs11ModuleReport.missingToken(discovery, wantedLabels);
    if (warning) {
      logger.warn(warning);
    }

    return discovery;
  }

  // A 32-bit process cannot host the Repeater's 64-bit build, so these are never loaded.
  private inspect32Bit(
    candidate: Pkcs11ModuleCandidate
  ): Pkcs11ModuleDiagnostic[] {
    return candidate.x86
      .filter((path: string) => this.found(path))
      .map((path: string) => ({ path, arch: this.readArch(path) }))
      .filter(({ arch }) => arch === 'x86')
      .map(({ path, arch }) => ({
        path,
        product: candidate.product,
        rejection: { reason: 'architecture', arch }
      }));
  }

  /** @returns the library at `path` if it loads; otherwise records why not. */
  private load(
    candidate: Pkcs11ModuleCandidate,
    path: string,
    probeEnv: NodeJS.ProcessEnv,
    diagnostics: Pkcs11ModuleDiagnostic[]
  ): LoadedModule | undefined {
    const { product } = candidate;

    if (!this.found(path)) {
      return undefined;
    }

    const arch = this.readArch(path);

    if (arch !== 'x64') {
      diagnostics.push({
        path,
        product,
        rejection: { reason: 'architecture', arch }
      });

      return undefined;
    }

    if (!this.isConfigSafe(path)) {
      diagnostics.push({
        path,
        product,
        rejection: { reason: 'unsupported-path' }
      });

      return undefined;
    }

    const result = this.timedProbe(path, probeEnv);

    if (isProbeFailed(result)) {
      diagnostics.push({
        path,
        product,
        rejection: { reason: result.reason, detail: result.detail }
      });

      return undefined;
    }

    return {
      candidate,
      path,
      library: result.library,
      tokens: result.tokens
    };
  }

  private found(path: string): boolean {
    const exists = this.exists(path);
    logger.debug('PKCS#11: %s %s', exists ? 'found' : 'no library at', path);

    return exists;
  }

  private timedProbe(
    path: string,
    probeEnv: NodeJS.ProcessEnv
  ): Pkcs11ProbeResult {
    const startedAt = this.now();
    const result = this.probe(path, probeEnv);
    const summary = isProbeFailed(result)
      ? `${result.reason}: ${result.detail}`
      : `loaded "${result.library}", ${result.tokens.length} token(s)`;

    logger.debug(
      'PKCS#11: probed %s in %d ms: %s',
      path,
      this.now() - startedAt,
      summary
    );

    return result;
  }
}
