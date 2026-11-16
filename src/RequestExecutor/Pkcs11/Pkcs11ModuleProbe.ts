import { Pkcs11jsBinding, Pkcs11jsModule } from './Pkcs11jsModule';
import { Pkcs11jsModuleLoader } from './Pkcs11jsModuleLoader';
import type { PKCS11 } from 'pkcs11js';

export type Pkcs11ProbeFailure =
  | 'missing-dependency'
  | 'wrong-architecture'
  | 'not-pkcs11'
  | 'load-failed'
  | 'init-failed'
  | 'crashed'
  | 'timeout';

export interface Pkcs11ProbeToken {
  label: string;
  serial: string;
}

export interface Pkcs11ProbeLoaded {
  ok: true;
  library: string;
  tokens: Pkcs11ProbeToken[];
}

export interface Pkcs11ProbeFailed {
  ok: false;
  reason: Pkcs11ProbeFailure;
  detail: string;
}

export type Pkcs11ProbeResult = Pkcs11ProbeLoaded | Pkcs11ProbeFailed;

export const isProbeFailed = (
  result: Pkcs11ProbeResult
): result is Pkcs11ProbeFailed => !result.ok;

/**
 * Loads a PKCS#11 library, lists the tokens present and unloads it again.
 * Meant to run in a throwaway process: a vendor library may crash or hang
 * while loading, which no try/catch can contain. Never logs in.
 */
export class Pkcs11ModuleProbe {
  /** Hidden first argument of bright-cli that runs a probe instead of the CLI. */
  public static readonly COMMAND = '__pkcs11-probe';
  /** Prefix of the stdout line with the result, to tell it from other output. */
  public static readonly RESULT_MARKER = 'PKCS11_PROBE_RESULT ';
  // SoftHSM2 and some HSMs always offer an empty slot with an uninitialized token.
  private static readonly CKF_TOKEN_INITIALIZED = 0x00000400;

  constructor(
    private readonly binding: () => Pkcs11jsBinding = Pkcs11jsModuleLoader.binding
  ) {}

  // pkcs11js reports LoadLibrary failures as "Win32 error <GetLastError()>".
  private static classifyLoadError(message: string): Pkcs11ProbeFailure {
    if (/\bWin32 error 126\b/.test(message)) {
      return 'missing-dependency';
    }

    if (/\bWin32 error 193\b/.test(message)) {
      return 'wrong-architecture';
    }

    if (/\bWin32 error 127\b|C_GetFunctionList/.test(message)) {
      return 'not-pkcs11';
    }

    return 'load-failed';
  }

  private static unload(lib: PKCS11): void {
    try {
      lib.C_Finalize();
    } catch {
      // Not initialized, or the library refuses: the process exits next anyway.
    }

    try {
      lib.close();
    } catch {
      // Same as above.
    }
  }

  public probe(path: string): Pkcs11ProbeResult {
    let binding: Pkcs11jsBinding;

    try {
      binding = this.binding();
    } catch (e) {
      return { ok: false, reason: 'load-failed', detail: e?.message };
    }

    const lib = new binding.PKCS11();

    try {
      lib.load(path);
    } catch (e) {
      const detail = String(e?.message ?? e);

      return {
        ok: false,
        reason: Pkcs11ModuleProbe.classifyLoadError(detail),
        detail
      };
    }

    try {
      return this.inspect(binding, lib);
    } finally {
      Pkcs11ModuleProbe.unload(lib);
    }
  }

  /** Runs the probe for `bright-cli __pkcs11-probe <path>` and prints its result. */
  public run(
    args: string[],
    write: (text: string) => void = (text: string) =>
      void process.stdout.write(text)
  ): void {
    const path: string | undefined = args[0];
    const result: Pkcs11ProbeResult = path
      ? this.probe(path)
      : { ok: false, reason: 'load-failed', detail: 'no library path given' };

    write(`${Pkcs11ModuleProbe.RESULT_MARKER}${JSON.stringify(result)}\n`);
  }

  private inspect(binding: Pkcs11jsBinding, lib: PKCS11): Pkcs11ProbeResult {
    try {
      lib.C_Initialize();
      const info = lib.C_GetInfo();
      const tokens = new Pkcs11jsModule(binding, lib)
        .tokens()
        .filter(
          ({ flags }) =>
            // A single bit; the lint rules ban bitwise operators.
            Math.floor(flags / Pkcs11ModuleProbe.CKF_TOKEN_INITIALIZED) % 2 ===
            1
        )
        .map(({ label, serial }) => ({ label, serial }));

      return {
        ok: true,
        library: [info.manufacturerID, info.libraryDescription]
          .map((value: string) => value.trim())
          .filter(Boolean)
          .join(' '),
        tokens
      };
    } catch (e) {
      return {
        ok: false,
        reason: 'init-failed',
        detail: String(e?.message ?? e)
      };
    }
  }
}
