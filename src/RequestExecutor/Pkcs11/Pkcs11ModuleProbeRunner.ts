import { Pkcs11ModuleProbe, Pkcs11ProbeResult } from './Pkcs11ModuleProbe';
import { Helpers } from '../../Utils';
import {
  spawnSync,
  SpawnSyncOptions,
  SpawnSyncReturns
} from 'node:child_process';
import { posix, win32 } from 'node:path';

export type SpawnProbe = (
  command: string,
  args: string[],
  options: SpawnSyncOptions
) => Pick<
  SpawnSyncReturns<string>,
  'status' | 'signal' | 'stdout' | 'stderr' | 'error'
>;

export interface Pkcs11ModuleProbeRunnerOptions {
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  spawn?: SpawnProbe;
  /** How to start this CLI again: the executable and the arguments before the probe's. */
  self?: () => { command: string; args: string[] };
}

/**
 * Runs {@link Pkcs11ModuleProbe} in a child process of this CLI, so that a
 * library that crashes or hangs costs the probe, not the Repeater.
 */
export class Pkcs11ModuleProbeRunner {
  public static readonly DEFAULT_TIMEOUT_MS = 15_000;

  private readonly timeoutMs: number;
  private readonly env: NodeJS.ProcessEnv;
  private readonly platform: NodeJS.Platform;
  private readonly spawn: SpawnProbe;
  private readonly self: () => { command: string; args: string[] };

  constructor({
    timeoutMs = Pkcs11ModuleProbeRunner.DEFAULT_TIMEOUT_MS,
    env = process.env,
    platform = process.platform,
    spawn = spawnSync as SpawnProbe,
    self = () =>
      // A pkg executable started by another one runs its first argument as a
      // script, so the entry point must stay in the arguments.
      Helpers.getExecArgs({ excludeAll: true, escape: false, spawn: true })
  }: Pkcs11ModuleProbeRunnerOptions = {}) {
    this.timeoutMs = timeoutMs;
    this.env = env;
    this.platform = platform;
    this.spawn = spawn;
    this.self = self;
  }

  private static parse(stdout: string | undefined): Pkcs11ProbeResult {
    const line = (stdout ?? '')
      .split(/\r?\n/)
      .find((text: string) => text.startsWith(Pkcs11ModuleProbe.RESULT_MARKER));

    if (!line) {
      return undefined;
    }

    try {
      const result = JSON.parse(
        line.slice(Pkcs11ModuleProbe.RESULT_MARKER.length)
      );

      return typeof result?.ok === 'boolean' ? result : undefined;
    } catch {
      return undefined;
    }
  }

  private static describeExit(
    status: number | null,
    signal: NodeJS.Signals | null,
    stderr: string | undefined
  ): string {
    const exit = signal
      ? `the probe process was killed by ${signal}`
      : // Windows reports crashes as NTSTATUS codes, e.g. 0xC0000005 for an access violation.
        `the probe process exited with code 0x${(status ?? 0)
          .toString(16)
          .toUpperCase()}`;
    const lines = (stderr ?? '')
      .split(/\r?\n/)
      .map((line: string) => line.trim())
      .filter(Boolean);
    // Node prints an uncaught error's message above its stack and version lines.
    const reason =
      lines.filter((line: string) => /error/i.test(line)).pop() ?? lines.pop();

    return reason ? `${exit}: ${reason.slice(0, 300)}` : exit;
  }

  public probe(path: string): Pkcs11ProbeResult {
    const { command, args } = this.self();
    const { error, status, signal, stdout, stderr } = this.spawn(
      command,
      [...args, Pkcs11ModuleProbe.COMMAND, path],
      {
        env: this.envFor(path),
        encoding: 'utf8',
        timeout: this.timeoutMs,
        killSignal: 'SIGKILL',
        windowsHide: true,
        shell: false
      }
    );

    if ((error as NodeJS.ErrnoException)?.code === 'ETIMEDOUT') {
      return {
        ok: false,
        reason: 'timeout',
        detail: `no answer within ${this.timeoutMs / 1000} s`
      };
    }

    if (error) {
      return { ok: false, reason: 'crashed', detail: error.message };
    }

    const result = Pkcs11ModuleProbeRunner.parse(stdout);

    return status === 0 && result
      ? result
      : {
          ok: false,
          reason: 'crashed',
          detail: Pkcs11ModuleProbeRunner.describeExit(status, signal, stderr)
        };
  }

  // Windows resolves a library's own DLL dependencies through PATH, not its
  // directory (pkcs11js calls LoadLibraryW without flags).
  private envFor(path: string): NodeJS.ProcessEnv {
    const { dirname, delimiter } = this.platform === 'win32' ? win32 : posix;
    const key =
      Object.keys(this.env).find(
        (name: string) => name.toUpperCase() === 'PATH'
      ) ?? 'PATH';
    const current = this.env[key];

    return {
      ...this.env,
      [key]: current ? `${dirname(path)}${delimiter}${current}` : dirname(path)
    };
  }
}
