import { Helpers } from '../Utils/Helpers';
import { RepeaterTools } from './McpServer';
import { inject, injectable } from 'tsyringe';
import { ChildProcess, spawn } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';

export interface RepeaterRunToolInput {
  id: string;
  hostname?: string;
}

export interface RepeaterStopToolInput {
  id: string;
  signal?: NodeJS.Signals;
  timeoutMs?: number;
}

export interface RepeaterIdInput {
  id: string;
}

export interface RepeaterProcessStatus {
  id: string;
  running: boolean;
  pid: number | undefined;
  startedAt: string;
  exitedAt?: string;
  exitCode?: number | null;
  lastError?: string;
}

export interface RepeaterRunToolContext {
  token?: string;
}

export interface RepeaterRunCommandOptions {
  startupGraceMs?: number;
}

export const RepeaterRunCommandOptions: unique symbol = Symbol(
  'RepeaterRunCommandOptions'
);

const SENSITIVE_OPTIONS = new Set(['--token', '-t']);

interface RepeaterProcessEntry {
  id: string;
  child: ChildProcess;
  startedAt: Date;
  exitedAt?: Date;
  exitCode?: number | null;
  lastError?: string;
  sensitiveValues: Set<string>;
}

@injectable()
export class DefaultRepeaterTools implements RepeaterTools {
  private readonly startupGraceMs: number;
  private readonly processes = new Map<string, RepeaterProcessEntry>();

  constructor(
    @inject(RepeaterRunCommandOptions)
    private readonly options: RepeaterRunCommandOptions
  ) {
    this.startupGraceMs = this.options.startupGraceMs ?? 500;
  }

  public async run(
    input: RepeaterRunToolInput,
    context: RepeaterRunToolContext = {}
  ): Promise<RepeaterProcessStatus> {
    const id = this.requireId(input.id);
    const existing = this.processes.get(id);

    if (existing && this.isRunning(existing)) {
      throw new Error(`A repeater command is already running for id "${id}".`);
    }

    const repeaterArgs = this.buildArgs(input, context);
    const sensitiveValues = new Set(this.collectSensitiveValues(repeaterArgs));
    const { command, args, shell, windowsVerbatimArguments } =
      Helpers.getExecArgs({
        spawn: true,
        excludeAll: true,
        include: ['repeater', ...repeaterArgs]
      });

    const child = spawn(command, args, {
      shell,
      windowsVerbatimArguments,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const entry: RepeaterProcessEntry = {
      id,
      child,
      sensitiveValues,
      startedAt: new Date()
    };

    this.processes.set(id, entry);
    this.attachHandlers(entry);

    try {
      await this.waitForImmediateFailure(entry);
    } catch (error) {
      if (this.processes.get(id) === entry && !this.isRunning(entry)) {
        this.processes.delete(id);
      }
      throw error;
    }

    return this.toStatus(entry);
  }

  public async stop(
    input: RepeaterStopToolInput
  ): Promise<RepeaterProcessStatus> {
    const id = this.requireId(input.id);
    const entry = this.requireEntry(id);

    if (!this.isRunning(entry)) {
      return this.toStatus(entry);
    }

    const { child } = entry;
    const signal = input.signal ?? 'SIGTERM';
    const timeoutMs = input.timeoutMs ?? 5000;
    const exitPromise = new Promise<void>((resolve) =>
      child.once('exit', () => resolve())
    );

    child.kill(signal);

    await Promise.race([
      exitPromise,
      setTimeout(timeoutMs, undefined, { ref: false })
    ]);

    if (this.isRunning(entry)) {
      child.kill('SIGKILL');
      await Promise.race([
        exitPromise,
        setTimeout(1000, undefined, { ref: false })
      ]);
    }

    return this.toStatus(entry);
  }

  public status(input: RepeaterIdInput): RepeaterProcessStatus {
    return this.toStatus(this.requireEntry(this.requireId(input.id)));
  }

  public stopAll(): Promise<RepeaterProcessStatus[]> {
    return Promise.all(
      [...this.processes.keys()].map((id) => this.stop({ id }))
    );
  }

  private buildArgs(
    input: RepeaterRunToolInput,
    context: RepeaterRunToolContext
  ): string[] {
    const args: string[] = [];
    const token = this.resolveToken(context);

    this.addValue(args, '--token', token);
    this.addValue(args, '--id', input.id);
    this.addValue(args, '--hostname', input.hostname);

    return args;
  }
  private requireId(id: string | undefined): string {
    if (typeof id !== 'string' || !id) {
      throw new Error('Repeater id is required.');
    }

    return id;
  }

  private requireEntry(id: string): RepeaterProcessEntry {
    const entry = this.processes.get(id);

    if (!entry) {
      throw new Error(`No repeater process found for id "${id}".`);
    }

    return entry;
  }

  private resolveToken(context: RepeaterRunToolContext): string {
    const token = context.token ?? process.env.BRIGHT_TOKEN;

    if (!token) {
      throw new Error(
        'A Bright API token is required. Set BRIGHT_TOKEN on the MCP server process or provide it through MCP transport authentication.'
      );
    }

    return token;
  }

  private attachHandlers(entry: RepeaterProcessEntry): void {
    const { child } = entry;

    child.once('error', (error: Error) => {
      entry.lastError = this.redact(entry, error.message);
    });
    child.once('exit', (code) => {
      entry.exitedAt = new Date();
      entry.exitCode = code;
    });
  }

  private waitForImmediateFailure(entry: RepeaterProcessEntry): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const { child } = entry;

      const cleanup = () => {
        clearTimeout(timer);
        child.off('error', handleError);
        child.off('exit', handleExit);
      };

      const settle = (callback: () => void) => {
        if (settled) {
          return;
        }

        settled = true;
        cleanup();
        callback();
      };

      const handleError = (error: Error) =>
        settle(() => reject(new Error(this.redact(entry, error.message))));

      const handleExit = (code: number | null, signal: NodeJS.Signals | null) =>
        settle(() =>
          reject(
            new Error(
              `Repeater command exited before startup completed with code ${code} and signal ${signal}.`
            )
          )
        );

      const timer = global.setTimeout(
        () => settle(resolve),
        this.startupGraceMs
      );
      timer.unref?.();

      child.once('error', handleError);
      child.once('exit', handleExit);
    });
  }

  private collectSensitiveValues(args: string[]): string[] {
    const values: string[] = [];

    args.forEach((arg, index) => {
      const [optionName, inlineValue]: string[] = arg.split('=', 2);

      if (inlineValue && SENSITIVE_OPTIONS.has(optionName)) {
        values.push(inlineValue);
      }

      if (SENSITIVE_OPTIONS.has(arg) && args[index + 1]) {
        values.push(args[index + 1]);
      }
    });

    return values.filter((value) => value.length > 0);
  }

  private redact(entry: RepeaterProcessEntry, value: string): string {
    return this.redactWith(entry.sensitiveValues, value);
  }

  private redactWith(sensitiveValues: Set<string>, value: string): string {
    return [...sensitiveValues]
      .sort((left, right) => right.length - left.length)
      .reduce(
        (currentValue, secret) => currentValue.split(secret).join('[Filtered]'),
        value
      );
  }

  private isRunning(entry: RepeaterProcessEntry): boolean {
    return !entry.exitedAt;
  }

  private toStatus(entry: RepeaterProcessEntry): RepeaterProcessStatus {
    return {
      id: entry.id,
      running: this.isRunning(entry),
      pid: entry.child.pid,
      startedAt: entry.startedAt.toISOString(),
      exitedAt: entry.exitedAt?.toISOString(),
      exitCode: entry.exitCode,
      lastError: entry.lastError
    };
  }

  private addValue(
    args: string[],
    option: string,
    value: string | number | undefined
  ): void {
    if (value !== undefined) {
      args.push(option, String(value));
    }
  }
}
