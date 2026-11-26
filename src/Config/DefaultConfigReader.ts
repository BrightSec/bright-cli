import { CliConfig, ConfigReader } from './ConfigReader';
import { Helpers } from '../Utils';
import { sync } from 'find-up';
import { load } from 'js-yaml';
import { extname } from 'node:path';
import { readFileSync } from 'node:fs';
import { Context, createContext, Script } from 'node:vm';

export class DefaultConfigReader implements ConfigReader {
  private readonly rcOptions: string[] = [
    '.brightrc',
    '.brightrc.json',
    '.brightrc.yml',
    '.brightrc.yaml',
    'bright.config.js',
    // ADHOC: keep for backward compatibility with the legacy nexploit-cli.
    '.nexploitrc',
    '.nexploitrc.json',
    '.nexploitrc.yml',
    '.nexploitrc.yaml',
    'nexploit.config.js'
  ];
  private readonly config: Map<keyof CliConfig, CliConfig[keyof CliConfig]>;

  constructor() {
    this.config = new Map<keyof CliConfig, CliConfig[keyof CliConfig]>();
  }

  public discovery(cwd: string): string | undefined {
    return sync(this.rcOptions, {
      cwd
    });
  }

  public load(rcPath: string): this {
    const rcExt: string = extname(rcPath.toLowerCase());

    if (rcExt === '.js') {
      this.configure(this.loadCommonJsModule(rcPath));
    } else if (rcExt === '.yml' || rcExt === '.yaml') {
      this.configure(
        load(readFileSync(rcPath, 'utf8')) as Record<string, unknown>
      );
    } else {
      this.configure(JSON.parse(readFileSync(rcPath, 'utf-8')));
    }

    return this;
  }

  public get<T extends keyof CliConfig>(key: T): CliConfig[T] {
    return this.config.get(key);
  }

  public has(key: keyof CliConfig): boolean {
    return this.config.has(key);
  }

  public toJSON(): CliConfig {
    return [...this.config.entries()].reduce(
      (acc: CliConfig, [key, value]: [string, unknown]) => {
        (acc as Record<string, unknown>)[key] = value;

        return acc;
      },
      {} as CliConfig
    );
  }

  private loadCommonJsModule(filename: string): Record<string, unknown> {
    const code: string = readFileSync(filename, { encoding: 'utf8' });
    const script: Script = new Script(code, {
      filename
    });
    const vmModule: { exports: any } = { exports: {} };
    const context: Context = createContext({
      exports: vmModule.exports,
      module: vmModule
    });

    script.runInNewContext(context, { timeout: 100 });

    const config: Record<string, unknown> | (() => Record<string, unknown>) =
      context.module?.exports ?? context.exports;

    if (typeof config === 'function') {
      return config();
    }

    return config;
  }

  private configure(map: Record<string, unknown>): void {
    Object.entries(Helpers.omit(map)).map(([key, value]: [string, unknown]) =>
      this.config.set(
        key as keyof CliConfig,
        value as CliConfig[keyof CliConfig]
      )
    );
  }
}
