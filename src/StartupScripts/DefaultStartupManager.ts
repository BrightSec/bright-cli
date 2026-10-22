import { StartupManager } from './StartupManager';
import { StartupOptions } from './StartupOptions';
import {
  add,
  AddOptions,
  remove,
  run,
  stop,
  enable,
  disable
} from '@brightsec/os-service';
import { promisify } from 'node:util';

export class DefaultStartupManager implements StartupManager {
  public async install({ name, ...options }: StartupOptions): Promise<void> {
    await promisify<string, AddOptions>(add)(name, options);
    await promisify<string>(enable)(name);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  public async run(dispose?: () => Promise<unknown> | unknown): Promise<void> {
    run(() => this.exit(0, dispose));
  }

  public async uninstall(name: string): Promise<void> {
    try {
      await promisify(disable)(name);
    } catch {
      // noop: os-service does not have isExists method
    }

    try {
      await promisify(remove)(name);
    } catch {
      // noop: os-service does not have isExists method
    }
  }

  private async exit(
    code: number,
    dispose?: () => Promise<unknown> | unknown
  ): Promise<void> {
    await dispose?.();
    stop(code);
  }
}
