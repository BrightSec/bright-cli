import { sync } from 'find-up';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

export class CliInfo {
  public readonly cwd: string;
  public readonly version: string;
  public readonly distribution: string | undefined;
  // Per process, so the server can tell apart two processes sharing a Repeater ID.
  // Only those few processes need to differ, so 32 bits keep it short to read out.
  public readonly instanceId: string = randomBytes(4).toString('hex');

  constructor(cwd: string) {
    const packagePath = this.getPackagePath(cwd);
    const packageData = this.getPackageData(packagePath);

    this.cwd = packagePath ? path.dirname(packagePath) : cwd;
    this.version = process.env.VERSION ?? packageData?.version;
    this.distribution = packageData?.brightCli?.distribution;
  }

  private getPackageData(packagePath: string) {
    try {
      const pkg = readFileSync(packagePath, 'utf8');

      return JSON.parse(pkg);
    } catch {
      // noop
    }
  }

  private getPackagePath(cwd?: string): string {
    return sync('package.json', {
      cwd: cwd || process.env.BRIGHT_CWD || process.cwd()
    });
  }
}
