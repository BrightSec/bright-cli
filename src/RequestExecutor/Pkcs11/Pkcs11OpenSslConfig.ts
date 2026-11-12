import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

export interface Pkcs11OpenSslConfigResult {
  path: string;
  /** OpenSSL provider name to pass as SSLENGINE. */
  name: string;
}

/**
 * Generates the OpenSSL config that curl loads into every easy handle's
 * library context. It holds paths only, never a PIN.
 */
export class Pkcs11OpenSslConfig {
  // OpenSSL's config syntax treats these as comments, quotes, variables or
  // line breaks, and there is no escaping that works for unquoted values.
  private static readonly UNSAFE = /["#$\\\n\r;]/;

  /**
   * Both providers tag their algorithms with a hard-coded `provider=<name>`
   * property, so an instance configured under any other name cannot use its
   * own keys ("provider keymgmt failure"). This also limits a process to one
   * instance, hence one vendor module.
   */
  public static providerName(provider: string): string {
    return /pkcs11prov/i.test(basename(provider)) ? 'pkcs11prov' : 'pkcs11';
  }

  /** @returns whether `path` can be written into the generated config. */
  public static isSafePath(path: string): boolean {
    return !Pkcs11OpenSslConfig.UNSAFE.test(path.replace(/\\/g, '/'));
  }

  public static render(
    provider: string,
    module: string
  ): { content: string; name: string } {
    const name = Pkcs11OpenSslConfig.providerName(provider);
    const modulePath = Pkcs11OpenSslConfig.path(module, 'module');
    const content = [
      'openssl_conf = openssl_init',
      '[openssl_init]',
      'providers = provider_sect',
      '[provider_sect]',
      'default = default_sect',
      `${name} = ${name}_sect`,
      '[default_sect]',
      'activate = 1',
      `[${name}_sect]`,
      `module = ${Pkcs11OpenSslConfig.path(provider, 'provider')}`,
      // libp11 reads pkcs11_module, pkcs11-provider reads pkcs11-module-path;
      // each ignores the other's keys.
      `pkcs11_module = ${modulePath}`,
      `pkcs11-module-path = ${modulePath}`,
      // pkcs11-provider instances otherwise invalidate each other's key
      // handles when several easy handles are alive.
      'pkcs11-module-quirks = no-deinit',
      'activate = 1',
      ''
    ].join('\n');

    return { content, name };
  }

  public static write(
    provider: string,
    module: string
  ): Pkcs11OpenSslConfigResult {
    const { content, name } = Pkcs11OpenSslConfig.render(provider, module);
    const dir = mkdtempSync(join(tmpdir(), 'bright-cli-pkcs11-'));
    chmodSync(dir, 0o700);
    process.once('exit', () => rmSync(dir, { recursive: true, force: true }));
    const path = join(dir, 'openssl.cnf');
    writeFileSync(path, content, { mode: 0o600 });

    return { path, name };
  }

  private static path(value: string, subject: string): string {
    // Forward slashes work on Windows too and need no escaping.
    const normalized = value.replace(/\\/g, '/');

    if (!Pkcs11OpenSslConfig.isSafePath(value)) {
      throw new Error(
        `The PKCS#11 ${subject} path ${value} contains a character OpenSSL cannot read from its config ("#", "$", ";", quotes or line breaks).`
      );
    }

    return normalized;
  }
}
