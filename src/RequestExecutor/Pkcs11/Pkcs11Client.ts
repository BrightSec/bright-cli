import { CurlHandlePool } from './CurlHandlePool';
import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import { Pkcs11ModuleLoader } from './Pkcs11Module';
import { Pkcs11jsModuleLoader } from './Pkcs11jsModuleLoader';
import { Pkcs11OpenSslConfig } from './Pkcs11OpenSslConfig';
import { Pkcs11Identity, Pkcs11Preflight } from './Pkcs11Preflight';
import { Pkcs11ProviderLocator } from './Pkcs11ProviderLocator';
import { Pkcs11Cert, Pkcs11Options } from '../Pkcs11Cert';
import { Helpers, logger } from '../../Utils';
import { delimiter, dirname } from 'node:path';

export interface Pkcs11ClientDependencies {
  loader?: Pkcs11ModuleLoader;
  locateProvider?: (explicit?: string) => string;
  writeConfig?: typeof Pkcs11OpenSslConfig.write;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
}

/**
 * Everything the HTTP executor needs for PKCS#11 targets: which certificate
 * applies to a URL, its verified identity, and the long-lived easy handles to
 * send the request on.
 */
export class Pkcs11Client {
  private readonly pools = new Map<Pkcs11Cert, CurlHandlePool>();
  private readonly preflight?: Pkcs11Preflight;
  private readonly setupError?: Pkcs11Error;

  constructor(
    private readonly options: Pkcs11Options,
    {
      loader = new Pkcs11jsModuleLoader(),
      locateProvider = (explicit?: string): string =>
        Pkcs11ProviderLocator.locate(explicit),
      writeConfig = Pkcs11OpenSslConfig.write,
      env = process.env,
      platform = process.platform
    }: Pkcs11ClientDependencies = {}
  ) {
    try {
      const modules = new Set(options.certs.map(({ module }) => module));

      if (modules.size !== 1) {
        throw new Error(
          `All PKCS#11 certificates must use the same vendor module; found ${[
            ...modules
          ].join(', ')}.`
        );
      }

      const provider = locateProvider(options.provider);
      const config = writeConfig(provider, [...modules][0]);

      if (env.OPENSSL_CONF && env.OPENSSL_CONF !== config.path) {
        logger.warn(
          'PKCS#11: ignoring OPENSSL_CONF=%s for PKCS#11 connections; the Repeater uses its own generated config for them.',
          env.OPENSSL_CONF
        );
      }

      // curl reads it into each easy handle's library context when the
      // provider is first selected, so it must be set before any PKCS#11 request.
      env.OPENSSL_CONF = config.path;

      if (platform === 'win32') {
        // Windows resolves the provider's own DLL dependencies
        // (libcrypto-3-x64.dll) through PATH, not its directory.
        env.PATH = `${dirname(provider)}${delimiter}${env.PATH ?? ''}`;
      }

      logger.debug('PKCS#11: using OpenSSL provider %s', provider);
      this.preflight = new Pkcs11Preflight(loader, config.name, { env });
    } catch (e) {
      this.setupError =
        e instanceof Pkcs11Error
          ? e
          : new Pkcs11Error(Pkcs11ErrorCode.MODULE_LOAD_FAILED, e.message);
      logger.error('PKCS#11: %s', this.setupError.message);
    }
  }

  /** Starts the checks so that a broken setup is reported at startup. */
  public warmUp(): void {
    for (const cert of this.options.certs) {
      this.identity(cert).catch((): undefined => undefined);
    }
  }

  /** @returns the PKCS#11 certificates for `url`, in configuration order. */
  public match(url: string): Pkcs11Cert[] {
    const target = new URL(url);

    if (target.protocol !== 'https:') {
      return [];
    }

    const port = Helpers.portFromURL(target);

    return this.options.certs.filter(
      (cert: Pkcs11Cert) =>
        (cert.hostname === target.hostname ||
          Helpers.wildcardToRegExp(cert.hostname).test(target.hostname)) &&
        (!cert.port || cert.port === port)
    );
  }

  /** @throws Pkcs11Error */
  public identity(cert: Pkcs11Cert): Promise<Pkcs11Identity> {
    return this.setupError
      ? Promise.reject(this.setupError)
      : this.preflight.identity(cert);
  }

  public pool(cert: Pkcs11Cert): CurlHandlePool {
    let pool = this.pools.get(cert);

    if (!pool) {
      pool = new CurlHandlePool(cert.maxConcurrency);
      this.pools.set(cert, pool);
    }

    return pool;
  }
}
