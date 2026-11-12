import { CurlHandlePool } from './CurlHandlePool';
import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import { Pkcs11ModuleLoader } from './Pkcs11Module';
import { Pkcs11jsModuleLoader } from './Pkcs11jsModuleLoader';
import { Pkcs11OpenSslConfig } from './Pkcs11OpenSslConfig';
import { Pkcs11PinPrompt } from './Pkcs11PinPrompt';
import { Pkcs11PinStore } from './Pkcs11PinStore';
import { Pkcs11Identity, Pkcs11Preflight } from './Pkcs11Preflight';
import { Pkcs11ProviderLocator } from './Pkcs11ProviderLocator';
import { TerminalPinPrompt } from './TerminalPinPrompt';
import { Pkcs11Cert, Pkcs11Options } from '../Pkcs11Cert';
import { Helpers, logger } from '../../Utils';
import { delimiter, dirname } from 'node:path';

export interface Pkcs11ClientDependencies {
  loader?: Pkcs11ModuleLoader;
  locateProvider?: (explicit?: string) => string;
  writeConfig?: typeof Pkcs11OpenSslConfig.write;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  prompt?: Pkcs11PinPrompt;
}

/**
 * Everything the HTTP executor needs for PKCS#11 targets: which certificate
 * applies to a URL, its verified identity, and the long-lived easy handles to
 * send the request on.
 */
export class Pkcs11Client {
  private readonly pools = new Map<Pkcs11Cert, CurlHandlePool>();
  private readonly pins = new Pkcs11PinStore();
  private readonly prompt: Pkcs11PinPrompt;
  private readonly preflight?: Pkcs11Preflight;
  private readonly setupError?: Pkcs11Error;
  private started?: Promise<void>;

  constructor(
    private readonly options: Pkcs11Options,
    {
      loader = new Pkcs11jsModuleLoader(),
      locateProvider = (explicit?: string): string =>
        Pkcs11ProviderLocator.locate(explicit),
      writeConfig = Pkcs11OpenSslConfig.write,
      env = process.env,
      platform = process.platform,
      prompt = new TerminalPinPrompt()
    }: Pkcs11ClientDependencies = {}
  ) {
    this.prompt = prompt;

    try {
      const provider = locateProvider(options.provider);
      const config = writeConfig(provider, options.module);

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
        // OpenSSL reads OPENSSL_CONF through the CRT's getenv(), which only sees
        // the environment as it was at process start. With this flag set it
        // reads through GetEnvironmentVariableW, which sees the value above.
        env.OPENSSL_WIN32_UTF8 = '1';
      }

      logger.debug('PKCS#11: using OpenSSL provider %s', provider);
      this.preflight = new Pkcs11Preflight(
        loader,
        { module: options.module, provider: config.name },
        { env, pins: this.pins }
      );
    } catch (e) {
      this.setupError =
        e instanceof Pkcs11Error
          ? e
          : new Pkcs11Error(Pkcs11ErrorCode.MODULE_LOAD_FAILED, e.message);
      logger.error('PKCS#11: %s', this.setupError.message);
    }
  }

  /**
   * Asks for the missing PINs, then starts the checks so that a broken setup
   * is reported at startup. Runs once; the terminal is never asked afterwards.
   *
   * @throws Pkcs11PinPromptCancelledError
   */
  public start(): Promise<void> {
    this.started ??= this.askForPins().then(() => this.warmUp());

    return this.started;
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

  private async askForPins(): Promise<void> {
    // Without a terminal the checks report the missing PINs.
    if (this.setupError || !this.prompt.interactive) {
      return;
    }

    const certs = this.options.certs.filter(
      (cert: Pkcs11Cert) => !cert.pinFile && !cert.pinEnv && this.needsPin(cert)
    );

    for (const cert of certs) {
      await this.askForPin(cert);
    }
  }

  private async askForPin(cert: Pkcs11Cert): Promise<void> {
    const pin = await this.prompt.ask(
      `Enter the PKCS#11 PIN for ${this.describe(cert)}: `
    );

    if (pin) {
      this.pins.set(cert, pin);
    } else {
      logger.warn(
        'PKCS#11: no PIN entered for %s; its requests will fail until the Repeater restarts.',
        cert.hostname
      );
    }
  }

  private needsPin(cert: Pkcs11Cert): boolean {
    try {
      return this.preflight.requiresPin(cert);
    } catch (e) {
      // A card that is missing now may be inserted later, but the PIN can be
      // asked for only now. A module that does not load fails every request anyway.
      return !(
        e instanceof Pkcs11Error &&
        e.code === Pkcs11ErrorCode.MODULE_LOAD_FAILED
      );
    }
  }

  private describe({ hostname, port, token, label, id }: Pkcs11Cert): string {
    const details = [
      token !== undefined ? `token "${token}"` : '',
      label !== undefined ? `label "${label}"` : '',
      id !== undefined ? `id ${id}` : ''
    ].filter(Boolean);

    return `${hostname}${port ? `:${port}` : ''}${
      details.length ? ` (${details.join(', ')})` : ''
    }`;
  }
}
