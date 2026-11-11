import {
  Cert,
  Pkcs11CertParser,
  RequestExecutorOptions
} from '../RequestExecutor';
import { ErrorMessageFactory, Helpers, logger } from '../Utils';
import container from '../container';
import { DefaultRepeaterServerOptions, RepeaterLauncher } from '../Repeater';
import { Arguments, Argv, CommandModule } from 'yargs';
import { captureException } from '@sentry/node';
import { normalize } from 'node:path';
import process from 'node:process';

export class RunRepeater implements CommandModule {
  // Validation and registration see the same args object; parsing once keeps
  // the file and env checks from running twice.
  private static readonly pkcs11ByArgs = new WeakMap<
    Arguments,
    RequestExecutorOptions['pkcs11']
  >();

  // The daemon service is installed with argv only, so values from these are lost.
  private static readonly PKCS11_ENV_OPTIONS: Readonly<Record<string, string>> =
    {
      REPEATER_PKCS11_CERT: '--pkcs11-cert',
      REPEATER_PKCS11_MODULE: '--pkcs11-module',
      REPEATER_PKCS11_PROVIDER: '--pkcs11-provider'
    };

  public readonly command = 'repeater [options]';
  public readonly describe = 'Starts an on-prem agent.';

  private static checkPkcs11(args: Arguments): void {
    // Removing the daemon must work even if the card setup has since changed.
    if (args.remove) {
      return;
    }

    RunRepeater.pkcs11ByArgs.set(args, RunRepeater.parsePkcs11(args));
  }

  private static parsePkcs11(
    args: Arguments
  ): RequestExecutorOptions['pkcs11'] {
    const daemon = !!args.daemon;
    const provider = args.pkcs11Provider as string | undefined;
    const module = args.pkcs11Module as string | undefined;

    if (daemon) {
      RunRepeater.assertNoPkcs11Env();
    }

    const certs = Pkcs11CertParser.parse(args.pkcs11Cert, { daemon });
    const resolvedModule =
      module &&
      Pkcs11CertParser.resolveFile(module, 'Option --pkcs11-module', daemon);
    const resolvedProvider =
      provider &&
      Pkcs11CertParser.resolveFile(
        provider,
        'Option --pkcs11-provider',
        daemon
      );

    if (!certs.length) {
      return undefined;
    }

    if (!resolvedModule) {
      throw new Error(
        'Option --pkcs11-module is required with --pkcs11-cert: set it to the PKCS#11 library of the card vendor.'
      );
    }

    return { module: resolvedModule, provider: resolvedProvider, certs };
  }

  private static assertNoPkcs11Env(): void {
    for (const [name, flag] of Object.entries(RunRepeater.PKCS11_ENV_OPTIONS)) {
      if (process.env[name]) {
        throw new Error(
          `${name} is not available to the daemon service, which does not inherit this shell's environment. Pass ${flag} instead.`
        );
      }
    }
  }

  private static pkcs11Options(
    args: Arguments
  ): RequestExecutorOptions['pkcs11'] {
    if (args.remove) {
      return undefined;
    }

    return RunRepeater.pkcs11ByArgs.has(args)
      ? RunRepeater.pkcs11ByArgs.get(args)
      : RunRepeater.parsePkcs11(args);
  }

  public builder(argv: Argv): Argv {
    return argv
      .option('token', {
        alias: 't',
        describe: 'Bright API-key',
        requiresArg: true,
        demandOption: true
      })
      .option('id', {
        alias: 'agent',
        describe:
          'ID of an existing repeater which you want to use to run a new scan.',
        type: 'string',
        requiresArg: true,
        demandOption: true
      })
      .option('scripts', {
        alias: 'S',
        requiresArg: true,
        string: true,
        describe:
          'JSON string which contains script list, which is initially empty and consists of zero or more host and path pairs. Example: {"*.example.com": "./hmac.js"}',
        coerce(arg: string): Record<string, string> {
          return JSON.parse(arg);
        }
      })
      .option('timeout', {
        requiresArg: true,
        default: 30000,
        describe:
          'Time to wait for a server to send response headers (and start the response body) before aborting the request, in milliseconds or a duration string (e.g. 30s, 1m).',
        // Without its own coerce, yargs applies the global seconds-based
        // --timeout coercion to this millisecond default.
        coerce: (arg: string | number) => Helpers.parseDuration(arg, 'ms')
      })
      .option('header', {
        alias: 'H',
        requiresArg: true,
        conflicts: ['headers'],
        array: true,
        describe:
          'A list of specific headers that should be included into request.',
        coerce(arg: string[]): Record<string, string> {
          return Array.isArray(arg) ? Helpers.parseHeaders(arg) : {};
        }
      })
      .option('headers', {
        requiresArg: true,
        deprecated: 'Use --header instead.',
        string: true,
        conflicts: ['header'],
        describe:
          'JSON string which contains header list, which is initially empty and consists of zero or more name and value pairs. Example: {"x-slack-signature": "Z2dFIHJldHNhRQ"}',
        coerce(arg: string): Record<string, string> {
          return JSON.parse(arg);
        }
      })
      .option('cacert', {
        default: false,
        requiresArg: true,
        describe:
          'The path to file which may contain multiple CA certificates. Example: /etc/ssl/certs/ca-certificates.crt',
        coerce(arg: string): string | boolean {
          return typeof arg === 'string' || typeof arg === 'boolean'
            ? arg
            : false;
        }
      })
      .option('cert', {
        requiresArg: true,
        array: true,
        string: true,
        describe:
          'The certificate must be in PKCS, or PEM format. Example: {"hostname": "example.com", "path": "./example.pem", "passphrase": "pa$$word", "port": "1234"}.',
        coerce(args: (string | Cert)[] | Cert): Cert[] {
          // The config file supplies objects (or a single object), the CLI and env JSON strings.
          return (Array.isArray(args) ? args : [args])
            .map((arg: string | Cert) =>
              typeof arg === 'string' ? JSON.parse(arg) : arg
            )
            .map(({ path, hostname, passphrase, port }: Cert) => {
              if (!path) {
                logger.error(
                  'Error during "repeater": Specify the path to your client certificate file.'
                );
                process.exit(1);
              }

              if (!hostname) {
                logger.error(
                  'Error during "repeater": Specify the hostname (without protocol and port) of the request URL for which you want to use the certificate.'
                );
                process.exit(1);
              }

              return {
                hostname,
                passphrase,
                path: normalize(path),
                port
              };
            });
        }
      })
      .option('pkcs11-cert', {
        requiresArg: true,
        array: true,
        describe:
          'Client certificate whose private key is on a PKCS#11 token (smart card, USB token, HSM), for HTTPS targets. Requires --pkcs11-module. ' +
          'Required: "hostname", "pinFile" or "pinEnv". ' +
          'Optional: "port", "token" (token label), "label" and "id" (CKA_LABEL and hex CKA_ID of the certificate on the token, chosen at startup when absent), ' +
          '"certFile" (PEM file with the certificate instead of the one on the token; "label" and "id" then select the private key), "maxConcurrency" (default 1). ' +
          'Example: {"hostname": "example.com", "pinFile": "/run/secrets/card.pin", "label": "X.509 Certificate for PIV Authentication"}'
      })
      .option('pkcs11-module', {
        requiresArg: true,
        string: true,
        describe:
          'PKCS#11 library of the card vendor, used for all --pkcs11-cert entries. Example: "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll"'
      })
      .option('pkcs11-provider', {
        requiresArg: true,
        string: true,
        describe:
          'Path to the OpenSSL PKCS#11 provider plugin, if not in the default location.'
      })
      .option('experimental-connection-reuse', {
        deprecated: 'Use --ntlm instead',
        boolean: true,
        describe: 'Configure ntlm support (enables TCP connection reuse)'
      })
      .option('ntlm', {
        boolean: true,
        describe: 'Configure ntlm support (enables TCP connection reuse)'
      })
      .option('kerberos', {
        boolean: true,
        describe: 'Enable Kerberos/SPNEGO authentication for target requests'
      })
      .option('kerberos-domains', {
        requiresArg: true,
        array: true,
        describe:
          'Space-separated list of domains that should use Kerberos authentication. If omitted, applies to all domains.',
        coerce(arg: string[]): string[] {
          if (arg[0] === undefined) {
            return undefined;
          }

          if (arg.length === 1 && arg[0].includes(' ')) {
            return arg[0].trim().split(' ');
          }

          return arg;
        }
      })
      .option('kerberos-credentials', {
        requiresArg: true,
        string: true,
        describe:
          'Kerberos credentials in user:password format. If omitted, system keytab or existing ticket (kinit) is used.'
      })
      .option('kerberos-delegation', {
        boolean: true,
        describe: 'Allow Kerberos credential delegation to the target server'
      })
      .option('daemon', {
        requiresArg: false,
        alias: 'd',
        describe: 'Run as repeater in daemon mode'
      })
      .option('run', {
        requiresArg: false,
        hidden: true
      })
      .option('remove-daemon', {
        requiresArg: false,
        alias: ['rm', 'remove'],
        describe: 'Stop and remove repeater daemon'
      })
      .option('proxy-domains', {
        requiresArg: true,
        array: true,
        describe:
          'Space-separated list of domains that should be routed through the proxy. This option is only applicable when using the --proxy option',
        coerce(arg: string[]): string[] {
          if (arg[0] === undefined) {
            return undefined;
          }

          // if values are passed from env variable, they are passed as a single string
          if (arg.length === 1) {
            if (arg[0].includes(' ')) {
              return arg[0].trim().split(' ');
            }

            return arg;
          }

          return arg;
        }
      })
      .option('proxy-domains-bypass', {
        requiresArg: true,
        array: true,
        default: process.env.NO_PROXY?.trim()
          .split(',')
          .map((domain) => domain.trim()),
        describe:
          'Space-separated list of domains that should not be routed through the proxy. This option is only applicable when using the --proxy option',
        coerce(arg: string[]): string[] {
          // if values are passed from env variable, they are passed as a single string
          if (arg.length === 1) {
            if (arg[0] === undefined) {
              return undefined;
            }

            if (arg[0].includes(' ')) {
              return arg[0].trim().split(' ');
            }

            return arg;
          }

          return arg;
        }
      })
      .conflicts({
        daemon: 'remove-daemon',
        ntlm: ['proxy', 'experimental-connection-reuse', 'kerberos'],
        kerberos: ['ntlm']
      })
      .conflicts('proxy-domains', 'proxy-domains-bypass')
      .implies('kerberos-domains', 'kerberos')
      .implies('kerberos-credentials', 'kerberos')
      .implies('kerberos-delegation', 'kerberos')
      .env('REPEATER')
      .middleware((args: Arguments) => {
        if (Object.hasOwnProperty.call(args, '')) {
          // handling the case of having REPEATER environment variable w/o suffix,
          // that results in yargs option with empty name
          delete args[''];
        }
      }, true)
      .exitProcess(false)
      .check((args: Arguments) => {
        const id = args.id as string;
        if (!Helpers.isShortUUID(id) && !Helpers.isUUID(id)) {
          throw new Error(
            'Option --id has wrong value. Please ensure that --id option has a valid ID.'
          );
        }

        const proxyDomains = (args.proxyDomains as string[]) ?? [];
        for (const domain of proxyDomains) {
          if (domain.includes(',')) {
            throw new Error(
              `Option --proxy-domains has a wrong value.` +
                `Please ensure that --proxy-domains option has space separated list of domain values`
            );
          }
        }

        const proxyDomainsBypass = (args.proxyDomainsBypass as string[]) ?? [];
        for (const domain of proxyDomainsBypass) {
          if (domain.includes(',')) {
            throw new Error(
              `Option --proxy-domain-bypass has wrong value.` +
                `Please ensure that --proxy-domain-bypass option has space separated list of domain values`
            );
          }
        }

        RunRepeater.checkPkcs11(args);

        return true;
      })
      .middleware((args: Arguments) => {
        container
          .register<RequestExecutorOptions>(RequestExecutorOptions, {
            useValue: {
              headers: (args.header ?? args.headers) as Record<string, string>,
              timeout: args.timeout as number,
              proxyUrl: (args.proxyTarget ?? args.proxy) as string,
              certs: args.cert as Cert[],
              pkcs11: RunRepeater.pkcs11Options(args),
              maxBodySize: Infinity,
              maxContentLength: 100,
              reuseConnection:
                !!args.ntlm || !!args.experimentalConnectionReuse,
              whitelistMimes: [
                { type: 'text/html', allowTruncation: false },
                { type: 'text/plain', allowTruncation: true },
                { type: 'text/css', allowTruncation: false },
                { type: 'text/javascript', allowTruncation: false },
                { type: 'text/markdown', allowTruncation: true },
                { type: 'text/xml', allowTruncation: false },
                { type: 'application/javascript', allowTruncation: false },
                { type: 'application/x-javascript', allowTruncation: false },
                { type: 'application/json', allowTruncation: false },
                { type: 'application/xml', allowTruncation: false },
                {
                  type: 'application/x-www-form-urlencoded',
                  allowTruncation: false
                },
                { type: 'application/msgpack', allowTruncation: false },
                { type: 'application/ld+json', allowTruncation: false },
                { type: 'application/graphql', allowTruncation: false }
              ],
              proxyDomains: args.proxyDomains as string[],
              proxyDomainsBypass: args.proxyDomainsBypass as string[],
              kerberos: args.kerberos
                ? {
                    enabled: true,
                    domains: args.kerberosDomains as string[],
                    credentials: args.kerberosCredentials as string,
                    delegation: !!args.kerberosDelegation
                  }
                : undefined
            }
          })
          .register<DefaultRepeaterServerOptions>(
            DefaultRepeaterServerOptions,
            {
              useValue: {
                uri: args.repeaterServer as string,
                token: args.token as string,
                connectTimeout: args.timeout as number,
                proxyUrl: (args.proxyBright ?? args.proxy) as string,
                insecure: args.insecure as boolean
              }
            }
          );
      });
  }

  // eslint-disable-next-line complexity
  public async handler(args: Arguments): Promise<void> {
    const repeaterLauncher: RepeaterLauncher =
      container.resolve(RepeaterLauncher);

    if (args.cacert) {
      await repeaterLauncher.loadCerts(
        typeof args.cacert === 'string' ? args.cacert : undefined
      );
    }

    if (args.scripts) {
      await repeaterLauncher.loadScripts(
        args.scripts as Record<string, string>
      );
    }

    if (args.remove) {
      await repeaterLauncher.uninstall();
      process.exitCode = 0;

      return;
    }

    if (args.daemon) {
      await repeaterLauncher.install();
      process.exitCode = 0;

      return;
    }

    try {
      ['SIGTERM', 'SIGINT', 'SIGHUP'].forEach((event) =>
        process.on(event, async () => {
          await repeaterLauncher.close();
          process.exitCode = 0;
        })
      );

      await repeaterLauncher.run(args.id as string, args.run as boolean);
    } catch (error) {
      captureException(error);
      logger.error(
        ErrorMessageFactory.genericCommandError({ error, command: 'repeater' })
      );
      await repeaterLauncher.close();
      process.exitCode = 1;
    }
  }
}
