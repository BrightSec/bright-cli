import { CliConfig, ConfigReader } from './ConfigReader';
import { ClusterArgs, Helpers, logger, Logger, LogLevel } from '../Utils';
import { SystemConfigManager } from './SystemConfigManager';
import { CliInfo } from './CliInfo';
import { Arguments, Argv, CommandModule } from 'yargs';
import { init, runWithAsyncContext, setContext } from '@sentry/node';
import process from 'node:process';

export interface CliBuilderOptions {
  info: CliInfo;
  configReader: ConfigReader;
}

export class CliBuilder {
  private _options: CliBuilderOptions;

  get options(): CliBuilderOptions {
    return this._options;
  }

  constructor(options: CliBuilderOptions) {
    this._options = options;
  }

  public build({ commands }: { commands: CommandModule[] }): Argv {
    const { configReader, info } = this.options;
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const cli: Argv = require('yargs')
      .option('config', {
        requiresArg: true,
        describe: 'Path to the file with configuration',
        config: true,
        default: configReader.discovery(info.cwd),
        configParser: (configPath: string): CliConfig =>
          configReader.load(configPath).toJSON()
      })
      .option('log-level', {
        requiresArg: true,
        choices: Object.keys(LogLevel).map((x) =>
          !isNaN(+x) ? +x : x.toLowerCase()
        ),
        default: LogLevel.NOTICE,
        describe:
          'What level of logs to report. Any logs of a higher level than the setting are shown.'
      })
      .option('log-file', {
        requiresArg: true,
        type: 'string',
        describe:
          'File path to write logs to. If specified, logs will be written to this file'
      })
      .implies({
        'log-max-size': 'log-file',
        'log-max-files': 'log-file',
        'log-rotate-interval': 'log-file',
        'log-compress': 'log-file'
      })
      .group(
        [
          'log-max-size',
          'log-max-files',
          'log-rotate-interval',
          'log-compress'
        ],
        'Log Rotation Options (requires --log-file):'
      )
      .option('log-max-size', {
        requiresArg: true,
        type: 'string',
        describe:
          'Maximum size of log file before rotation (e.g., "10MB", "1GB"). Default: 10MB'
      })
      .option('log-max-files', {
        requiresArg: true,
        type: 'number',
        describe: 'Maximum number of rotated log files to keep. Default: 5'
      })
      .option('log-rotate-interval', {
        requiresArg: true,
        type: 'string',
        describe:
          'Time interval to rotate log files (e.g., "1d", "12h", "7d"). Default: 1d'
      })
      .option('log-compress', {
        type: 'boolean',
        describe: 'Compress rotated log files using gzip. Default: true'
      })
      .option('cluster', {
        deprecated: 'Use --hostname instead',
        requiresArg: true,
        describe:
          'Bright application name (domain name). [default: app.brightsec.com]'
      })
      .option('hostname', {
        requiresArg: true,
        describe:
          'Bright application name (domain name). [default: app.brightsec.com]'
      })
      .option('insecure', {
        boolean: true,
        default: false,
        description:
          'Allows CLI to proceed and operate even for server connections otherwise considered insecure.'
      })
      .option('proxy', {
        requiresArg: true,
        default: process.env.PROXY,
        describe:
          'Specify a proxy URL to route all traffic through. This should be an HTTP(S), SOCKS4, or SOCKS5 URL. By default, if you specify SOCKS://<URL>, then SOCKS5h is applied.'
      })
      .option('proxy-bright', {
        requiresArg: true,
        describe:
          'Specify a proxy URL to route all outbound traffic through. For more information, see the --proxy option.'
      })
      .option('proxy-target', {
        requiresArg: true,
        describe:
          'Specify a proxy URL to route all inbound traffic through. For more information, see the --proxy option.'
      })
      .option('timeout', {
        describe:
          'Request timeout in seconds or a duration string (e.g. 10s, 1m, 1h, 10h, 1y).',
        default: 30,
        coerce: (arg: string | number) => Helpers.parseDuration(arg, 's')
      })
      .conflicts({
        proxy: ['proxy-bright', 'proxy-target'],
        hostname: 'cluster'
      })
      .middleware((args: Arguments) => {
        const { api, repeaterServer } = Helpers.getClusterUrls(
          args as ClusterArgs
        );
        args.api = api;
        args.repeaterServer = repeaterServer;

        // Configure logger with rotation options if log file is specified
        if (args.logFile) {
          const options = {
            maxSize: args['log-max-size'] as string | '10MB',
            maxFiles: args['log-max-files'] as number | 5,
            interval: args['log-rotate-interval'] as string | '1d',
            compress: (args['log-compress'] === false ? undefined : 'gzip') as
              | 'gzip'
              | undefined
          };
          Logger.configure(
            args.logLevel as LogLevel,
            args.logFile as string,
            options
          );
        }
      })

      .middleware((argv: Arguments) => {
        logger.logLevel = argv['log-level'] as LogLevel;
        if (argv['log-file']) {
          logger.logFile = argv['log-file'] as string;
        }

        return argv;
      })

      .middleware(
        (args: Arguments) =>
          (logger.logLevel = !isNaN(+args.logLevel)
            ? (+args.logLevel as unknown as LogLevel)
            : LogLevel[
                args.logLevel?.toString().toUpperCase() as keyof typeof LogLevel
              ])
      )
      .usage('Usage: $0 <command> [options] [<file | scan>]')
      .pkgConf('bright', info.cwd)
      .example(
        '$0 archive:generate --mockfile=.mockfile --name=archive.har',
        'output har file on base your mock requests'
      );

    return commands
      .reduce(
        (acc: Argv, item: CommandModule) =>
          acc.command(this.wrapWithSentry(item)),
        cli
      )
      .recommendCommands()
      .demandCommand(1)
      .strict(true)
      .version(info.version)
      .alias('v', 'version')
      .help('help')
      .alias('h', 'help')
      .wrap(null);
  }

  private wrapWithSentry(command: CommandModule) {
    const handler = command.handler.bind(command);

    command.handler = async (args: Arguments) => {
      const systemConfigManager = new SystemConfigManager(args.api as string);
      const systemConfig = await systemConfigManager.read();

      return runWithAsyncContext(() => {
        this.initSentry(systemConfig.sentryDsn);
        setContext('args', args);

        systemConfigManager.enableBackgroundRotation((rotatedSystemConfig) => {
          this.initSentry(rotatedSystemConfig.sentryDsn);
        });

        return handler(args);
      });
    };

    return command;
  }

  private initSentry(dsn: string) {
    init({
      dsn,
      attachStacktrace: true,
      release: process.env.VERSION,
      ignoreErrors: [
        /The Repeater ID [\w]+ specified is currently being used by another Repeater\./,
        /The Repeater ID [\w]+ is inactive\./
      ],
      beforeSend(event) {
        if (event.contexts.args) {
          event.contexts.args = {
            ...event.contexts.args,
            t: event.contexts.args.t && '[Filtered]',
            token: event.contexts.args.token && '[Filtered]'
          };
        }

        return event;
      }
    });
  }
}
