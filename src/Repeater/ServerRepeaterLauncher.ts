import { RepeaterLauncher } from './RepeaterLauncher';
import {
  DeploymentRuntime,
  RepeaterLimitsEvent,
  RepeaterErrorCodes,
  RepeaterServer,
  RepeaterServerErrorEvent,
  RepeaterServerEvents,
  RepeaterServerNetworkTestEvent,
  RepeaterServerReconnectionFailedEvent,
  RepeaterServerRequestEvent,
  RepeaterServerRequestResponse
} from './RepeaterServer';
import { RuntimeDetector } from './RuntimeDetector';
import { ScriptLoader, VirtualScripts, VirtualScriptType } from '../Scripts';
import { StartupManager } from '../StartupScripts';
import {
  Certificates,
  Request,
  RequestExecutorOptions
} from '../RequestExecutor';
import { Helpers, logger } from '../Utils';
import { CliInfo } from '../Config';
import { RepeaterCommandHub } from './RepeaterCommandHub';
import { delay, inject, injectable } from 'tsyringe';
import chalk from 'chalk';
import { captureException, setTag } from '@sentry/node';

@injectable()
export class ServerRepeaterLauncher implements RepeaterLauncher {
  private static readonly SERVICE_NAME = 'bright-repeater';
  private repeaterRunning: boolean = false;
  private repeaterId: string | undefined;

  constructor(
    @inject(RuntimeDetector) private readonly runtimeDetector: RuntimeDetector,
    @inject(VirtualScripts) private readonly virtualScripts: VirtualScripts,
    @inject(RepeaterServer) private readonly repeaterServer: RepeaterServer,
    @inject(StartupManager)
    private readonly startupManager: StartupManager,
    @inject(RepeaterCommandHub)
    private readonly commandHub: RepeaterCommandHub,
    @inject(Certificates) private readonly certificates: Certificates,
    @inject(ScriptLoader) private readonly scriptLoader: ScriptLoader,
    @inject(RequestExecutorOptions)
    private readonly requestExecutorOptions: RequestExecutorOptions,
    @inject(delay(() => CliInfo)) private readonly info: CliInfo
  ) {}

  public close() {
    this.repeaterRunning = false;

    this.repeaterServer.disconnect();

    return Promise.resolve();
  }

  public async install(): Promise<void> {
    const { command, args: execArgs } = Helpers.getExecArgs({
      escape: false,
      include: ['--run'],
      exclude: ['--daemon', '-d']
    });

    await this.startupManager.install({
      command,
      args: execArgs,
      name: ServerRepeaterLauncher.SERVICE_NAME,
      displayName: 'Bright Repeater'
    });

    logger.log(
      'A Repeater daemon process was initiated successfully (SERVICE: %s)',
      ServerRepeaterLauncher.SERVICE_NAME
    );
  }

  public loadCerts(cacert: string): Promise<void> {
    return this.certificates.load(cacert);
  }

  public loadScripts(scripts: Record<string, string>): Promise<void> {
    return this.scriptLoader.load(scripts);
  }

  public async uninstall(): Promise<void> {
    await this.startupManager.uninstall(ServerRepeaterLauncher.SERVICE_NAME);

    logger.log(
      'The Repeater daemon process (SERVICE: %s) was stopped and deleted successfully',
      ServerRepeaterLauncher.SERVICE_NAME
    );
  }

  public async run(
    repeaterId: string,
    asDaemon: boolean = false
  ): Promise<void> {
    if (this.repeaterRunning) {
      return;
    }

    this.repeaterRunning = true;

    setTag('bridge_id', repeaterId);

    if (asDaemon) {
      await this.startupManager.run(() => this.close());
    }

    logger.log('Starting the Repeater (%s)...', this.info.version);

    this.repeaterId = repeaterId;

    this.subscribeToEvents();

    await this.repeaterServer.connect(this.repeaterId);
  }

  private getRuntime(): DeploymentRuntime {
    return {
      version: this.info.version,
      scriptsLoaded: !!this.virtualScripts.size,
      localScriptsLoaded: !!this.virtualScripts.count(VirtualScriptType.LOCAL),
      ci: this.runtimeDetector.ci(),
      os: this.runtimeDetector.os(),
      arch: this.runtimeDetector.arch(),
      docker: this.runtimeDetector.isInsideDocker(),
      distribution: this.runtimeDetector.distribution(),
      nodeVersion: this.runtimeDetector.nodeVersion()
    };
  }

  private subscribeToEvents() {
    this.repeaterServer.on(RepeaterServerEvents.CONNECTED, this.deployRepeater);
    this.repeaterServer.on(RepeaterServerEvents.ERROR, this.handleError);
    this.repeaterServer.on(
      RepeaterServerEvents.RECONNECTION_FAILED,
      this.reconnectionFailed
    );
    this.repeaterServer.on(RepeaterServerEvents.REQUEST, this.requestReceived);
    this.repeaterServer.on(RepeaterServerEvents.LIMITS, this.limitsReceived);
    this.repeaterServer.on(
      RepeaterServerEvents.TEST_NETWORK,
      this.testingNetwork
    );
    this.repeaterServer.on(RepeaterServerEvents.SCRIPTS_UPDATED, (payload) =>
      this.commandHub.compileScripts(payload.script)
    );
    this.repeaterServer.on(RepeaterServerEvents.UPDATE_AVAILABLE, (payload) =>
      logger.warn(
        '%s: A new Repeater version (%s) is available, for update instruction visit https://docs.brightsec.com/docs/cli-installation-guide',
        chalk.yellow('(!) IMPORTANT'),
        payload.version
      )
    );
    this.repeaterServer.on(
      RepeaterServerEvents.RECONNECT_ATTEMPT,
      ({ attempt }) =>
        logger.warn('Reconnecting to Bright cloud (attempt %d)', attempt)
    );
    this.repeaterServer.on(RepeaterServerEvents.RECONNECTION_SUCCEEDED, () =>
      logger.log('The Repeater (%s) connected', this.info.version)
    );
  }

  private handleError = ({
    code,
    message,
    remediation
  }: RepeaterServerErrorEvent) => {
    const normalizedMessage = this.normalizeMessage(message);
    const normalizedRemediation = this.normalizeMessage(remediation ?? '');

    if (this.isCriticalError(code)) {
      this.handleCriticalError(normalizedMessage, normalizedRemediation);
    } else {
      logger.error(normalizedMessage);
    }
  };

  private normalizeMessage(message: string): string {
    return message.replace(/\.$/, '');
  }

  private isCriticalError(code: RepeaterErrorCodes): boolean {
    return [
      RepeaterErrorCodes.REPEATER_DEACTIVATED,
      RepeaterErrorCodes.REPEATER_NO_LONGER_SUPPORTED,
      RepeaterErrorCodes.REPEATER_UNAUTHORIZED,
      RepeaterErrorCodes.REPEATER_ALREADY_STARTED,
      RepeaterErrorCodes.REPEATER_NOT_PERMITTED,
      RepeaterErrorCodes.UNEXPECTED_ERROR
    ].includes(code);
  }

  private handleCriticalError(message: string, remediation: string): void {
    logger.error('%s: %s. %s', chalk.red('(!) CRITICAL'), message, remediation);
    this.close().catch(logger.error);
    process.exitCode = 1;
  }

  private deployRepeater = async () => {
    try {
      await this.repeaterServer.deploy(
        {
          repeaterId: this.repeaterId
        },
        this.getRuntime()
      );
      logger.log('The Repeater (%s) started', this.info.version);
    } catch {
      // noop
    }
  };

  private reconnectionFailed = ({
    error
  }: RepeaterServerReconnectionFailedEvent) => {
    captureException(error);
    logger.error(error);
    this.close().catch(logger.error);
    process.exitCode = 1;
  };

  private testingNetwork = async (event: RepeaterServerNetworkTestEvent) => {
    try {
      const output = await this.commandHub.testNetwork(event.type, event.input);

      return {
        output
      };
    } catch (e) {
      return {
        error: typeof e === 'string' ? e : (e as Error).message
      };
    }
  };

  private limitsReceived = (event: RepeaterLimitsEvent) => {
    logger.debug('Limits received: %i', event.maxBodySize);
    this.requestExecutorOptions.maxBodySize = event.maxBodySize;
  };

  private requestReceived = async (
    event: RepeaterServerRequestEvent
  ): Promise<RepeaterServerRequestResponse> => {
    const response = await this.commandHub.sendRequest(
      new Request({ ...event })
    );

    const {
      statusCode,
      message,
      errorCode,
      body,
      headers,
      protocol,
      encoding,
      ttfb
    } = response;

    return {
      protocol,
      body,
      headers,
      statusCode,
      errorCode,
      message,
      encoding,
      ttfb
    };
  };
}
