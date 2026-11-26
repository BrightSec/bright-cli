import { logger, ProxyFactory } from '../Utils';
import {
  DeployCommandOptions,
  DeploymentRuntime,
  RepeaterErrorCodes,
  RepeaterServer,
  RepeaterServerDeployedEvent,
  RepeaterServerErrorEvent,
  RepeaterServerEventHandler,
  RepeaterServerEvents,
  RepeaterServerEventsMap,
  RepeaterServerNetworkTestEvent,
  RepeaterServerNetworkTestResult,
  RepeaterServerReconnectionAttemptedEvent,
  RepeaterServerReconnectionFailedEvent,
  RepeaterServerRequestEvent,
  RepeaterServerRequestResponse,
  RepeaterServerScriptsUpdatedEvent,
  RepeaterUpgradeAvailableEvent,
  RepeaterLimitsEvent
} from './RepeaterServer';
import { inject, injectable } from 'tsyringe';
import io, { Socket } from 'socket.io-client';
import parser from 'socket.io-msgpack-parser';
import { captureException, captureMessage, withScope } from '@sentry/node';
import { EventEmitter, once } from 'node:events';

export interface DefaultRepeaterServerOptions {
  readonly uri: string;
  readonly token: string;
  readonly connectTimeout?: number;
  readonly proxyUrl?: string;
  readonly insecure?: boolean;
  readonly proxyDomains?: string[];
}

export const DefaultRepeaterServerOptions: unique symbol = Symbol(
  'DefaultRepeaterServerOptions'
);

type CallbackFunction<T = unknown> = (arg: T) => unknown;
type HandlerFunction = (args: unknown[]) => unknown;

const enum SocketEvents {
  DEPLOYED = 'deployed',
  DEPLOY = 'deploy',
  UNDEPLOY = 'undeploy',
  UNDEPLOYED = 'undeployed',
  TEST_NETWORK = 'test-network',
  ERROR = 'error',
  UPDATE_AVAILABLE = 'update-available',
  SCRIPT_UPDATED = 'scripts-updated',
  REQUEST = 'request',
  LIMITS = 'limits'
}

interface SocketListeningEventMap {
  [SocketEvents.DEPLOYED]: (event: RepeaterServerDeployedEvent) => void;
  [SocketEvents.UNDEPLOYED]: () => void;
  [SocketEvents.ERROR]: (event: RepeaterServerErrorEvent) => void;
  [SocketEvents.TEST_NETWORK]: (
    event: RepeaterServerNetworkTestEvent,
    callback: CallbackFunction<RepeaterServerNetworkTestResult>
  ) => void;
  [SocketEvents.UPDATE_AVAILABLE]: (
    event: RepeaterUpgradeAvailableEvent
  ) => void;
  [SocketEvents.SCRIPT_UPDATED]: (
    event: RepeaterServerScriptsUpdatedEvent
  ) => void;
  [SocketEvents.REQUEST]: (
    request: RepeaterServerRequestEvent,
    callback: CallbackFunction<RepeaterServerRequestResponse>
  ) => void;
  [SocketEvents.LIMITS]: (request: RepeaterLimitsEvent) => void;
}

interface SocketEmitEventMap {
  [SocketEvents.DEPLOY]: (
    options: DeployCommandOptions,
    runtime?: DeploymentRuntime
  ) => void;
  [SocketEvents.UNDEPLOY]: () => void;
}

@injectable()
export class DefaultRepeaterServer implements RepeaterServer {
  private readonly MAX_DEPLOYMENT_TIMEOUT = 60_000;
  private readonly MIN_RECONNECTION_DELAY = 1_000;
  private readonly MAX_RECONNECTION_DELAY = 5_000;
  private readonly events = new EventEmitter();
  private readonly handlerMap = new WeakMap<
    RepeaterServerEventHandler<any>,
    HandlerFunction
  >();
  private latestReconnectionError?: Error;
  private connectionTimer?: NodeJS.Timeout;
  private _socket?: Socket<SocketListeningEventMap, SocketEmitEventMap>;
  private connectionAttempts = 0;
  private disposed = false;

  private get socket() {
    if (!this._socket) {
      throw new Error(
        'Please make sure that repeater established a connection with host.'
      );
    }

    return this._socket;
  }

  constructor(
    @inject(ProxyFactory) private readonly proxyFactory: ProxyFactory,
    @inject(DefaultRepeaterServerOptions)
    private readonly options: DefaultRepeaterServerOptions
  ) {}

  public disconnect() {
    // Set before anything else: tearing the socket down synchronously emits
    // reserved events (`disconnect`, `connect_error`) whose handlers would
    // otherwise schedule a reconnection against the socket being disposed of.
    this.disposed = true;

    this.events.removeAllListeners();
    this.clearConnectionTimer();

    this._socket?.disconnect();
    this._socket?.removeAllListeners();
    this._socket?.io.removeAllListeners();
    this._socket = undefined;
  }

  public async deploy(
    options: DeployCommandOptions,
    runtime: DeploymentRuntime
  ): Promise<RepeaterServerDeployedEvent> {
    // Deferred callbacks must never dereference the socket through the throwing
    // getter: the socket may be gone by the time they run, and there is no
    // frame left to catch the error.
    process.nextTick(() =>
      this._socket?.emit(SocketEvents.DEPLOY, options, runtime)
    );

    const [result]: RepeaterServerDeployedEvent[] = await Promise.race([
      once(this.socket as unknown as EventEmitter, SocketEvents.DEPLOYED),
      new Promise<never>((_, reject) =>
        setTimeout(
          reject,
          this.MAX_DEPLOYMENT_TIMEOUT,
          new Error('No response.')
        ).unref()
      )
    ]);

    return result;
  }

  public async connect(hostname: string) {
    this.disposed = false;
    this.connectionAttempts = 0;

    this._socket = io(this.options.uri, {
      parser,
      path: '/api/ws/v1',
      transports: ['websocket'],
      reconnectionDelayMax: this.MAX_RECONNECTION_DELAY,
      reconnectionDelay: this.MIN_RECONNECTION_DELAY,
      timeout: this.options?.connectTimeout,
      rejectUnauthorized: !this.options.insecure,
      // @ts-expect-error Type is wrong.
      // Agent is passed directly to "ws" package, which accepts http.Agent
      agent: this.options.proxyUrl
        ? this.proxyFactory.createProxyForClient({
            proxyUrl: this.options.proxyUrl,
            targetUrl: this.options.uri,
            rejectUnauthorized: !this.options.insecure
          })
        : undefined,
      auth: {
        token: this.options.token,
        domain: hostname
      }
    });

    this.listenToReservedEvents();
    this.listenToApplicationEvents();

    await once(this.socket as unknown as EventEmitter, 'connect');

    logger.debug('Repeater connected to %s', this.options.uri);
  }

  public off<K extends keyof RepeaterServerEventsMap>(
    event: K,
    handler?: RepeaterServerEventHandler<K>
  ): void {
    const wrappedHandler = this.handlerMap.get(handler);
    if (wrappedHandler) {
      this.events.off(event, wrappedHandler);
      this.handlerMap.delete(handler);
    }
  }

  public on<K extends keyof RepeaterServerEventsMap>(
    event: K,
    handler: RepeaterServerEventHandler<K>
  ): void {
    const wrappedHandler = (...args: unknown[]) =>
      this.wrapEventListener(event, handler, ...args);
    this.handlerMap.set(handler, wrappedHandler);
    this.events.on(event, wrappedHandler);
  }

  private listenToApplicationEvents() {
    this.socket.on(SocketEvents.DEPLOYED, (event) =>
      this.events.emit(RepeaterServerEvents.DEPLOY, event)
    );
    this.socket.on(SocketEvents.REQUEST, (event, callback) =>
      this.events.emit(RepeaterServerEvents.REQUEST, event, callback)
    );
    this.socket.on(SocketEvents.TEST_NETWORK, (event, callback) =>
      this.events.emit(RepeaterServerEvents.TEST_NETWORK, event, callback)
    );
    this.socket.on(SocketEvents.ERROR, (event) => {
      captureMessage(event.message, {
        fingerprint: [event.code ?? 'repeater_socket_error']
      });
      this.events.emit(RepeaterServerEvents.ERROR, event);
    });
    this.socket.on(SocketEvents.UPDATE_AVAILABLE, (event) =>
      this.events.emit(RepeaterServerEvents.UPDATE_AVAILABLE, event)
    );
    this.socket.on(SocketEvents.SCRIPT_UPDATED, (event) =>
      this.events.emit(RepeaterServerEvents.SCRIPTS_UPDATED, event)
    );
    this.socket.on(SocketEvents.LIMITS, (event) =>
      this.events.emit(RepeaterServerEvents.LIMITS, event)
    );
  }

  private listenToReservedEvents() {
    this.socket.on('connect', this.handleConnect);
    this.socket.on('connect_error', this.handleConnectionError);
    this.socket.on('disconnect', this.handleDisconnect);
    this.socket.io.on('reconnect', () => {
      this.latestReconnectionError = undefined;
    });
    this.socket.io.on(
      'reconnect_error',
      (error) => (this.latestReconnectionError = error)
    );
    this.socket.io.on('reconnect_failed', () =>
      this.events.emit(RepeaterServerEvents.RECONNECTION_FAILED, {
        error: this.latestReconnectionError
      } as RepeaterServerReconnectionFailedEvent)
    );
    this.socket.io.on('reconnect_attempt', (attempt) =>
      this.events.emit(RepeaterServerEvents.RECONNECT_ATTEMPT, {
        attempt
      } as RepeaterServerReconnectionAttemptedEvent)
    );
    this.socket.io.on('reconnect', () =>
      this.events.emit(RepeaterServerEvents.RECONNECTION_SUCCEEDED)
    );
  }

  private handleConnectionError = (err: Error) => {
    const { data } = err as unknown as {
      data?: Omit<RepeaterServerErrorEvent, 'transaction'>;
    };

    if (data && this.isTerminalConnectionError(data)) {
      // Terminal by definition: retrying cannot change the outcome. Consumers
      // treat these as critical and tear the server down synchronously, so
      // scheduling a reconnection here would outlive the socket.
      this.events.emit(RepeaterServerEvents.ERROR, {
        ...data,
        message: err.message
      });

      return;
    }

    this.scheduleReconnection();
  };

  private isTerminalConnectionError(
    data: Omit<RepeaterServerErrorEvent, 'transaction'>
  ) {
    return [
      RepeaterErrorCodes.REPEATER_UNAUTHORIZED,
      RepeaterErrorCodes.REPEATER_NOT_PERMITTED
    ].includes(data.code);
  }

  private scheduleReconnection() {
    if (this.disposed) {
      return;
    }

    // A single pending attempt at a time: without this, every failed attempt
    // during an outage leaks another timer that nothing can cancel.
    this.clearConnectionTimer();

    let delay = Math.max(
      this.MIN_RECONNECTION_DELAY * 2 ** this.connectionAttempts,
      this.MIN_RECONNECTION_DELAY
    );
    delay += delay * 0.3 * Math.random();
    delay = Math.min(delay, this.MAX_RECONNECTION_DELAY);

    this.connectionAttempts++;

    this.events.emit(RepeaterServerEvents.RECONNECT_ATTEMPT, {
      attempt: this.connectionAttempts
    } as RepeaterServerReconnectionAttemptedEvent);
    // Intentionally referenced: a pending attempt must keep a long-running
    // Repeater alive while the network is down.
    this.connectionTimer = setTimeout(() => this._socket?.connect(), delay);
  }

  private async wrapEventListener<TArgs extends TArg[], TArg>(
    event: string,
    handler: (...payload: TArgs) => unknown,
    ...args: unknown[]
  ) {
    // Fork a Sentry scope per dispatched event so a per-request `trace_id` tag
    // applies ONLY to this forward's capture — a global `setTag` would
    // cross-contaminate concurrent forwards. The scope wraps the whole try/catch
    // so it also encloses the capture in `handleEventError`.
    return withScope(async (scope) => {
      if (event === RepeaterServerEvents.REQUEST) {
        const traceId = (args[0] as RepeaterServerRequestEvent | undefined)
          ?.traceId;
        if (traceId) {
          scope.setTag('trace_id', traceId);
        }
      }

      try {
        const callback = this.extractLastArgument(args);

        // eslint-disable-next-line @typescript-eslint/return-await
        const response = await handler(...(args as TArgs));

        callback?.(response);
      } catch (err) {
        this.handleEventError(err, event, args);
      }
    });
  }

  private extractLastArgument(args: unknown[]): CallbackFunction | undefined {
    const lastArg = args.pop();
    if (typeof lastArg === 'function') {
      return lastArg as CallbackFunction;
    } else {
      // If the last argument is not a function, add it back to the args array
      args.push(lastArg);

      return undefined;
    }
  }

  private clearConnectionTimer() {
    if (this.connectionTimer) {
      clearTimeout(this.connectionTimer);
      this.connectionTimer = undefined;
    }
  }

  private handleConnect = () => {
    this.connectionAttempts = 0;
    this.clearConnectionTimer();
    this.events.emit(RepeaterServerEvents.CONNECTED);
  };

  private handleDisconnect = (reason: string): void => {
    if (reason !== 'io client disconnect') {
      this.events.emit(RepeaterServerEvents.DISCONNECTED);
    }

    // the disconnection was initiated by the server, you need to reconnect manually
    if (reason === 'io server disconnect' && !this.disposed) {
      this._socket?.connect();
    }
  };

  private handleEventError(error: Error, event: string, args: unknown[]): void {
    captureException(error);
    logger.debug(
      'An error occurred while processing the %s event with the following payload: %j',
      event,
      args
    );
    logger.error(error);
  }
}
