import 'reflect-metadata';
import { ServerRepeaterLauncher } from './ServerRepeaterLauncher';
import {
  RepeaterServer,
  RepeaterServerEvents,
  RepeaterServerEventHandler,
  RepeaterServerRequestEvent,
  RepeaterServerRequestResponse,
  RepeaterErrorCodes
} from './RepeaterServer';
import { RepeaterCommandHub } from './RepeaterCommandHub';
import { RuntimeDetector } from './RuntimeDetector';
import { StartupManager } from '../StartupScripts';
import { ScriptLoader, VirtualScripts } from '../Scripts';
import {
  Certificates,
  Protocol,
  RequestExecutorOptions,
  Response
} from '../RequestExecutor';
import { CliInfo } from '../Config';
import { logger } from '../Utils';
import { anything, instance, mock, reset, verify, when } from 'ts-mockito';
import { captureException } from '@sentry/node';

jest.mock('@sentry/node', () => ({
  captureException: jest.fn(),
  setTag: jest.fn()
}));

describe('ServerRepeaterLauncher', () => {
  const runtimeDetectorMock = mock<RuntimeDetector>();
  const virtualScriptsMock = mock<VirtualScripts>();
  const startupManagerMock = mock<StartupManager>();
  const commandHubMock = mock<RepeaterCommandHub>();
  const certificatesMock = mock<Certificates>();
  const scriptLoaderMock = mock<ScriptLoader>();
  const requestExecutorOptionsMock = mock<RequestExecutorOptions>();
  const cliInfoMock = mock<CliInfo>();

  // A fake RepeaterServer that records the handlers subscribeToEvents registers,
  // so the captured REQUEST handler can be driven directly.
  const handlers = new Map<string, RepeaterServerEventHandler<never>>();
  const repeaterServer: RepeaterServer = {
    disconnect: (): void => undefined,
    connect: (): Promise<void> => Promise.resolve(),
    deploy: (): Promise<never> => Promise.resolve() as never,
    on: (event, handler): void => {
      handlers.set(event, handler as RepeaterServerEventHandler<never>);
    },
    off: (): void => undefined
  };

  let sut: ServerRepeaterLauncher;
  let loggerErrorSpy: jest.SpyInstance;

  const requestHandler = (): ((
    event: RepeaterServerRequestEvent
  ) => Promise<RepeaterServerRequestResponse>) =>
    handlers.get(RepeaterServerEvents.REQUEST) as unknown as (
      event: RepeaterServerRequestEvent
    ) => Promise<RepeaterServerRequestResponse>;

  beforeEach(async () => {
    handlers.clear();
    (captureException as jest.Mock).mockClear();
    loggerErrorSpy = jest.spyOn(logger, 'error').mockImplementation(() => 0);

    when(cliInfoMock.version).thenReturn('0.0.0-test');
    when(virtualScriptsMock.size).thenReturn(0);
    when(virtualScriptsMock.count(anything())).thenReturn(0);

    sut = new ServerRepeaterLauncher(
      instance(runtimeDetectorMock),
      instance(virtualScriptsMock),
      repeaterServer,
      instance(startupManagerMock),
      instance(commandHubMock),
      instance(certificatesMock),
      instance(scriptLoaderMock),
      instance(requestExecutorOptionsMock),
      instance(cliInfoMock)
    );

    // run() wires subscribeToEvents, registering the REQUEST handler.
    await sut.run('repeater-1');
  });

  afterEach(() => {
    loggerErrorSpy.mockRestore();
    reset(commandHubMock);
  });

  describe('run', () => {
    const okResponse = (): Response =>
      ({
        protocol: Protocol.HTTP,
        statusCode: 200,
        headers: { 'content-type': 'text/plain' },
        body: 'ok'
      } as unknown as Response);

    it('should ack with a protocol error when the request payload cannot be constructed', async () => {
      // arrange — a URL the Request constructor still rejects post-relaxation
      // (blank after trim).
      const event: RepeaterServerRequestEvent = {
        protocol: Protocol.HTTP,
        url: ''
      };

      // act
      const response = await requestHandler()(event);

      // assert
      expect(response).toEqual({
        protocol: Protocol.HTTP,
        protocolError: {
          code: RepeaterErrorCodes.MALFORMED_REQUEST,
          message: 'Invalid URL: '
        }
      });
    });

    it('should not invoke the command hub when the request payload cannot be constructed', async () => {
      // arrange
      const event: RepeaterServerRequestEvent = {
        protocol: Protocol.HTTP,
        url: ''
      };

      // act
      await requestHandler()(event);

      // assert
      verify(commandHubMock.sendRequest(anything())).never();
    });

    it('should ack with message and errorCode when execution itself fails', async () => {
      // arrange — a constructible request whose execution fails is a distinct
      // error class from a malformed payload.
      when(commandHubMock.sendRequest(anything())).thenResolve({
        protocol: Protocol.HTTP,
        message: 'Connection refused',
        errorCode: 'ECONNREFUSED'
      } as unknown as Response);
      const event: RepeaterServerRequestEvent = {
        protocol: Protocol.HTTP,
        url: 'http://valid.test/'
      };

      // act
      const response = await requestHandler()(event);

      // assert
      expect(response).toMatchObject({
        protocol: Protocol.HTTP,
        message: 'Connection refused',
        errorCode: 'ECONNREFUSED'
      });
      expect('protocolError' in response).toBe(false);
    });

    it('should ack with the response fields on a successful request', async () => {
      // arrange
      when(commandHubMock.sendRequest(anything())).thenResolve(okResponse());
      const event: RepeaterServerRequestEvent = {
        protocol: Protocol.HTTP,
        url: 'http://valid.test/'
      };

      // act
      const response = await requestHandler()(event);

      // assert
      expect(response).toMatchObject({
        protocol: Protocol.HTTP,
        statusCode: 200,
        body: 'ok'
      });
    });

    it('should not report a rejected payload to Sentry', async () => {
      // arrange
      const event: RepeaterServerRequestEvent = {
        protocol: Protocol.HTTP,
        url: ''
      };

      // act
      await requestHandler()(event);

      // assert — a rejected payload is a logger.error, never a Sentry event.
      expect(captureException).not.toHaveBeenCalled();
      expect(loggerErrorSpy).toHaveBeenCalled();
    });

    it('should log a reconnecting warning on a reconnection attempt', () => {
      // arrange
      const loggerWarnSpy = jest
        .spyOn(logger, 'warn')
        .mockImplementation(() => 0);

      // act
      (
        handlers.get(RepeaterServerEvents.RECONNECT_ATTEMPT) as (
          payload: unknown
        ) => unknown
      )({ attempt: 2 });

      // assert
      expect(loggerWarnSpy).toHaveBeenCalledWith(
        'Reconnecting to Bright cloud (attempt %d)',
        2
      );
      loggerWarnSpy.mockRestore();
    });
  });
});
