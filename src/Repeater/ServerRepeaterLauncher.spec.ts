import 'reflect-metadata';
import { ServerRepeaterLauncher } from './ServerRepeaterLauncher';
import { RepeaterServer, RepeaterServerEvents } from './RepeaterServer';
import { RuntimeDetector } from './RuntimeDetector';
import { RepeaterCommandHub } from './RepeaterCommandHub';
import { ScriptLoader, VirtualScripts } from '../Scripts';
import { StartupManager } from '../StartupScripts';
import { Certificates, RequestExecutorOptions } from '../RequestExecutor';
import { CliInfo } from '../Config';
import { Logger, logger } from '../Utils';
import { anything, instance, mock, reset, spy, verify, when } from 'ts-mockito';

describe('ServerRepeaterLauncher', () => {
  const mockedRepeaterServer = mock<RepeaterServer>();
  const handlers = new Map<string, (payload?: unknown) => unknown>();

  let loggerSpy: Logger;
  let launcher: ServerRepeaterLauncher;

  beforeEach(() => {
    loggerSpy = spy(logger);
    when(loggerSpy.warn(anything(), anything())).thenReturn();
    when(mockedRepeaterServer.on(anything(), anything())).thenCall(
      (event: string, handler: (payload?: unknown) => unknown) =>
        handlers.set(event, handler)
    );

    launcher = new ServerRepeaterLauncher(
      instance(mock<RuntimeDetector>()),
      instance(mock<VirtualScripts>()),
      instance(mockedRepeaterServer),
      instance(mock<StartupManager>()),
      instance(mock<RepeaterCommandHub>()),
      instance(mock<Certificates>()),
      instance(mock<ScriptLoader>()),
      {} as RequestExecutorOptions,
      { version: '1.0.0' } as CliInfo
    );
  });

  afterEach(() => {
    handlers.clear();
    reset<RepeaterServer | Logger>(mockedRepeaterServer, loggerSpy);
  });

  describe('run', () => {
    it('should log a reconnecting warning on a reconnection attempt', async () => {
      // arrange
      await launcher.run('8PY6wKetVqmfMC9K9g4A7Y');

      // act
      handlers.get(RepeaterServerEvents.RECONNECT_ATTEMPT)?.({ attempt: 2 });

      // assert
      verify(
        loggerSpy.warn('Reconnecting to Bright cloud (attempt %d)', 2)
      ).once();
    });
  });
});
