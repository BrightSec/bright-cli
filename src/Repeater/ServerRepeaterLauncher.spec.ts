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
import {
  anything,
  capture,
  instance,
  mock,
  reset,
  spy,
  verify,
  when
} from 'ts-mockito';

describe('ServerRepeaterLauncher', () => {
  const mockedRepeaterServer = mock<RepeaterServer>();
  const mockedStartupManager = mock<StartupManager>();
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
      instance(mockedStartupManager),
      instance(mock<RepeaterCommandHub>()),
      instance(mock<Certificates>()),
      instance(mock<ScriptLoader>()),
      {} as RequestExecutorOptions,
      { version: '1.0.0' } as CliInfo
    );
  });

  afterEach(() => {
    handlers.clear();
    reset<RepeaterServer | Logger | StartupManager>(
      mockedRepeaterServer,
      loggerSpy,
      mockedStartupManager
    );
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

  describe('install', () => {
    it('should append the extra arguments to the service command line', async () => {
      // arrange
      when(mockedStartupManager.install(anything())).thenResolve();
      when(loggerSpy.log(anything(), anything())).thenReturn();

      // act
      await launcher.install(['--pkcs11-module', 'C:\\Bright\\vendor.dll']);

      // assert
      const { args } = capture(mockedStartupManager.install).last()[0];
      expect(args.slice(-3)).toEqual([
        '--run',
        '--pkcs11-module',
        'C:\\Bright\\vendor.dll'
      ]);
    });
  });
});
