import 'reflect-metadata';
import { RunRepeater } from './RunRepeater';
import { CliBuilder, CliInfo, ConfigReader } from '../Config';
import { DefaultRepeaterServerOptions } from '../Repeater';
import { RequestExecutorOptions } from '../RequestExecutor';
import container from '../container';
import { instance, mock } from 'ts-mockito';
import { Arguments, Argv } from 'yargs';

jest.mock('../Config/SystemConfigManager', () => ({
  SystemConfigManager: jest.fn().mockImplementation(() => ({
    read: jest.fn().mockResolvedValue({}),
    enableBackgroundRotation: jest.fn()
  }))
}));

describe('RunRepeater', () => {
  const repeaterId = '8PY6wKetVqmfMC9K9g4A7Y';
  const handler = jest.fn<Promise<void>, [Arguments]>();

  let cli: Argv;

  beforeAll(() => {
    const runRepeater = new RunRepeater();
    runRepeater.handler = handler;

    cli = new CliBuilder({
      info: new CliInfo(process.cwd()),
      configReader: instance(mock<ConfigReader>())
    }).build({ commands: [runRepeater] });
  });

  afterEach(() => handler.mockReset());

  describe('builder', () => {
    it.each([
      { flags: [], expected: 30_000 },
      { flags: ['--timeout', '45000'], expected: 45_000 },
      { flags: ['--timeout', '1m'], expected: 60_000 }
    ])(
      'should resolve the timeout to $expected ms given [$flags]',
      async ({ flags, expected }) => {
        // act
        await cli.parse([
          'repeater',
          '--id',
          repeaterId,
          '--token',
          'token',
          ...flags
        ]);

        // assert
        expect(handler).toHaveBeenCalledWith(
          expect.objectContaining({ timeout: expected })
        );
        expect(
          container.resolve<DefaultRepeaterServerOptions>(
            DefaultRepeaterServerOptions
          ).connectTimeout
        ).toBe(expected);
        expect(
          container.resolve<RequestExecutorOptions>(RequestExecutorOptions)
            .timeout
        ).toBe(expected);
      }
    );
  });
});
