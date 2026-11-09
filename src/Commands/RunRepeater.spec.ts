import 'reflect-metadata';
import { RunRepeater } from './RunRepeater';
import { CliBuilder, CliInfo, ConfigReader } from '../Config';
import { DefaultRepeaterServerOptions } from '../Repeater';
import { RequestExecutorOptions } from '../RequestExecutor';
import container from '../container';
import { instance, mock } from 'ts-mockito';
import { Arguments, Argv } from 'yargs';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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

  const parseRepeater = (flags: string[], parser: Argv = cli) =>
    parser.parse([
      'repeater',
      '--id',
      repeaterId,
      '--token',
      'token',
      ...flags
    ]);

  // yargs throws synchronously when validation fails; this turns it into a rejection.
  const settle = (parse: () => unknown): Promise<unknown> =>
    Promise.resolve().then(parse);

  // A parse that fails validation leaves a yargs instance in a state that breaks
  // the next parse, so each failing case gets its own instance.
  const freshCli = (
    configReader: ConfigReader = instance(mock<ConfigReader>())
  ) => {
    const runRepeater = new RunRepeater();
    runRepeater.handler = handler;

    return new CliBuilder({
      info: new CliInfo(process.cwd()),
      configReader
    }).build({ commands: [runRepeater] });
  };

  describe('builder', () => {
    const dir = mkdtempSync(join(tmpdir(), 'run-repeater-pkcs11-'));
    const module = join(dir, 'vendor-pkcs11.so');
    const pinFile = join(dir, 'card.pin');

    beforeAll(() => {
      writeFileSync(module, '');
      writeFileSync(pinFile, '1234');
    });

    afterAll(() => rmSync(dir, { recursive: true, force: true }));

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

    it('should register the parsed --pkcs11-cert entries with the default --pkcs11-module', async () => {
      // act
      await parseRepeater([
        '--pkcs11-module',
        module,
        '--pkcs11-cert',
        JSON.stringify({ hostname: 'a.example.com', pinFile }),
        '--pkcs11-cert',
        JSON.stringify({ hostname: 'b.example.com', pinFile, port: '8443' })
      ]);

      // assert
      expect(handler).toHaveBeenCalled();
      expect(
        container.resolve<RequestExecutorOptions>(RequestExecutorOptions).pkcs11
      ).toEqual({
        provider: undefined,
        certs: [
          expect.objectContaining({ hostname: 'a.example.com', module }),
          expect.objectContaining({
            hostname: 'b.example.com',
            module,
            port: '8443'
          })
        ]
      });
    });

    it('should leave PKCS#11 disabled when no --pkcs11-cert is given', async () => {
      // act
      await parseRepeater(['--pkcs11-module', module]);

      // assert
      expect(handler).toHaveBeenCalled();
      expect(
        container.resolve<RequestExecutorOptions>(RequestExecutorOptions).pkcs11
      ).toBeUndefined();
    });

    it('should not start the repeater when a --pkcs11-cert entry is invalid', async () => {
      // arrange
      const entry = JSON.stringify({
        hostname: 'a.example.com',
        pinFile,
        pin: '1234'
      });

      // act
      const result = settle(() =>
        parseRepeater(['--pkcs11-cert', entry], freshCli())
      );

      // assert
      await expect(result).rejects.toThrow(
        'Option --pkcs11-cert #1 (hostname "a.example.com"): a literal "pin" is not accepted'
      );
      expect(handler).not.toHaveBeenCalled();
    });

    it('should not start the repeater when --pkcs11-provider does not exist', async () => {
      // arrange
      const provider = join(dir, 'missing-provider.so');

      // act
      const result = settle(() =>
        parseRepeater(['--pkcs11-provider', provider], freshCli())
      );

      // assert
      await expect(result).rejects.toThrow(
        `Option --pkcs11-provider has wrong value: ${provider} does not exist.`
      );
      expect(handler).not.toHaveBeenCalled();
    });

    it('should accept --cert and --pkcs11-cert entries given as objects by the config file', async () => {
      // arrange
      const config = {
        cert: [{ hostname: 'c.example.com', path: join(dir, 'c.pfx') }],
        pkcs11Cert: [{ hostname: 'd.example.com', module, pinFile }]
      };
      const configReader = {
        discovery: () => undefined,
        load() {
          return this;
        },
        toJSON: () => config
      } as unknown as ConfigReader;
      const configuredCli = freshCli(configReader);

      // act
      await configuredCli.parse([
        'repeater',
        '--id',
        repeaterId,
        '--token',
        'token',
        '--config',
        join(dir, '.brightrc.json')
      ]);

      // assert
      const options = container.resolve<RequestExecutorOptions>(
        RequestExecutorOptions
      );
      expect(handler).toHaveBeenCalled();
      expect(options.certs).toEqual([
        expect.objectContaining({ hostname: 'c.example.com' })
      ]);
      expect(options.pkcs11?.certs).toEqual([
        expect.objectContaining({ hostname: 'd.example.com', module })
      ]);
    });
  });
});
