import 'reflect-metadata';
import { RunRepeater } from './RunRepeater';
import { CliBuilder, CliConfig, CliInfo, ConfigReader } from '../Config';
import { DefaultRepeaterServerOptions } from '../Repeater';
import { RequestExecutorOptions } from '../RequestExecutor';
import { Pkcs11PinPromptCancelledError } from '../RequestExecutor/Pkcs11/Pkcs11PinPrompt';
import container from '../container';
import { anything, instance, mock, when } from 'ts-mockito';
import { Arguments, Argv } from 'yargs';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';

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

  // CliBuilder configures the process-wide yargs singleton, so a cli built here
  // shares state with `cli`.
  const cliWith = (configReader: ConfigReader) => {
    const runRepeater = new RunRepeater();
    runRepeater.handler = handler;

    return new CliBuilder({
      info: new CliInfo(process.cwd()),
      configReader
    }).build({ commands: [runRepeater] });
  };

  // A parse that fails validation leaves the yargs singleton in a state that
  // breaks the next parse, so failing cases run against isolated modules.
  const isolatedCli = (): Argv => {
    let isolated: Argv;

    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { RunRepeater: IsolatedRunRepeater } = require('./RunRepeater');
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const config = require('../Config');
      const runRepeater = new IsolatedRunRepeater();
      runRepeater.handler = handler;
      isolated = new config.CliBuilder({
        info: new config.CliInfo(process.cwd()),
        configReader: instance(mock<ConfigReader>())
      }).build({ commands: [runRepeater] });
    });

    return isolated;
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

    it('should register the parsed --pkcs11-cert entries with the --pkcs11-module', async () => {
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
        module,
        provider: undefined,
        certs: [
          expect.objectContaining({ hostname: 'a.example.com' }),
          expect.objectContaining({ hostname: 'b.example.com', port: '8443' })
        ]
      });
    });

    it('should not start the repeater when --pkcs11-cert is given without --pkcs11-module', async () => {
      // act
      const result = settle(() =>
        parseRepeater(
          [
            '--pkcs11-cert',
            JSON.stringify({ hostname: 'a.example.com', pinFile })
          ],
          isolatedCli()
        )
      );

      // assert
      await expect(result).rejects.toThrow(
        'Option --pkcs11-module is required with --pkcs11-cert'
      );
      expect(handler).not.toHaveBeenCalled();
    });

    it('should not start the repeater when --pkcs11-module does not exist', async () => {
      // arrange
      const missing = join(dir, 'missing-pkcs11.so');

      // act
      const result = settle(() =>
        parseRepeater(['--pkcs11-module', missing], isolatedCli())
      );

      // assert
      await expect(result).rejects.toThrow(
        `Option --pkcs11-module ${missing} does not exist or is not a file.`
      );
      expect(handler).not.toHaveBeenCalled();
    });

    it('should reject a relative --pkcs11-module when installing the daemon', async () => {
      // act
      const result = settle(() =>
        parseRepeater(
          [
            '--daemon',
            '--pkcs11-module',
            relative(process.cwd(), module),
            '--pkcs11-cert',
            JSON.stringify({ hostname: 'a.example.com', pinFile })
          ],
          isolatedCli()
        )
      );

      // assert
      await expect(result).rejects.toThrow(
        /Option --pkcs11-module .* must be an absolute path when installing the daemon/
      );
      expect(handler).not.toHaveBeenCalled();
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
        parseRepeater(['--pkcs11-cert', entry], isolatedCli())
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
        parseRepeater(['--pkcs11-provider', provider], isolatedCli())
      );

      // assert
      await expect(result).rejects.toThrow(
        `Option --pkcs11-provider ${provider} does not exist or is not a file.`
      );
      expect(handler).not.toHaveBeenCalled();
    });

    it('should register an existing --pkcs11-provider with the certificates', async () => {
      // arrange
      const provider = join(dir, 'pkcs11prov.so');
      writeFileSync(provider, '');

      // act
      await parseRepeater([
        '--pkcs11-provider',
        provider,
        '--pkcs11-module',
        module,
        '--pkcs11-cert',
        JSON.stringify({ hostname: 'a.example.com', pinFile })
      ]);

      // assert
      expect(
        container.resolve<RequestExecutorOptions>(RequestExecutorOptions).pkcs11
          ?.provider
      ).toBe(provider);
    });

    it('should read the PIN variable named by "pinEnv" from the process environment', async () => {
      // arrange
      process.env.BRIGHT_SPEC_CARD_PIN = '1234';

      // act
      await settle(() =>
        parseRepeater([
          '--pkcs11-module',
          module,
          '--pkcs11-cert',
          JSON.stringify({
            hostname: 'a.example.com',
            pinEnv: 'BRIGHT_SPEC_CARD_PIN'
          })
        ])
      ).finally(() => delete process.env.BRIGHT_SPEC_CARD_PIN);

      // assert
      expect(
        container.resolve<RequestExecutorOptions>(RequestExecutorOptions).pkcs11
          ?.certs
      ).toEqual([expect.objectContaining({ pinEnv: 'BRIGHT_SPEC_CARD_PIN' })]);
    });

    it('should accept several entries from REPEATER_PKCS11_CERT as a JSON array', async () => {
      // arrange
      process.env.REPEATER_PKCS11_CERT = JSON.stringify([
        { hostname: 'a.example.com', pinFile },
        { hostname: 'b.example.com', pinFile }
      ]);

      // act
      await settle(() => parseRepeater(['--pkcs11-module', module])).finally(
        () => delete process.env.REPEATER_PKCS11_CERT
      );

      // assert
      expect(
        container
          .resolve<RequestExecutorOptions>(RequestExecutorOptions)
          .pkcs11?.certs.map(({ hostname }) => hostname)
      ).toEqual(['a.example.com', 'b.example.com']);
    });

    it('should reject "pinEnv" when installing the daemon', async () => {
      // arrange
      process.env.BRIGHT_SPEC_CARD_PIN = '1234';
      const entry = JSON.stringify({
        hostname: 'a.example.com',
        pinEnv: 'BRIGHT_SPEC_CARD_PIN'
      });

      // act
      const result = settle(() =>
        parseRepeater(
          ['--daemon', '--pkcs11-module', module, '--pkcs11-cert', entry],
          isolatedCli()
        )
      ).finally(() => delete process.env.BRIGHT_SPEC_CARD_PIN);

      // assert
      await expect(result).rejects.toThrow(
        /"pinEnv" is not available to the daemon service/
      );
      expect(handler).not.toHaveBeenCalled();
    });

    it.each([
      {
        name: 'REPEATER_PKCS11_CERT',
        flag: '--pkcs11-cert',
        value: () => JSON.stringify({ hostname: 'a.example.com', pinFile })
      },
      {
        name: 'REPEATER_PKCS11_MODULE',
        flag: '--pkcs11-module',
        value: () => module
      },
      {
        name: 'REPEATER_PKCS11_PROVIDER',
        flag: '--pkcs11-provider',
        value: () => module
      }
    ])(
      'should reject $name when installing the daemon',
      async ({ name, flag, value }) => {
        // arrange
        process.env[name] = value();

        // act
        const result = settle(() =>
          parseRepeater(['--daemon'], isolatedCli())
        ).finally(() => delete process.env[name]);

        // assert
        await expect(result).rejects.toThrow(
          `${name} is not available to the daemon service, which does not inherit this shell's environment. Pass ${flag} instead.`
        );
        expect(handler).not.toHaveBeenCalled();
      }
    );

    it('should not validate --pkcs11-module when removing the daemon', async () => {
      // act
      await parseRepeater([
        '--remove-daemon',
        '--pkcs11-module',
        join(dir, 'removed-pkcs11.so')
      ]);

      // assert
      expect(handler).toHaveBeenCalled();
    });

    it('should not validate --pkcs11-cert entries when removing the daemon', async () => {
      // arrange
      const entry = JSON.stringify({ hostname: 'a.example.com', pinFile });

      // act
      await parseRepeater(['--remove-daemon', '--pkcs11-cert', entry]);

      // assert
      expect(handler).toHaveBeenCalled();
    });

    it('should parse a --cert entry given as a JSON string on the command line', async () => {
      // act
      await parseRepeater([
        '--cert',
        JSON.stringify({
          hostname: 'c.example.com',
          path: './c.pfx',
          passphrase: 'secret',
          port: '8443'
        })
      ]);

      // assert
      expect(
        container.resolve<RequestExecutorOptions>(RequestExecutorOptions).certs
      ).toEqual([
        {
          hostname: 'c.example.com',
          path: 'c.pfx',
          passphrase: 'secret',
          port: '8443'
        }
      ]);
    });

    it.each([
      {
        source: 'arrays',
        config: {
          cert: [{ hostname: 'c.example.com', path: 'c.pfx' }],
          pkcs11Module: module,
          pkcs11Cert: [{ hostname: 'd.example.com', pinFile }]
        }
      },
      {
        source: 'single objects',
        config: {
          cert: { hostname: 'c.example.com', path: 'c.pfx' },
          pkcs11Module: module,
          pkcs11Cert: { hostname: 'd.example.com', pinFile }
        }
      }
    ])(
      'should accept --cert and --pkcs11-cert given as $source by the config file',
      async ({ config }) => {
        // arrange
        const reader = mock<ConfigReader>();
        when(reader.load(anything())).thenCall(() => instance(reader));
        when(reader.toJSON()).thenReturn(config as unknown as CliConfig);

        // act
        await parseRepeater(
          ['--config', join(dir, '.brightrc.json')],
          cliWith(instance(reader))
        );

        // assert
        const options = container.resolve<RequestExecutorOptions>(
          RequestExecutorOptions
        );
        expect(handler).toHaveBeenCalled();
        expect(options.certs).toEqual([
          expect.objectContaining({ hostname: 'c.example.com' })
        ]);
        expect(options.pkcs11?.module).toBe(module);
        expect(options.pkcs11?.certs).toEqual([
          expect.objectContaining({ hostname: 'd.example.com' })
        ]);
      }
    );
  });

  describe('handler', () => {
    const SIGNALS = ['SIGTERM', 'SIGINT', 'SIGHUP'] as const;
    let listeners: Map<string, NodeJS.SignalsListener[]>;

    beforeEach(() => {
      listeners = new Map(
        SIGNALS.map((signal) => [signal, process.listeners(signal)])
      );
    });

    afterEach(() => {
      jest.restoreAllMocks();
      process.exitCode = undefined;
      for (const signal of SIGNALS) {
        process
          .listeners(signal)
          .filter((listener) => !listeners.get(signal)?.includes(listener))
          .forEach((listener) => process.off(signal, listener));
      }
    });

    const arrange = (prepare: () => Promise<void>) => {
      const calls: string[] = [];
      const launcher = {
        run: jest.fn(() => {
          calls.push('run');

          return Promise.resolve();
        }),
        close: jest.fn(() => Promise.resolve()),
        install: jest.fn(() => Promise.resolve())
      };
      const executor = {
        prepare: jest.fn(() => {
          calls.push('prepare');

          return prepare();
        })
      };
      jest.spyOn(container, 'resolve').mockReturnValue(launcher);
      jest.spyOn(container, 'resolveAll').mockReturnValue([executor]);

      return { calls, launcher, executor };
    };

    const args = (extra: Record<string, unknown> = {}): Arguments => ({
      _: [],
      $0: 'bright-cli',
      id: repeaterId,
      ...extra
    });

    it('should prepare the executors before the Repeater connects', async () => {
      // arrange
      const { calls } = arrange(() => Promise.resolve());

      // act
      await new RunRepeater().handler(args());

      // assert
      expect(calls).toEqual(['prepare', 'run']);
    });

    it('should not start the Repeater when PIN entry is cancelled', async () => {
      // arrange
      const { launcher } = arrange(() =>
        Promise.reject(new Pkcs11PinPromptCancelledError())
      );

      // act
      await new RunRepeater().handler(args());

      // assert
      expect(launcher.run).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(1);
    });

    it('should not prepare the executors when installing the daemon', async () => {
      // arrange
      const { executor, launcher } = arrange(() => Promise.resolve());

      // act
      await new RunRepeater().handler(args({ daemon: true }));

      // assert
      expect(launcher.install).toHaveBeenCalled();
      expect(executor.prepare).not.toHaveBeenCalled();
    });
  });
});
