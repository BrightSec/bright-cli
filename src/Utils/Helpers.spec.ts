import { Helpers } from './Helpers';
import { reset, spy, when } from 'ts-mockito';

enum TestEnum {
  TEST = 'test',
  PROD = 'prod'
}

describe('Helpers', () => {
  describe('getClusterUrls', () => {
    it('should returns localhost api and repeater server if --hostname is localhost', () => {
      // arrange
      const args = {
        hostname: 'localhost'
      };
      // act
      const result = Helpers.getClusterUrls(args);
      // assert

      expect(result).toEqual({
        api: 'http://localhost:8000',
        repeaterServer: 'ws://localhost:8000/workstations'
      });
    });

    it('should returns default values if --hostname, and --api not used', () => {
      // arrange
      const args = {};
      // act
      const result = Helpers.getClusterUrls(args);
      // assert
      expect(result).toEqual({
        api: 'https://app.brightsec.com',
        repeaterServer: 'wss://app.brightsec.com/workstations'
      });
    });

    it('should returns values with --hostname option', () => {
      // arrange
      const args = {
        hostname: 'test.com'
      };
      // act
      const result = Helpers.getClusterUrls(args);
      // assert
      expect(result).toEqual({
        api: 'https://test.com',
        repeaterServer: 'wss://test.com/workstations'
      });
    });

    it('should returns values with --cluster option', () => {
      // arrange
      const args = {
        cluster: 'test.com'
      };
      // act
      const result = Helpers.getClusterUrls(args);
      // assert
      expect(result).toEqual({
        api: 'https://test.com',
        repeaterServer: 'wss://test.com/workstations'
      });
    });
  });

  describe('getExecArgs', () => {
    let spiedProcess!: NodeJS.Process;

    beforeAll(() => (spiedProcess = spy(process)));

    afterAll(() => reset(spiedProcess));

    it('should return current exec args', () => {
      // arrange
      const options = { escape: false };
      // act
      const result = Helpers.getExecArgs(options);
      // assert
      expect(result).toMatchObject({
        windowsVerbatimArguments: false,
        command: process.execPath,
        args: [...process.execArgv, ...process.argv.slice(1)]
      });
    });

    it('should return exec args excluding all app args', () => {
      // arrange
      const options = { excludeAll: true, escape: false };
      // act
      const result = Helpers.getExecArgs(options);
      // assert
      expect(result).toMatchObject({
        windowsVerbatimArguments: false,
        command: process.execPath,
        args: expect.arrayContaining([process.argv[1]])
      });
    });

    it('should return exec args including extra args', () => {
      // arrange
      const extraArgs = ['--run'];
      const options = { include: extraArgs, escape: false };
      // act
      const result = Helpers.getExecArgs(options);
      // assert
      expect(result).toMatchObject({
        windowsVerbatimArguments: false,
        command: process.execPath,
        args: [...process.execArgv, ...process.argv.slice(1), ...extraArgs]
      });
    });

    it('should return exec args excluding specific args', () => {
      // arrange
      const excessArgs = [...process.argv].slice(-2);
      const options = { exclude: excessArgs, escape: false };
      // act
      const result = Helpers.getExecArgs(options);
      // assert
      expect(result).toMatchObject({
        windowsVerbatimArguments: false,
        command: process.execPath,
        args: [
          ...process.execArgv,
          ...process.argv.slice(1, process.argv.length - 2)
        ]
      });
    });

    it('should escape windows verbatim arguments', () => {
      // arrange
      const META_CHARS_REGEXP = /([()\][%!^"`<>&|;, *?])/g;

      const escapeShellArgument = (val: string): string => {
        val = `${val}`;
        val = val.replace(/(\\*)"/g, '$1$1\\"');
        val = val.replace(/(\\*)$/, '$1$1');
        val = `"${val}"`;

        return val.replace(META_CHARS_REGEXP, '^$1');
      };

      const options = { escape: true };

      when(spiedProcess.platform).thenReturn('win32');

      // act
      const result = Helpers.getExecArgs(options);
      // assert
      expect(result).toMatchObject({
        windowsVerbatimArguments: true,
        command: `"${process.execPath}"`,
        args: [
          ...process.execArgv.map(escapeShellArgument),
          ...process.argv.slice(1).map(escapeShellArgument)
        ]
      });
    });
  });

  describe('wildcardToRegExp', () => {
    [
      { wildcard: '*.example.com', input: 'sub.example.com', expected: true },
      {
        wildcard: '*.example.com',
        input: 'sub.sub.example.com',
        expected: true
      },
      { wildcard: '*.example.com', input: 'examp1e.com', expected: false },
      { wildcard: '*.example.com', input: 'example.co', expected: false },
      { wildcard: '*.example.com', input: 'example.com', expected: false },
      { wildcard: '*', input: 'sub.example.co', expected: true },
      { wildcard: '*', input: 'sub.sub.example.co', expected: true },
      { wildcard: '*', input: 'example.com', expected: true }
    ].forEach(({ wildcard, input, expected }) => {
      it(`regexp '${wildcard}' tests '${input}' ${
        expected ? 'positive' : 'negative'
      }`, () => {
        // arrange
        const regex = Helpers.wildcardToRegExp(wildcard);
        // act
        const test = regex.test(input);
        // assert
        expect(test).toBe(expected);
      });
    });
  });

  describe('selectEnumValue', () => {
    it('should found with case agnostic', () => {
      // arrange
      // act
      const actual = Helpers.selectEnumValue(TestEnum, 'TesT');
      // assert
      expect(actual).toBe(TestEnum.TEST);
    });
    it('should returns undefined', () => {
      // arrange
      // act
      const actual = Helpers.selectEnumValue(TestEnum, 'Staging');
      // assert
      expect(actual).toBeUndefined();
    });
  });

  describe('omit', () => {
    it('should returns valid object', () => {
      // arrange
      const input = {
        a: 1,
        b: 2,
        c: null as number,
        d: undefined as number,
        e: 3
      };
      // act
      const actual = Helpers.omit(input);
      // assert
      expect(actual).toEqual({ a: 1, b: 2, e: 3 });
    });
  });

  describe('split', () => {
    it('should split even array', () => {
      // arrange
      const items = [1, 2, 3, 4];
      // act
      const actual = Helpers.split(items, 2);
      // assert
      expect(actual).toEqual([
        [1, 2],
        [3, 4]
      ]);
    });
    it('should split odd array', () => {
      // arrange
      const items = [1, 2, 3, 4, 5];
      // act
      const actual = Helpers.split(items, 2);
      // assert
      expect(actual).toEqual([[1, 2], [3, 4], [5]]);
    });
    it('should split empty array', () => {
      const items: string[] = [];

      const actual = Helpers.split(items, 3);

      expect(actual).toEqual([]);
    });
  });
  describe('toArray', () => {
    it('should return array', () => {
      // arrange
      // act
      const actual = Helpers.toArray(TestEnum);
      // assert
      expect(actual).toEqual([TestEnum.TEST, TestEnum.PROD]);
    });
  });

  describe('parseHeaders', () => {
    it('should return empty object', () => {
      // arrange
      const input: string[] = [];

      // act
      const actual = Helpers.parseHeaders(input);

      // assert
      expect(actual).toEqual({});
    });

    it('should returns pairs of key/value even if value omitted', () => {
      // arrange
      const input: string[] = ['header1', 'header2: value2'];

      // act
      const actual = Helpers.parseHeaders(input);

      // assert
      expect(actual).toEqual({
        header1: '',
        header2: 'value2'
      });
    });

    it('should throw error', () => {
      const act = () => Helpers.parseHeaders({} as string[]);

      // assert
      expect(act).toThrow('First argument must be an instance of Array.');
    });
  });

  describe('parseDuration', () => {
    it.each([
      { input: 30, unit: 's', expected: 30_000 },
      { input: '30', unit: 's', expected: 30_000 },
      { input: '0.5', unit: 's', expected: 500 },
      { input: 30_000, unit: 'ms', expected: 30_000 },
      { input: '45000', unit: 'ms', expected: 45_000 },
      { input: '10s', unit: 's', expected: 10_000 },
      { input: '10s', unit: 'ms', expected: 10_000 },
      { input: '1m', unit: 'ms', expected: 60_000 },
      { input: '1h', unit: 's', expected: 3_600_000 }
    ] as const)(
      'should convert $input with numeric unit "$unit" to $expected milliseconds',
      ({ input, unit, expected }) => {
        // act
        const actual = Helpers.parseDuration(input, unit);

        // assert
        expect(actual).toBe(expected);
      }
    );
  });

  describe('portFromURL', () => {
    it('should return port 80 by default for http', () => {
      // arrange
      const url = new URL('http://example.com');

      // act
      const actual = Helpers.portFromURL(url);

      // assert
      expect(actual).toEqual('80');
    });

    it('should return port 443 by default for https', () => {
      // arrange
      const url = new URL('https://example.com');

      // act
      const actual = Helpers.portFromURL(url);

      // assert
      expect(actual).toEqual('443');
    });

    it('should return port as-is in URL', () => {
      // arrange
      const url = new URL('https://localhost:4443');

      // act
      const actual = Helpers.portFromURL(url);

      // assert
      expect(actual).toEqual('4443');
    });
  });
});
