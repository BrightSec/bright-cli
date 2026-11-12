import { TerminalPinPrompt } from './TerminalPinPrompt';
import { Pkcs11PinPromptCancelledError } from './Pkcs11PinPrompt';
import { Logger, LogLevel } from '../../Utils';
import { PassThrough } from 'node:stream';
import { EOL } from 'node:os';

describe('TerminalPinPrompt', () => {
  const terminal = ({ isTTY = true } = {}) => {
    const input = Object.assign(new PassThrough(), {
      isTTY,
      setRawMode: jest.fn()
    });
    // The prompt and the log share one terminal, so both write here.
    const screen: string[] = [];
    const output = {
      write: jest.fn((chunk: string) => screen.push(chunk))
    };
    const log = new Logger(LogLevel.VERBOSE);

    return {
      input,
      output,
      log,
      screen,
      prompt: new TerminalPinPrompt(input, output, log),
      written: () =>
        output.write.mock.calls.map(([chunk]: [string]) => chunk).join('')
    };
  };

  afterEach(() => jest.restoreAllMocks());

  describe('interactive', () => {
    it.each([
      { isTTY: true, expected: true },
      { isTTY: false, expected: false }
    ])(
      'should be $expected when the input TTY flag is $isTTY',
      ({ isTTY, expected }) => {
        // arrange
        const { prompt } = terminal({ isTTY });

        // act
        const result = prompt.interactive;

        // assert
        expect(result).toBe(expected);
      }
    );
  });

  describe('ask', () => {
    it('should return the typed PIN without echoing it', async () => {
      // arrange
      const { input, prompt, written } = terminal();

      // act
      const result = prompt.ask('PIN: ');
      input.write('12');
      input.write('34\r');

      // assert
      await expect(result).resolves.toBe('1234');
      expect(written()).toBe(`PIN: ${EOL}`);
    });

    it('should apply backspace and ignore arrow keys', async () => {
      // arrange
      const { input, prompt } = terminal();

      // act
      const result = prompt.ask('PIN: ');
      input.write('125');
      input.write('\u007f');
      input.write('\u001b[D');
      input.write('3\n');

      // assert
      await expect(result).resolves.toBe('123');
    });

    it('should restore the terminal mode once the PIN is entered', async () => {
      // arrange
      const { input, prompt } = terminal();

      // act
      const result = prompt.ask('PIN: ');
      input.write('1\r');
      await result;

      // assert
      expect(input.setRawMode.mock.calls).toEqual([[true], [false]]);
      expect(input.listenerCount('data')).toBe(0);
    });

    it.each([
      { action: 'entered', keys: '1234\r' },
      { action: 'cancelled', keys: '\u0003' }
    ])(
      'should print the log lines written while the PIN is typed after the PIN is $action',
      async ({ keys }) => {
        // arrange
        const { input, prompt, log, screen } = terminal();
        jest
          .spyOn(process.stdout, 'write')
          .mockImplementation((chunk: string | Uint8Array) => {
            screen.push(chunk.toString());

            return true;
          });

        // act
        const result = prompt.ask('PIN: ');
        log.debug('Rotation is not needed');
        input.write(keys);
        await result.catch((): undefined => undefined);

        // assert
        expect(screen).toEqual([
          'PIN: ',
          EOL,
          expect.stringMatching(/\[VERBOSE\] Rotation is not needed\n$/)
        ]);
      }
    );

    it.each([
      { key: 'Ctrl+C', input: '12\u0003' },
      { key: 'Ctrl+D', input: '\u0004' }
    ])('should be cancelled with $key', async ({ input: keys }) => {
      // arrange
      const { input, prompt } = terminal();

      // act
      const result = prompt.ask('PIN: ');
      input.write(keys);

      // assert
      await expect(result).rejects.toBeInstanceOf(
        Pkcs11PinPromptCancelledError
      );
      expect(input.setRawMode).toHaveBeenLastCalledWith(false);
    });
  });
});
