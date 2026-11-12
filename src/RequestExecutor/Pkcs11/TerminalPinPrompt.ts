import {
  Pkcs11PinPrompt,
  Pkcs11PinPromptCancelledError
} from './Pkcs11PinPrompt';
import { EventEmitter } from 'node:events';
import { EOL } from 'node:os';

export interface TerminalInput extends EventEmitter {
  isTTY?: boolean;
  setRawMode?(mode: boolean): unknown;
  resume(): unknown;
  pause(): unknown;
}

export interface TerminalOutput {
  write(chunk: string): unknown;
}

/** Reads a PIN from the terminal without echoing it. */
export class TerminalPinPrompt implements Pkcs11PinPrompt {
  private static readonly ENTER = new Set(['\r', '\n']);
  // Ctrl+C and Ctrl+D: raw mode turns them into input instead of SIGINT / EOF.
  private static readonly CANCEL = new Set(['\u0003', '\u0004']);
  private static readonly BACKSPACE = new Set(['\u007f', '\b']);
  private static readonly ESCAPE = '\u001b';

  constructor(
    private readonly input: TerminalInput = process.stdin,
    // stderr keeps the question out of redirected stdout logs.
    private readonly output: TerminalOutput = process.stderr
  ) {}

  get interactive(): boolean {
    return !!this.input.isTTY && typeof this.input.setRawMode === 'function';
  }

  public ask(question: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const pin: string[] = [];

      const finish = (error?: Error) => {
        this.input.off('data', onData);
        this.input.setRawMode(false);
        this.input.pause();
        this.output.write(EOL);

        if (error) {
          reject(error);
        } else {
          resolve(pin.join(''));
        }
      };

      const onData = (chunk: Buffer | string) => {
        const text = chunk.toString();

        // Arrow and function keys arrive as one escape sequence per chunk.
        if (text.startsWith(TerminalPinPrompt.ESCAPE)) {
          return;
        }

        for (const char of text) {
          if (TerminalPinPrompt.ENTER.has(char)) {
            return finish();
          }

          if (TerminalPinPrompt.CANCEL.has(char)) {
            return finish(new Pkcs11PinPromptCancelledError());
          }

          if (TerminalPinPrompt.BACKSPACE.has(char)) {
            pin.pop();
          } else if (char >= ' ') {
            pin.push(char);
          }
        }
      };

      this.output.write(question);
      this.input.setRawMode(true);
      this.input.on('data', onData);
      this.input.resume();
    });
  }
}
