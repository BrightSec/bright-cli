export interface Pkcs11PinPrompt {
  /** False when there is no terminal to ask in, e.g. under a service manager. */
  readonly interactive: boolean;
  /** @throws Pkcs11PinPromptCancelledError when the user cancels the input. */
  ask(question: string): Promise<string>;
}

export class Pkcs11PinPromptCancelledError extends Error {
  constructor() {
    super('PIN entry was cancelled.');
    this.name = 'Pkcs11PinPromptCancelledError';
  }
}
