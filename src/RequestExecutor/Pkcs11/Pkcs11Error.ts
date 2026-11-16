export enum Pkcs11ErrorCode {
  MODULE_LOAD_FAILED = 'PKCS11_MODULE_LOAD_FAILED',
  TOKEN_NOT_FOUND = 'PKCS11_TOKEN_NOT_FOUND',
  PIN_INCORRECT = 'PKCS11_PIN_INCORRECT',
  PIN_LOCKED = 'PKCS11_PIN_LOCKED',
  KEY_NOT_FOUND = 'PKCS11_KEY_NOT_FOUND',
  PIN_UNAVAILABLE = 'PKCS11_PIN_UNAVAILABLE',
  HANDSHAKE_FAILED = 'PKCS11_HANDSHAKE_FAILED'
}

/**
 * A smart-card / PKCS#11 failure. `code` travels to the cloud in the existing
 * `errorCode` response field; the message must never contain the PIN.
 */
export class Pkcs11Error extends Error {
  constructor(
    public readonly code: Pkcs11ErrorCode,
    message: string,
    // Failures that a retry cannot fix, or that would cost a PIN attempt, are
    // never retried until the Repeater restarts.
    public readonly retryable = false
  ) {
    super(message);
    this.name = 'Pkcs11Error';
  }
}
