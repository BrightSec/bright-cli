export interface Pkcs11Token {
  slot: Buffer;
  label: string;
  flags: number;
}

export interface Pkcs11ObjectInfo {
  handle: Buffer;
  label?: string;
  id?: Buffer;
}

export interface Pkcs11PrivateKeyInfo extends Pkcs11ObjectInfo {
  keyType?: number;
}

export interface Pkcs11CertificateInfo extends Pkcs11ObjectInfo {
  value: Buffer;
}

export interface Pkcs11ObjectFilter {
  label?: string;
  id?: Buffer;
}

/**
 * The subset of a PKCS#11 module the pre-flight needs. Keeps the native
 * binding behind an interface so the selection logic is testable.
 */
export interface Pkcs11Module {
  tokens(): Pkcs11Token[];
  mechanisms(slot: Buffer): number[];
  openSession(slot: Buffer): Buffer;
  closeSession(session: Buffer): void;
  /** @throws Pkcs11ModuleError */
  login(session: Buffer, pin: string): void;
  findPrivateKeys(
    session: Buffer,
    filter: Pkcs11ObjectFilter
  ): Pkcs11PrivateKeyInfo[];
  findCertificates(
    session: Buffer,
    filter: Pkcs11ObjectFilter
  ): Pkcs11CertificateInfo[];
}

export interface Pkcs11ModuleLoader {
  /**
   * Loads and initializes a module once per process. The module is never
   * finalized: the OpenSSL provider shares its process-wide state.
   */
  load(path: string): Pkcs11Module;
}

export const Pkcs11ModuleLoader: unique symbol = Symbol('Pkcs11ModuleLoader');

/** A failed PKCS#11 call, with the symbolic CKR_* name. */
export class Pkcs11ModuleError extends Error {
  constructor(public readonly ckr: string, message?: string) {
    super(message ?? ckr);
    this.name = 'Pkcs11ModuleError';
  }
}
