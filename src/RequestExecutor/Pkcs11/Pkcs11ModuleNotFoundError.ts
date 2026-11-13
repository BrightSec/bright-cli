/** No usable PKCS#11 library was found; the message tells the user what to do. */
export class Pkcs11ModuleNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Pkcs11ModuleNotFoundError';
  }
}
