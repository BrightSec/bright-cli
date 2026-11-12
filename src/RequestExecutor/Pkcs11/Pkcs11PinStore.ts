import { Pkcs11Cert } from '../Pkcs11Cert';

/**
 * PINs typed in the terminal at startup, one per `--pkcs11-cert` entry. They
 * live in process memory only and are never written anywhere.
 */
export class Pkcs11PinStore {
  private readonly pins = new Map<Pkcs11Cert, string>();

  public get(cert: Pkcs11Cert): string | undefined {
    return this.pins.get(cert);
  }

  public set(cert: Pkcs11Cert, pin: string): void {
    this.pins.set(cert, pin);
  }
}
