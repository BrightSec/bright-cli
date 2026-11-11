export interface Pkcs11UriParts {
  token: string;
  serial?: string;
  type: 'private' | 'cert';
  id?: Buffer;
  object?: string;
  pin?: string;
}

/**
 * Builds an RFC 7512 PKCS#11 URI. A URI with a PIN is a secret and must not be
 * logged.
 */
export class Pkcs11Uri {
  public static build({
    token,
    serial,
    type,
    id,
    object,
    pin
  }: Pkcs11UriParts): string {
    const path = [`token=${Pkcs11Uri.encode(token)}`];

    // Cards of the same model often share a label; the serial tells them apart.
    if (serial) {
      path.push(`serial=${Pkcs11Uri.encode(serial)}`);
    }

    // Both, when known: the provider resolves the URI on its own, and either
    // attribute alone may match more objects than the one the caller selected.
    if (id?.length) {
      path.push(`id=${Pkcs11Uri.encodeBytes(id)}`);
    }

    if (object) {
      path.push(`object=${Pkcs11Uri.encode(object)}`);
    }

    path.push(`type=${type}`);

    const query =
      pin === undefined ? '' : `?pin-value=${Pkcs11Uri.encode(pin)}`;

    return `pkcs11:${path.join(';')}${query}`;
  }

  // RFC 7512 allows unreserved characters as-is; everything else is %-encoded,
  // which also covers ";", "?" and "=" that would split the URI.
  private static encode(value: string): string {
    return Pkcs11Uri.encodeBytes(Buffer.from(value, 'utf8'), true);
  }

  private static encodeBytes(bytes: Buffer, keepUnreserved = false): string {
    return [...bytes]
      .map((byte: number) => {
        const char = String.fromCharCode(byte);

        return keepUnreserved && /[A-Za-z0-9\-._~]/.test(char)
          ? char
          : `%${byte.toString(16).padStart(2, '0')}`;
      })
      .join('');
  }
}
