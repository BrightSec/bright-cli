import { Pkcs11PublicKeyAttributes } from './Pkcs11Module';
import { createPublicKey, KeyObject, X509Certificate } from 'node:crypto';

/**
 * Normalizes public keys to SubjectPublicKeyInfo DER, so that a key on the
 * token and a certificate can be compared byte for byte.
 */
export class Pkcs11PublicKey {
  // id-ecPublicKey (1.2.840.10045.2.1)
  private static readonly EC_PUBLIC_KEY_OID = Buffer.from(
    '06072a8648ce3d0201',
    'hex'
  );
  private static readonly OCTET_STRING = 0x04;

  /** @returns undefined for key types other than RSA and named-curve EC, or unreadable attributes. */
  public static fromAttributes({
    modulus,
    publicExponent,
    ecParams,
    ecPoint
  }: Pkcs11PublicKeyAttributes): Buffer | undefined {
    if (modulus?.length && publicExponent?.length) {
      return Pkcs11PublicKey.tryExport(() =>
        createPublicKey({
          key: {
            kty: 'RSA',
            n: Pkcs11PublicKey.unsigned(modulus).toString('base64url'),
            e: Pkcs11PublicKey.unsigned(publicExponent).toString('base64url')
          },
          format: 'jwk'
        })
      );
    }

    if (ecParams?.length && ecPoint?.length) {
      // PKCS#11 wraps CKA_EC_POINT in a DER OCTET STRING, but some modules
      // return the bare point, whose first byte is the same 0x04 tag.
      return [Pkcs11PublicKey.unwrapOctetString(ecPoint), ecPoint]
        .filter(Boolean)
        .map((point: Buffer) =>
          Pkcs11PublicKey.tryExport(() =>
            createPublicKey({
              key: Pkcs11PublicKey.ecSpki(ecParams, point),
              format: 'der',
              type: 'spki'
            })
          )
        )
        .find(Boolean);
    }

    return undefined;
  }

  /** @param value DER or PEM; a PEM bundle yields its first certificate. */
  public static fromCertificate(value: Buffer | string): Buffer | undefined {
    return Pkcs11PublicKey.tryExport(
      () => new X509Certificate(value).publicKey
    );
  }

  private static tryExport(key: () => KeyObject): Buffer | undefined {
    try {
      return key().export({ type: 'spki', format: 'der' });
    } catch {
      return undefined;
    }
  }

  private static unsigned(value: Buffer): Buffer {
    const start = value.findIndex((byte: number) => byte !== 0);

    return start <= 0 ? value : value.subarray(start);
  }

  private static unwrapOctetString(value: Buffer): Buffer | undefined {
    if (value[0] !== Pkcs11PublicKey.OCTET_STRING || value.length < 2) {
      return undefined;
    }

    const first = value[1];
    const lengthBytes = first < 0x80 ? 0 : first - 0x80;

    if (lengthBytes > 2 || value.length < 2 + lengthBytes) {
      return undefined;
    }

    const length = lengthBytes ? value.readUIntBE(2, lengthBytes) : first;
    const start = 2 + lengthBytes;

    return start + length === value.length ? value.subarray(start) : undefined;
  }

  private static ecSpki(curve: Buffer, point: Buffer): Buffer {
    return Pkcs11PublicKey.tlv(
      0x30,
      Buffer.concat([
        Pkcs11PublicKey.tlv(
          0x30,
          Buffer.concat([Pkcs11PublicKey.EC_PUBLIC_KEY_OID, curve])
        ),
        // BIT STRING with no unused bits
        Pkcs11PublicKey.tlv(0x03, Buffer.concat([Buffer.from([0]), point]))
      ])
    );
  }

  private static tlv(tag: number, content: Buffer): Buffer {
    const { length } = content;
    const header =
      length < 0x80
        ? [tag, length]
        : length < 0x100
        ? [tag, 0x81, length]
        : [tag, 0x82, Math.floor(length / 0x100), length % 0x100];

    return Buffer.concat([Buffer.from(header), content]);
  }
}
