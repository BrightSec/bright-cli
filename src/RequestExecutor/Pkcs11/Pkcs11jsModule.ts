import {
  Pkcs11CertificateInfo,
  Pkcs11Module,
  Pkcs11ModuleError,
  Pkcs11ObjectFilter,
  Pkcs11PrivateKeyInfo,
  Pkcs11PublicKeyAttributes,
  Pkcs11Token
} from './Pkcs11Module';
import type { AttributeResult, PKCS11, Template } from 'pkcs11js';

export type Pkcs11jsBinding = typeof import('pkcs11js');

const MAX_OBJECTS = 64;

export const toModuleError = (e: unknown): Pkcs11ModuleError => {
  const message = String((e as Error)?.message ?? e);

  return new Pkcs11ModuleError(
    /^(CKR_[A-Z_]+)/.exec(message)?.[1] ?? 'CKR_GENERAL_ERROR',
    message
  );
};

export class Pkcs11jsModule implements Pkcs11Module {
  constructor(
    private readonly binding: Pkcs11jsBinding,
    private readonly lib: PKCS11
  ) {}

  // CK_ULONG is 8 bytes on 64-bit Unix and 4 on Windows, in host byte order
  // (little-endian on every platform bright-cli ships for).
  private static readUlong(value?: Buffer): number | undefined {
    switch (value?.length) {
      case 8:
        return Number(value.readBigUInt64LE());
      case 4:
        return value.readUInt32LE();
      default:
        return undefined;
    }
  }

  public tokens(): Pkcs11Token[] {
    return this.call(() =>
      this.lib.C_GetSlotList(true).map((slot: Buffer) => {
        const info = this.lib.C_GetTokenInfo(slot);

        return {
          slot,
          label: info.label.trim(),
          serial: info.serialNumber.trim(),
          flags: info.flags
        };
      })
    );
  }

  public mechanisms(slot: Buffer): number[] {
    return this.call(() => this.lib.C_GetMechanismList(slot));
  }

  public openSession(slot: Buffer): Buffer {
    return this.call(() =>
      this.lib.C_OpenSession(slot, this.binding.CKF_SERIAL_SESSION)
    );
  }

  public closeSession(session: Buffer): void {
    this.call(() => this.lib.C_CloseSession(session));
  }

  public login(session: Buffer, pin: string): void {
    this.call(() => this.lib.C_Login(session, this.binding.CKU_USER, pin));
  }

  public findPrivateKeys(
    session: Buffer,
    filter: Pkcs11ObjectFilter
  ): Pkcs11PrivateKeyInfo[] {
    return this.find(session, this.binding.CKO_PRIVATE_KEY, filter).map(
      (handle: Buffer) => {
        const [label, id, keyType]: (Buffer | undefined)[] = this.attributes(
          session,
          handle,
          [
            this.binding.CKA_LABEL,
            this.binding.CKA_ID,
            this.binding.CKA_KEY_TYPE
          ]
        );

        return {
          handle,
          label: label?.toString(),
          id,
          keyType: Pkcs11jsModule.readUlong(keyType)
        };
      }
    );
  }

  public findCertificates(
    session: Buffer,
    filter: Pkcs11ObjectFilter
  ): Pkcs11CertificateInfo[] {
    return this.find(session, this.binding.CKO_CERTIFICATE, filter).map(
      (handle: Buffer) => {
        const [label, id, value]: (Buffer | undefined)[] = this.attributes(
          session,
          handle,
          [this.binding.CKA_LABEL, this.binding.CKA_ID, this.binding.CKA_VALUE]
        );

        return { handle, label: label?.toString(), id, value };
      }
    );
  }

  public publicKeyAttributes(
    session: Buffer,
    key: Pkcs11PrivateKeyInfo
  ): Pkcs11PublicKeyAttributes {
    const [modulus, publicExponent, ecParams]: (Buffer | undefined)[] =
      this.attributes(session, key.handle, [
        this.binding.CKA_MODULUS,
        this.binding.CKA_PUBLIC_EXPONENT,
        this.binding.CKA_EC_PARAMS
      ]);

    if (modulus?.length && publicExponent?.length) {
      return { modulus, publicExponent };
    }

    // CKA_EC_POINT is defined only on public key objects.
    const handles = key.id?.length
      ? this.find(session, this.binding.CKO_PUBLIC_KEY, { id: key.id })
      : [];

    if (handles.length !== 1) {
      return { ecParams };
    }

    const [publicModulus, publicKeyExponent, publicEcParams, ecPoint]: (
      | Buffer
      | undefined
    )[] = this.attributes(session, handles[0], [
      this.binding.CKA_MODULUS,
      this.binding.CKA_PUBLIC_EXPONENT,
      this.binding.CKA_EC_PARAMS,
      this.binding.CKA_EC_POINT
    ]);

    return {
      modulus: publicModulus,
      publicExponent: publicKeyExponent,
      ecParams: ecParams ?? publicEcParams,
      ecPoint
    };
  }

  private find(
    session: Buffer,
    objectClass: number,
    { label, id }: Pkcs11ObjectFilter
  ): Buffer[] {
    const template: Template = [
      { type: this.binding.CKA_CLASS, value: objectClass }
    ];

    if (label !== undefined) {
      template.push({ type: this.binding.CKA_LABEL, value: label });
    }

    if (id !== undefined) {
      template.push({ type: this.binding.CKA_ID, value: id });
    }

    return this.call(() => {
      this.lib.C_FindObjectsInit(session, template);
      try {
        return this.lib.C_FindObjects(session, MAX_OBJECTS);
      } finally {
        this.lib.C_FindObjectsFinal(session);
      }
    });
  }

  private attributes(
    session: Buffer,
    handle: Buffer,
    types: number[]
  ): (Buffer | undefined)[] {
    // Attributes are read one by one: a single missing attribute makes a
    // combined C_GetAttributeValue fail for all of them.
    return types.map((type: number) => {
      try {
        const [{ value }]: AttributeResult[] = this.lib.C_GetAttributeValue(
          session,
          handle,
          [{ type }]
        );

        return Buffer.isBuffer(value) ? value : undefined;
      } catch {
        return undefined;
      }
    });
  }

  private call<T>(fn: () => T): T {
    try {
      return fn();
    } catch (e) {
      throw toModuleError(e);
    }
  }
}
