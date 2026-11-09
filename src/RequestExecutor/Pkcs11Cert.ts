/**
 * A client certificate whose private key lives on a PKCS#11 token (smart card,
 * USB token, HSM). Applies to HTTPS targets only; WebSocket targets are not covered.
 */
export interface Pkcs11Cert {
  hostname: string;
  port?: string;
  /** Vendor PKCS#11 library (.dll / .so / .dylib). */
  module: string;
  pinFile?: string;
  /** Name of the environment variable holding the PIN, never the PIN itself. */
  pinEnv?: string;
  /** Token label; when absent the only token present is used. */
  token?: string;
  /** Key/cert label. When neither `object` nor `id` is set, the key is selected at startup. */
  object?: string;
  /** Hex-encoded CKA_ID. */
  id?: string;
  /** `"token"` reads the certificate from the token; any other value is a PEM file path. */
  cert: string;
  /** Concurrent connections allowed to sign with this key. */
  maxConcurrency: number;
}

export interface Pkcs11Options {
  certs: Pkcs11Cert[];
  /** Override for the OpenSSL PKCS#11 provider plugin location. */
  provider?: string;
}
