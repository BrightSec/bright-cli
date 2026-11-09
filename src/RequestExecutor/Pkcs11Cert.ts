/**
 * A client certificate whose private key lives on a PKCS#11 token (smart card,
 * USB token, HSM). Applies to HTTP targets only.
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
  /** Key/cert label; when absent with `id`, the key is selected at startup. */
  object?: string;
  /** Hex-encoded CKA_ID. */
  id?: string;
  /** `token` reads the certificate from the token; otherwise a PEM file path. */
  cert: 'token' | string;
  /** Concurrent connections allowed to sign with this key. */
  maxConcurrency: number;
}

export interface Pkcs11Options {
  certs: Pkcs11Cert[];
  /** Override for the OpenSSL PKCS#11 provider plugin location. */
  provider?: string;
}
