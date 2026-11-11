/**
 * A client certificate whose private key lives on a PKCS#11 token (smart card,
 * USB token, HSM). Applies to HTTPS targets only; WebSocket targets are not covered.
 */
export interface Pkcs11Cert {
  hostname: string;
  port?: string;
  pinFile?: string;
  /** Name of the environment variable holding the PIN, never the PIN itself. */
  pinEnv?: string;
  /** Token label; when absent the only token present is used. */
  token?: string;
  /**
   * CKA_LABEL of the certificate on the token. With `certFile`, the private
   * key's label instead, needed only when the token does not expose the
   * key's public half.
   */
  label?: string;
  /** Hex-encoded CKA_ID, with the same scope as `label`. */
  id?: string;
  /** Absolute path of a PEM file with the certificate; when absent it is read from the token. */
  certFile?: string;
  /** Concurrent connections allowed to sign with this key. */
  maxConcurrency: number;
}

export interface Pkcs11Options {
  /**
   * Vendor PKCS#11 library (.dll / .so / .dylib) shared by all certificates:
   * the OpenSSL providers drive a single module per process.
   */
  module: string;
  certs: Pkcs11Cert[];
  /** Override for the OpenSSL PKCS#11 provider plugin location. */
  provider?: string;
}
