import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import {
  Pkcs11CertificateInfo,
  Pkcs11Module,
  Pkcs11ModuleError,
  Pkcs11ModuleLoader,
  Pkcs11ObjectFilter,
  Pkcs11ObjectInfo,
  Pkcs11PrivateKeyInfo,
  Pkcs11Token
} from './Pkcs11Module';
import { Pkcs11PublicKey } from './Pkcs11PublicKey';
import { Pkcs11Uri } from './Pkcs11Uri';
import { Pkcs11Cert } from '../Pkcs11Cert';
import { logger } from '../../Utils';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

export interface Pkcs11Identity {
  /** OpenSSL provider name for CURLOPT_SSLENGINE. */
  provider: string;
  /** Includes the PIN: never log it. */
  keyUri: string;
  /**
   * DER certificate the pre-flight read from the token. curl gets these bytes
   * instead of a URI, because an RFC 7512 URI cannot single out a certificate.
   */
  certificate?: Buffer;
  certFile?: string;
  /** The token cannot sign RSA-PSS, which TLS 1.3 requires for RSA keys. */
  tls12Only: boolean;
}

export interface Pkcs11PreflightTarget {
  /** Path of the vendor PKCS#11 library. */
  module: string;
  /** OpenSSL provider name for CURLOPT_SSLENGINE. */
  provider: string;
}

export interface Pkcs11PreflightOptions {
  retryAfterMs?: number;
  now?: () => number;
  env?: NodeJS.ProcessEnv;
  readFile?: (path: string) => string;
  /** Decides how the example --pkcs11-cert in error messages is quoted. */
  platform?: NodeJS.Platform;
}

interface StoredFailure {
  error: Pkcs11Error;
  at: number;
}

interface Login {
  module: Pkcs11Module;
  token: Pkcs11Token;
  session: Buffer;
  /** Undefined when the token needs no login. */
  pin?: string;
}

interface KeyEntry {
  key: Pkcs11PrivateKeyInfo;
  /** SubjectPublicKeyInfo DER; undefined when the token hides the public half. */
  publicKey?: Buffer;
}

interface Pairing {
  certificate: Pkcs11CertificateInfo;
  key: Pkcs11PrivateKeyInfo;
}

/**
 * Checks each PKCS#11 certificate once before it is used: token present, PIN
 * usable, exactly one login, key and certificate found. Results are shared by
 * all concurrent callers and failures are remembered, so a wrong PIN costs the
 * card a single retry, not one per request.
 */
export class Pkcs11Preflight {
  public static readonly PIV_KEY_LABEL = 'Private key for PIV Authentication';
  private static readonly PIV_KEY_LABEL_PATTERN = /^Private key for (.+)$/;
  // YKCS11 prefixes it with "X.509 ", OpenSC does not.
  private static readonly PIV_AUTH_CERT_LABEL =
    /(?:^|\s)Certificate for PIV Authentication$/;

  // PKCS#11 v2.40 constants, kept here so this class does not need the native binding.
  private static readonly CKF_LOGIN_REQUIRED = 0x00000004;
  private static readonly CKF_USER_PIN_FINAL_TRY = 0x00020000;
  private static readonly CKF_USER_PIN_LOCKED = 0x00040000;
  private static readonly CKK_RSA = 0x00000000;
  private static readonly CKM_RSA_PKCS_PSS = 0x0000000d;
  private static readonly PERMANENT_PIN_ERRORS: ReadonlySet<string> = new Set([
    'CKR_PIN_INCORRECT',
    'CKR_PIN_INVALID',
    'CKR_PIN_LEN_RANGE',
    'CKR_PIN_EXPIRED'
  ]);

  private readonly retryAfterMs: number;
  private readonly now: () => number;
  private readonly env: NodeJS.ProcessEnv;
  private readonly readFile: (path: string) => string;
  private readonly platform: NodeJS.Platform;
  private readonly inflight = new Map<Pkcs11Cert, Promise<Pkcs11Identity>>();
  private readonly identities = new Map<Pkcs11Cert, Pkcs11Identity>();
  private readonly failures = new Map<Pkcs11Cert, StoredFailure>();
  // Keyed by token: certificates on the same card share one login,
  // so a rejected PIN is never tried again through another entry.
  private readonly logins = new Map<string, Login | Pkcs11Error>();

  constructor(
    private readonly loader: Pkcs11ModuleLoader,
    private readonly target: Pkcs11PreflightTarget,
    {
      retryAfterMs = 30_000,
      now = Date.now,
      env = process.env,
      readFile = (path: string) => readFileSync(path, 'utf8'),
      platform = process.platform
    }: Pkcs11PreflightOptions = {}
  ) {
    this.retryAfterMs = retryAfterMs;
    this.now = now;
    this.env = env;
    this.readFile = readFile;
    this.platform = platform;
  }

  // The flags are single bits; this avoids bitwise operators, which the lint rules ban.
  private static hasFlag(flags: number, flag: number): boolean {
    return Math.floor(flags / flag) % 2 === 1;
  }

  /** @throws Pkcs11Error */
  public identity(cert: Pkcs11Cert): Promise<Pkcs11Identity> {
    const identity = this.identities.get(cert);
    if (identity) {
      return Promise.resolve(identity);
    }

    const failure = this.failures.get(cert);
    if (
      failure &&
      (!failure.error.retryable || this.now() - failure.at < this.retryAfterMs)
    ) {
      return Promise.reject(failure.error);
    }

    let pending = this.inflight.get(cert);
    if (!pending) {
      pending = this.verify(cert).finally(() => this.inflight.delete(cert));
      this.inflight.set(cert, pending);
    }

    return pending;
  }

  private async verify(cert: Pkcs11Cert): Promise<Pkcs11Identity> {
    // Yield first so concurrent callers in the same tick share this run.
    await Promise.resolve();

    try {
      const identity = this.resolveIdentity(cert);
      this.identities.set(cert, identity);
      this.failures.delete(cert);

      return identity;
    } catch (e) {
      const error =
        e instanceof Pkcs11Error
          ? e
          : new Pkcs11Error(
              Pkcs11ErrorCode.MODULE_LOAD_FAILED,
              `PKCS#11 check for ${cert.hostname} failed: ${e?.message}`,
              true
            );
      this.failures.set(cert, { error, at: this.now() });
      logger.error('PKCS#11: %s', error.message);
      throw error;
    }
  }

  private resolveIdentity(cert: Pkcs11Cert): Pkcs11Identity {
    const { module, token, session, pin } = this.login(cert);
    const certFile = cert.certFile ? this.readCertFile(cert) : undefined;
    const { key, certificate } =
      cert.certFile === undefined
        ? this.selectFromToken(module, session, token, cert)
        : {
            key: this.selectKeyForFile(module, session, token, cert, certFile),
            certificate: undefined
          };

    this.assertKeyUriIsUnique(module, session, key);

    if (certificate) {
      logger.debug(
        'PKCS#11: using certificate %s from token "%s" for %s.',
        this.describeCertificate(certificate),
        token.label,
        cert.hostname
      );
    }

    this.warnIfExpired(cert, certificate?.value ?? certFile);

    const tls12Only =
      key.keyType === Pkcs11Preflight.CKK_RSA &&
      !module.mechanisms(token.slot).includes(Pkcs11Preflight.CKM_RSA_PKCS_PSS);
    if (tls12Only) {
      logger.warn(
        'PKCS#11: token "%s" cannot sign RSA-PSS; TLS to %s is limited to TLS 1.2.',
        token.label,
        cert.hostname
      );
    }

    return {
      provider: this.target.provider,
      keyUri: Pkcs11Uri.build({
        token: token.label,
        serial: token.serial,
        type: 'private',
        id: key.id,
        object: key.label,
        pin
      }),
      certificate: certificate?.value,
      certFile: cert.certFile,
      tls12Only
    };
  }

  private login(cert: Pkcs11Cert): Login {
    const module = this.loadModule();
    const token = this.selectToken(module, cert);
    const key = `${token.serial}\0${token.label}`;
    const previous = this.logins.get(key);

    if (previous instanceof Pkcs11Error) {
      throw previous;
    }

    const pin = Pkcs11Preflight.hasFlag(
      token.flags,
      Pkcs11Preflight.CKF_LOGIN_REQUIRED
    )
      ? this.pin(cert)
      : undefined;

    if (previous) {
      // The provider logs in with the PIN in each key URI, so a different PIN
      // for the same token would be tried on the card behind the pre-flight's back.
      if (previous.pin !== pin) {
        throw new Pkcs11Error(
          Pkcs11ErrorCode.PIN_INCORRECT,
          `Another --pkcs11-cert entry already logged in to token "${token.label}" with a different PIN; use the same PIN for all entries of a token.`
        );
      }

      return previous;
    }

    this.assertPinUsable(token);

    return this.openAndLogin(module, token, key, pin);
  }

  private openAndLogin(
    module: Pkcs11Module,
    token: Pkcs11Token,
    key: string,
    pin: string | undefined
  ): Login {
    let session: Buffer | undefined;
    let attempted = false;

    try {
      // The session stays open for the life of the process: closing the last
      // session of a token logs the application out of it.
      session = module.openSession(token.slot);

      if (pin !== undefined) {
        attempted = true;
        this.loginOnce(module, session, pin);
      }

      const login = { module, token, session, pin };
      this.logins.set(key, login);

      return login;
    } catch (e) {
      this.closeQuietly(module, session);
      const error = this.toLoginError(e, token, attempted);
      if (!error.retryable) {
        this.logins.set(key, error);
      }
      throw error;
    }
  }

  private closeQuietly(module: Pkcs11Module, session?: Buffer): void {
    try {
      if (session) {
        module.closeSession(session);
      }
    } catch {
      // The failure being reported matters more than a session that leaks.
    }
  }

  private loginOnce(module: Pkcs11Module, session: Buffer, pin: string): void {
    try {
      module.login(session, pin);
    } catch (e) {
      if (
        !(e instanceof Pkcs11ModuleError) ||
        e.ckr !== 'CKR_USER_ALREADY_LOGGED_IN'
      ) {
        throw e;
      }
    }
  }

  private toLoginError(
    e: unknown,
    token: Pkcs11Token,
    attempted: boolean
  ): Pkcs11Error {
    if (e instanceof Pkcs11Error) {
      return e;
    }

    const ckr = e instanceof Pkcs11ModuleError ? e.ckr : 'CKR_GENERAL_ERROR';

    if (Pkcs11Preflight.PERMANENT_PIN_ERRORS.has(ckr)) {
      return new Pkcs11Error(
        Pkcs11ErrorCode.PIN_INCORRECT,
        `The PIN for token "${token.label}" was rejected (${ckr}). The Repeater will not try it again; fix the PIN and restart it.`
      );
    }

    if (ckr === 'CKR_PIN_LOCKED') {
      return new Pkcs11Error(
        Pkcs11ErrorCode.PIN_LOCKED,
        `The PIN of token "${token.label}" is locked.`
      );
    }

    // Some vendors report a wrong PIN as a generic failure; once C_Login has
    // been called, another attempt may cost the card a PIN retry.
    return new Pkcs11Error(
      Pkcs11ErrorCode.TOKEN_NOT_FOUND,
      attempted
        ? `Logging in to token "${token.label}" failed (${ckr}). The Repeater will not try again, to protect the PIN retry counter; restart it once the card works.`
        : `Token "${token.label}" is not usable (${ckr}).`,
      !attempted
    );
  }

  private loadModule(): Pkcs11Module {
    try {
      return this.loader.load(this.target.module);
    } catch (e) {
      if (e instanceof Pkcs11Error) {
        throw e;
      }

      throw new Pkcs11Error(
        Pkcs11ErrorCode.MODULE_LOAD_FAILED,
        `Cannot load the PKCS#11 module ${this.target.module}: ${e?.message}`,
        true
      );
    }
  }

  private selectToken(module: Pkcs11Module, cert: Pkcs11Cert): Pkcs11Token {
    const tokens = module.tokens();
    const candidates = cert.token
      ? tokens.filter(({ label }: Pkcs11Token) => label === cert.token)
      : tokens;

    if (candidates.length > 1 && cert.token) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.TOKEN_NOT_FOUND,
        `Several tokens are labelled "${cert.token}" (serials ${candidates
          .map(({ serial }: Pkcs11Token) => serial)
          .join(', ')}); leave only one of them connected.`,
        true
      );
    }

    if (candidates.length !== 1) {
      const found = tokens.length
        ? `found: ${tokens.map(({ label }) => `"${label}"`).join(', ')}`
        : 'no token is present (is the card inserted?)';
      throw new Pkcs11Error(
        Pkcs11ErrorCode.TOKEN_NOT_FOUND,
        cert.token
          ? `Token "${cert.token}" not found; ${found}.`
          : `Set "token" to choose a token; ${found}.`,
        true
      );
    }

    return candidates[0];
  }

  private assertPinUsable(token: Pkcs11Token): void {
    if (
      Pkcs11Preflight.hasFlag(token.flags, Pkcs11Preflight.CKF_USER_PIN_LOCKED)
    ) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.PIN_LOCKED,
        `The PIN of token "${token.label}" is locked.`
      );
    }

    if (
      Pkcs11Preflight.hasFlag(
        token.flags,
        Pkcs11Preflight.CKF_USER_PIN_FINAL_TRY
      )
    ) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.PIN_LOCKED,
        `Token "${token.label}" has one PIN attempt left; the Repeater will not use it. Verify the PIN with the card vendor's tool first.`
      );
    }
  }

  private selectFromToken(
    module: Pkcs11Module,
    session: Buffer,
    token: Pkcs11Token,
    cert: Pkcs11Cert
  ): Pairing {
    const certificates = module.findCertificates(session, this.selector(cert));

    if (!certificates.length) {
      throw this.noCertificate(module, session, token, cert);
    }

    const keys = this.keyEntries(module, session, {});
    const pairings = this.pair(certificates, keys);

    if (!pairings.length) {
      throw this.noKeyForCertificates(token, certificates);
    }

    const chosen = this.choose(pairings);

    if (!chosen) {
      throw this.ambiguousCertificates(
        token,
        cert,
        pairings.map(({ certificate }: Pairing) => certificate)
      );
    }

    return chosen;
  }

  /** @returns the certificates that have a private key on the token, with that key. */
  private pair(
    certificates: Pkcs11CertificateInfo[],
    keys: KeyEntry[]
  ): Pairing[] {
    return certificates
      .map((certificate: Pkcs11CertificateInfo) => ({
        certificate,
        key: this.keyOf(certificate, keys)
      }))
      .filter((pairing): pairing is Pairing => !!pairing.key);
  }

  // CKA_ID shared by a key and its certificate is a PKCS#11 convention only;
  // equal public keys prove the pair.
  private keyOf(
    certificate: Pkcs11CertificateInfo,
    keys: KeyEntry[]
  ): Pkcs11PrivateKeyInfo | undefined {
    const publicKey = Pkcs11PublicKey.fromCertificate(certificate.value);
    const sameId = keys.filter(
      ({ key }: KeyEntry) =>
        !!certificate.id?.length && !!key.id?.equals(certificate.id)
    );
    const proven = publicKey
      ? keys.filter((entry: KeyEntry) => entry.publicKey?.equals(publicKey))
      : [];

    if (proven.length) {
      const preferred = proven.filter((entry: KeyEntry) =>
        sameId.includes(entry)
      );

      return this.only(preferred.length ? preferred : proven)?.key;
    }

    // A key whose public half the token hides can only be matched by id.
    return this.only(
      sameId.filter((entry: KeyEntry) => !publicKey || !entry.publicKey)
    )?.key;
  }

  private choose(pairings: Pairing[]): Pairing | undefined {
    if (pairings.length === 1) {
      return pairings[0];
    }

    // YubiKeys expose a generated attestation certificate under each key's
    // id, holding that key's public key, next to the certificate in the slot.
    const paired = pairings.filter(
      ({ certificate, key }: Pairing) =>
        certificate.label !== undefined &&
        this.certificateLabelsFor(key).includes(certificate.label)
    );

    if (paired.length === 1) {
      return paired[0];
    }

    return this.only(
      (paired.length ? paired : pairings).filter(({ certificate }: Pairing) =>
        Pkcs11Preflight.PIV_AUTH_CERT_LABEL.test(certificate.label ?? '')
      )
    );
  }

  // YKCS11 labels the key in a PIV slot "Private key for <slot>" and its
  // certificate "X.509 Certificate for <slot>"; most other tokens reuse the label.
  private certificateLabelsFor({ label }: Pkcs11PrivateKeyInfo): string[] {
    if (!label) {
      return [];
    }

    const slot = Pkcs11Preflight.PIV_KEY_LABEL_PATTERN.exec(label)?.[1];

    return slot ? [`X.509 Certificate for ${slot}`, label] : [label];
  }

  private selectKeyForFile(
    module: Pkcs11Module,
    session: Buffer,
    token: Pkcs11Token,
    cert: Pkcs11Cert,
    certFile: Buffer | undefined
  ): Pkcs11PrivateKeyInfo {
    const keys = this.keyEntries(module, session, this.selector(cert));
    const publicKey = certFile
      ? Pkcs11PublicKey.fromCertificate(certFile)
      : undefined;
    const proven = publicKey
      ? keys.filter((entry: KeyEntry) => entry.publicKey?.equals(publicKey))
      : [];
    // "id" and "label" narrow these down when the public halves are hidden.
    const candidates = proven.length
      ? proven
      : keys.filter((entry: KeyEntry) => !publicKey || !entry.publicKey);
    const chosen =
      this.only(candidates) ??
      this.only(
        candidates.filter(
          ({ key }: KeyEntry) => key.label === Pkcs11Preflight.PIV_KEY_LABEL
        )
      );

    if (chosen) {
      return chosen.key;
    }

    throw candidates.length
      ? this.ambiguousKeys(
          token,
          cert,
          candidates.map(({ key }: KeyEntry) => key)
        )
      : new Pkcs11Error(
          Pkcs11ErrorCode.KEY_NOT_FOUND,
          keys.length
            ? `No private key on token "${
                token.label
              }" holds the public key of the certificate in ${
                cert.certFile
              }. Keys found:\n${this.list(
                keys.map(({ key }: KeyEntry) => this.describeObject(key))
              )}`
            : `No private key${this.describeSelector(cert)} on token "${
                token.label
              }".`,
          true
        );
  }

  // The key URI carries only the key's id and label, so the provider would
  // pick any other key that shares both.
  private assertKeyUriIsUnique(
    module: Pkcs11Module,
    session: Buffer,
    key: Pkcs11PrivateKeyInfo
  ): void {
    const twins = module.findPrivateKeys(session, {
      label: key.label,
      id: key.id?.length ? key.id : undefined
    });

    if (twins.length > 1) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.KEY_NOT_FOUND,
        `Several private keys on the token share the id and label of ${this.describeObject(
          key
        )}, so the OpenSSL provider cannot tell them apart.`,
        true
      );
    }
  }

  private keyEntries(
    module: Pkcs11Module,
    session: Buffer,
    filter: Pkcs11ObjectFilter
  ): KeyEntry[] {
    return module
      .findPrivateKeys(session, filter)
      .map((key: Pkcs11PrivateKeyInfo) => ({
        key,
        publicKey: Pkcs11PublicKey.fromAttributes(
          module.publicKeyAttributes(session, key)
        )
      }));
  }

  private selector(cert: Pkcs11Cert): Pkcs11ObjectFilter {
    return {
      label: cert.label,
      id: cert.id ? Buffer.from(cert.id, 'hex') : undefined
    };
  }

  private only<T>(items: T[]): T | undefined {
    return items.length === 1 ? items[0] : undefined;
  }

  private noCertificate(
    module: Pkcs11Module,
    session: Buffer,
    token: Pkcs11Token,
    cert: Pkcs11Cert
  ): Pkcs11Error {
    const all = module.findCertificates(session, {});
    const field = this.distinguishingField(all);
    const usable = this.pair(all, this.keyEntries(module, session, {}));
    const example =
      this.choose(usable)?.certificate ?? usable[0]?.certificate ?? all[0];
    const message =
      cert.label === undefined && cert.id === undefined
        ? `Token "${token.label}" holds no certificates. Set "certFile" to a PEM file with the certificate for ${cert.hostname}.`
        : [
            `No certificate${this.describeSelector(cert)} on token "${
              token.label
            }".`,
            ...(all.length
              ? [
                  'Certificates on the token:',
                  this.list(all.map((c) => this.describeCertificate(c))),
                  field
                    ? this.restartHint(
                        { ...cert, label: undefined, id: undefined },
                        field,
                        example
                      )
                    : ''
                ]
              : [])
          ]
            .filter(Boolean)
            .join('\n');

    return new Pkcs11Error(Pkcs11ErrorCode.KEY_NOT_FOUND, message, true);
  }

  private noKeyForCertificates(
    token: Pkcs11Token,
    certificates: Pkcs11CertificateInfo[]
  ): Pkcs11Error {
    return new Pkcs11Error(
      Pkcs11ErrorCode.KEY_NOT_FOUND,
      certificates.length === 1
        ? `No private key on token "${
            token.label
          }" holds the public key of certificate ${this.describeCertificate(
            certificates[0]
          )}.`
        : `No private key on token "${
            token.label
          }" holds the public key of any of these certificates:\n${this.list(
            certificates.map((c) => this.describeCertificate(c))
          )}`,
      true
    );
  }

  private ambiguousCertificates(
    token: Pkcs11Token,
    cert: Pkcs11Cert,
    certificates: Pkcs11CertificateInfo[]
  ): Pkcs11Error {
    const field = this.distinguishingField(certificates);

    return new Pkcs11Error(
      Pkcs11ErrorCode.KEY_NOT_FOUND,
      [
        `Several certificates on token "${token.label}" can be used for ${cert.hostname}:`,
        this.list(certificates.map((c) => this.describeCertificate(c))),
        field
          ? this.restartHint(cert, field, certificates[0])
          : `Their labels and ids are the same; set "certFile" to a PEM file with the one ${cert.hostname} accepts and restart the Repeater.`
      ].join('\n'),
      true
    );
  }

  private ambiguousKeys(
    token: Pkcs11Token,
    cert: Pkcs11Cert,
    keys: Pkcs11PrivateKeyInfo[]
  ): Pkcs11Error {
    const field = this.distinguishingField(keys);

    return new Pkcs11Error(
      Pkcs11ErrorCode.KEY_NOT_FOUND,
      [
        `Several private keys on token "${token.label}" may belong to the certificate in ${cert.certFile}, and the token does not expose their public keys to tell:`,
        this.list(keys.map(this.describeObject)),
        field
          ? this.restartHint(cert, field, keys[0])
          : 'Their labels and ids are the same; the Repeater cannot use this token.'
      ].join('\n'),
      true
    );
  }

  // "label" reads best; the id is the fallback for objects without unique labels.
  private distinguishingField(
    objects: Pkcs11ObjectInfo[]
  ): 'label' | 'id' | undefined {
    const unique = (values: (string | undefined)[]) =>
      values.every(Boolean) && new Set(values).size === values.length;

    if (unique(objects.map(({ label }: Pkcs11ObjectInfo) => label))) {
      return 'label';
    }

    if (
      unique(
        objects.map(({ id }: Pkcs11ObjectInfo) => id?.toString('hex') || '')
      )
    ) {
      return 'id';
    }

    return undefined;
  }

  private restartHint(
    cert: Pkcs11Cert,
    field: 'label' | 'id',
    example: Pkcs11ObjectInfo
  ): string {
    const entry = {
      hostname: cert.hostname,
      port: cert.port,
      pinFile: cert.pinFile,
      pinEnv: cert.pinEnv,
      token: cert.token,
      id: cert.id,
      label: cert.label,
      [field]: field === 'id' ? example.id?.toString('hex') : example.label,
      certFile: cert.certFile,
      maxConcurrency:
        cert.maxConcurrency === 1 ? undefined : cert.maxConcurrency
    };

    return `Choose one with "${field}" and restart the Repeater, for example:\n  --pkcs11-cert ${this.quoteArgument(
      JSON.stringify(entry)
    )}`;
  }

  // Windows: CommandLineToArgvW reads backslashes literally except before a quote.
  private quoteArgument(value: string): string {
    return this.platform === 'win32'
      ? `"${value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1')}"`
      : `'${value.replace(/'/g, `'\\''`)}'`;
  }

  private list(lines: string[]): string {
    return lines
      .map((line: string, index: number) => `  ${index + 1}. ${line}`)
      .join('\n');
  }

  private pin(cert: Pkcs11Cert): string {
    const pin = cert.pinFile
      ? this.readPinFile(cert.pinFile)
      : this.env[cert.pinEnv];

    if (!pin) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.PIN_UNAVAILABLE,
        cert.pinFile
          ? `The PIN file ${cert.pinFile} is empty or unreadable.`
          : `The environment variable ${cert.pinEnv} holding the PIN is not set.`,
        true
      );
    }

    return pin;
  }

  private readPinFile(path: string): string | undefined {
    try {
      // Editors and `echo` add a trailing newline that is not part of the PIN.
      return this.readFile(path).replace(/\r?\n$/, '');
    } catch {
      return undefined;
    }
  }

  private readCertFile(cert: Pkcs11Cert): Buffer | undefined {
    try {
      return Buffer.from(this.readFile(cert.certFile));
    } catch {
      return undefined;
    }
  }

  private warnIfExpired(cert: Pkcs11Cert, value: Buffer | undefined): void {
    if (!value) {
      return;
    }

    try {
      const x509 = new X509Certificate(value);
      const now = this.now();

      if (now > Date.parse(x509.validTo) || now < Date.parse(x509.validFrom)) {
        logger.warn(
          'PKCS#11: the client certificate for %s is not valid now (valid %s to %s); the target will likely reject it.',
          cert.hostname,
          x509.validFrom,
          x509.validTo
        );
      }
    } catch {
      logger.warn(
        'PKCS#11: the client certificate for %s cannot be parsed.',
        cert.hostname
      );
    }
  }

  /** @returns "" without a selector, otherwise ` with label "…" and id …`. */
  private describeSelector(cert: Pkcs11Cert): string {
    const parts = [
      cert.label !== undefined ? `label "${cert.label}"` : '',
      cert.id !== undefined ? `id ${cert.id}` : ''
    ].filter(Boolean);

    return parts.length ? ` with ${parts.join(' and ')}` : '';
  }

  private describeObject = ({ label, id }: Pkcs11ObjectInfo): string =>
    `"${label ?? ''}" (id ${id?.toString('hex') || '-'})`;

  private describeCertificate(certificate: Pkcs11CertificateInfo): string {
    const object = this.describeObject(certificate);

    try {
      const { subject, issuer, validTo } = new X509Certificate(
        certificate.value
      );
      const oneLine = (name: string) => name.split('\n').join(', ');

      return `${object}, subject "${oneLine(subject)}", issuer "${oneLine(
        issuer
      )}", valid until ${validTo}`;
    } catch {
      return object;
    }
  }
}
