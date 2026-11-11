import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11Error';
import {
  Pkcs11CertificateInfo,
  Pkcs11Module,
  Pkcs11ModuleError,
  Pkcs11ModuleLoader,
  Pkcs11ObjectInfo,
  Pkcs11PrivateKeyInfo,
  Pkcs11Token
} from './Pkcs11Module';
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

/**
 * Checks each PKCS#11 certificate once before it is used: token present, PIN
 * usable, exactly one login, key and certificate found. Results are shared by
 * all concurrent callers and failures are remembered, so a wrong PIN costs the
 * card a single retry, not one per request.
 */
export class Pkcs11Preflight {
  public static readonly PIV_KEY_LABEL = 'Private key for PIV Authentication';
  private static readonly PIV_KEY_LABEL_PATTERN = /^Private key for (.+)$/;

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
      readFile = (path: string) => readFileSync(path, 'utf8')
    }: Pkcs11PreflightOptions = {}
  ) {
    this.retryAfterMs = retryAfterMs;
    this.now = now;
    this.env = env;
    this.readFile = readFile;
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
    const key = this.selectKey(module, session, cert);
    const certificate =
      cert.cert === 'token'
        ? this.selectCertificate(module, session, cert, key)
        : undefined;

    if (certificate) {
      logger.debug(
        'PKCS#11: using certificate %s from token "%s" for %s.',
        this.describeCertificate(certificate),
        token.label,
        cert.hostname
      );
    }

    this.warnIfExpired(cert, certificate?.value ?? this.readCertFile(cert));

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
      certFile: certificate ? undefined : cert.cert,
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

  private selectKey(
    module: Pkcs11Module,
    session: Buffer,
    cert: Pkcs11Cert
  ): Pkcs11PrivateKeyInfo {
    const explicit = cert.object !== undefined || cert.id !== undefined;
    const keys = module.findPrivateKeys(session, {
      label: cert.object,
      id: cert.id ? Buffer.from(cert.id, 'hex') : undefined
    });

    const key = explicit
      ? this.selectExplicitKey(cert, keys)
      : this.selectKeyAutomatically(module, session, cert, keys);

    if (!key) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.KEY_NOT_FOUND,
        explicit
          ? `No private key with ${this.describeSelector(cert)} on the token.`
          : `Cannot choose a private key; set "object" or "id". Keys found: ${
              keys.map(this.describeObject).join(', ') || 'none'
            }.`,
        true
      );
    }

    this.assertKeyUriIsUnique(module, session, key);

    return key;
  }

  private selectExplicitKey(
    cert: Pkcs11Cert,
    keys: Pkcs11PrivateKeyInfo[]
  ): Pkcs11PrivateKeyInfo | undefined {
    if (keys.length > 1) {
      const hint =
        cert.object !== undefined && cert.id !== undefined
          ? 'the OpenSSL provider cannot tell them apart'
          : 'set both "object" and "id" to choose one';

      throw new Pkcs11Error(
        Pkcs11ErrorCode.KEY_NOT_FOUND,
        `Several private keys have ${this.describeSelector(cert)}: ${keys
          .map(this.describeObject)
          .join(', ')}; ${hint}.`,
        true
      );
    }

    return keys[0];
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

  private selectKeyAutomatically(
    module: Pkcs11Module,
    session: Buffer,
    cert: Pkcs11Cert,
    keys: Pkcs11PrivateKeyInfo[]
  ): Pkcs11PrivateKeyInfo | undefined {
    const usable =
      cert.cert === 'token'
        ? keys.filter((key: Pkcs11PrivateKeyInfo) =>
            this.hasCertificate(module, session, key)
          )
        : keys;

    if (usable.length === 1) {
      return usable[0];
    }

    return keys.find(
      ({ label }: Pkcs11PrivateKeyInfo) =>
        label === Pkcs11Preflight.PIV_KEY_LABEL
    );
  }

  private hasCertificate(
    module: Pkcs11Module,
    session: Buffer,
    key: Pkcs11PrivateKeyInfo
  ): boolean {
    return (
      !!key.id?.length &&
      module.findCertificates(session, { id: key.id }).length > 0
    );
  }

  private selectCertificate(
    module: Pkcs11Module,
    session: Buffer,
    cert: Pkcs11Cert,
    key: Pkcs11PrivateKeyInfo
  ): Pkcs11CertificateInfo {
    const labels = this.certificateLabelsFor(key);
    const byId = key.id?.length
      ? module.findCertificates(session, { id: key.id })
      : [];
    const candidates = byId.length
      ? byId
      : labels.flatMap((label: string) =>
          module.findCertificates(session, { label })
        );

    if (!candidates.length) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.KEY_NOT_FOUND,
        `No certificate for key ${this.describeObject(
          key
        )} on the token; set "cert" to a PEM file for ${cert.hostname}.`,
        true
      );
    }

    // YubiKeys also expose a generated attestation certificate under the
    // key's id, with the same public key and a far later expiry.
    const paired =
      candidates.length > 1
        ? candidates.filter(
            ({ label }: Pkcs11CertificateInfo) =>
              label !== undefined && labels.includes(label)
          )
        : candidates;

    if (paired.length !== 1) {
      throw new Pkcs11Error(
        Pkcs11ErrorCode.KEY_NOT_FOUND,
        `Several certificates belong to key ${this.describeObject(
          key
        )}: ${candidates
          .map((candidate: Pkcs11CertificateInfo) =>
            this.describeCertificate(candidate)
          )
          .join(', ')}; set "cert" to a PEM file with the one ${
          cert.hostname
        } accepts.`,
        true
      );
    }

    return paired[0];
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
      return Buffer.from(this.readFile(cert.cert));
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

  private describeSelector(cert: Pkcs11Cert): string {
    return [
      cert.object ? `label "${cert.object}"` : '',
      cert.id ? `id ${cert.id}` : ''
    ]
      .filter(Boolean)
      .join(' and ');
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

      return `${object} [subject "${oneLine(subject)}", issuer "${oneLine(
        issuer
      )}", valid to ${validTo}]`;
    } catch {
      return object;
    }
  }
}
