import { Pkcs11Cert } from './Pkcs11Cert';
import { accessSync, constants, Stats, statSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

export interface Pkcs11CertParserOptions {
  env?: NodeJS.ProcessEnv;
  /** The entries are about to be written into a daemon service definition. */
  daemon?: boolean;
}

type RawEntry = Record<string, unknown>;

export class Pkcs11CertParser {
  private static readonly KNOWN_FIELDS: ReadonlySet<string> = new Set([
    'hostname',
    'port',
    'pinFile',
    'pinEnv',
    'token',
    'label',
    'id',
    'certFile',
    'maxConcurrency'
  ]);
  private static readonly HEX_ID = /^(?:[0-9a-f]{2})+$/i;
  private static readonly ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
  // `.env('REPEATER')` turns every variable starting with REPEATER into a repeater option.
  private static readonly RESERVED_ENV_PREFIX = /^REPEATER/i;

  /**
   * Turns raw `--pkcs11-cert` values into validated descriptors. A value is a
   * JSON string (CLI), a JSON string holding one object or an array of them
   * (env), or an object / array of objects (config file).
   *
   * @throws Error naming the offending entry; nothing is partially applied.
   */
  public static parse(
    entries: unknown,
    { env = process.env, daemon = false }: Pkcs11CertParserOptions = {}
  ): Pkcs11Cert[] {
    return Pkcs11CertParser.expand(entries).map(
      (raw: RawEntry, index: number) => {
        try {
          return Pkcs11CertParser.toDescriptor(raw, env, daemon);
        } catch (e) {
          throw new Error(
            `Option --pkcs11-cert #${index + 1}${Pkcs11CertParser.describeHost(
              raw
            )}: ${e.message}`
          );
        }
      }
    );
  }

  /**
   * @returns the absolute path of an existing regular file.
   * @throws Error mentioning `subject` when the file does not exist, or when
   * `daemon` is set and the path is relative.
   */
  public static resolveFile(
    path: string,
    subject: string,
    daemon = false
  ): string {
    // The daemon service re-parses the original arguments from its own working directory.
    if (daemon && !isAbsolute(path)) {
      throw new Error(
        `${subject} ${path} must be an absolute path when installing the daemon.`
      );
    }

    const absolute = resolve(path);
    let stats: Stats | undefined;

    try {
      stats = statSync(absolute);
    } catch {
      stats = undefined;
    }

    if (!stats?.isFile()) {
      throw new Error(
        `${subject} ${absolute} does not exist or is not a file.`
      );
    }

    return absolute;
  }

  private static expand(entries: unknown): RawEntry[] {
    if (entries === undefined || entries === null) {
      return [];
    }

    const values = Array.isArray(entries) ? entries : [entries];

    return values
      .flatMap((value: unknown, position: number) => {
        const parsed = Pkcs11CertParser.parseJson(value, position);

        return Array.isArray(parsed) ? parsed : [parsed];
      })
      .map((value: unknown, index: number) =>
        Pkcs11CertParser.toObject(value, index)
      );
  }

  private static parseJson(value: unknown, position: number): unknown {
    if (typeof value !== 'string') {
      return value;
    }

    try {
      return JSON.parse(value);
    } catch {
      throw new Error(
        `Option --pkcs11-cert value #${position + 1}: invalid JSON.`
      );
    }
  }

  private static toObject(value: unknown, index: number): RawEntry {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(
        `Option --pkcs11-cert #${index + 1}: expected a JSON object.`
      );
    }

    return value as RawEntry;
  }

  private static describeHost(raw: RawEntry): string {
    return typeof raw.hostname === 'string' && raw.hostname
      ? ` (hostname "${raw.hostname}")`
      : '';
  }

  private static toDescriptor(
    raw: RawEntry,
    env: NodeJS.ProcessEnv,
    daemon: boolean
  ): Pkcs11Cert {
    Pkcs11CertParser.assertKnownFields(raw);

    const hostname = Pkcs11CertParser.optionalString(raw, 'hostname');
    if (!hostname) {
      throw new Error(
        'specify "hostname" (without protocol and port) of the target that requires the certificate.'
      );
    }

    return {
      hostname,
      port: Pkcs11CertParser.port(raw),
      ...Pkcs11CertParser.pinSource(raw, env, daemon),
      token: Pkcs11CertParser.optionalString(raw, 'token'),
      label: Pkcs11CertParser.optionalString(raw, 'label'),
      id: Pkcs11CertParser.id(raw),
      certFile: Pkcs11CertParser.certFile(raw, daemon),
      maxConcurrency: Pkcs11CertParser.maxConcurrency(raw)
    };
  }

  private static assertKnownFields(raw: RawEntry): void {
    if ('pin' in raw) {
      throw new Error(
        'a literal "pin" is not accepted, because it would be stored in the process arguments and the daemon service definition. Use "pinFile" or "pinEnv".'
      );
    }

    if ('module' in raw) {
      throw new Error(
        '"module" is not a per-certificate field: all certificates share one PKCS#11 library. Set it once with --pkcs11-module.'
      );
    }

    // Entries written for former fields get their replacement named.
    if ('object' in raw) {
      throw new Error(
        '"object" was renamed to "label", which selects the certificate on the token by its label.'
      );
    }

    if ('cert' in raw) {
      throw new Error(
        '"cert" was replaced by "certFile", the path of a PEM file with the certificate. Leave it out to read the certificate from the token.'
      );
    }

    const unknown = Object.keys(raw).filter(
      (key: string) => !Pkcs11CertParser.KNOWN_FIELDS.has(key)
    );

    if (unknown.length) {
      throw new Error(
        `unknown field(s) ${unknown
          .map((key) => `"${key}"`)
          .join(', ')}. Allowed: ${[...Pkcs11CertParser.KNOWN_FIELDS].join(
          ', '
        )}.`
      );
    }
  }

  private static optionalString(
    raw: RawEntry,
    field: string
  ): string | undefined {
    const value = raw[field];

    if (value === undefined) {
      return undefined;
    }

    if (typeof value !== 'string' || !value.trim()) {
      throw new Error(`"${field}" must be a non-empty string.`);
    }

    return value.trim();
  }

  private static port(raw: RawEntry): string | undefined {
    if (raw.port === undefined) {
      return undefined;
    }

    const port = String(raw.port);
    const value = Number(port);

    if (!/^\d+$/.test(port) || value < 1 || value > 65535) {
      throw new Error('"port" must be a number between 1 and 65535.');
    }

    return port;
  }

  private static pinSource(
    raw: RawEntry,
    env: NodeJS.ProcessEnv,
    daemon: boolean
  ): Pick<Pkcs11Cert, 'pinFile' | 'pinEnv'> {
    const pinFile = Pkcs11CertParser.optionalString(raw, 'pinFile');
    const pinEnv = Pkcs11CertParser.optionalString(raw, 'pinEnv');

    if (!pinFile === !pinEnv) {
      throw new Error('specify exactly one of "pinFile" or "pinEnv".');
    }

    return pinEnv
      ? { pinEnv: Pkcs11CertParser.pinEnv(pinEnv, env, daemon) }
      : { pinFile: Pkcs11CertParser.pinFile(pinFile, daemon) };
  }

  private static pinEnv(
    name: string,
    env: NodeJS.ProcessEnv,
    daemon: boolean
  ): string {
    // The value is never echoed: a PIN typed here by mistake must not reach logs.
    if (!Pkcs11CertParser.ENV_NAME.test(name)) {
      throw new Error(
        '"pinEnv" must be the name of an environment variable (letters, digits and "_"), not the PIN itself.'
      );
    }

    if (Pkcs11CertParser.RESERVED_ENV_PREFIX.test(name)) {
      throw new Error(
        `"pinEnv" variable ${name} starts with "REPEATER", which bright-cli reads as its own options. Choose another name.`
      );
    }

    if (daemon) {
      throw new Error(
        '"pinEnv" is not available to the daemon service, which does not inherit this shell\'s environment. Use "pinFile".'
      );
    }

    if (!env[name]) {
      throw new Error(
        `environment variable ${name} referenced by "pinEnv" is not set.`
      );
    }

    return name;
  }

  private static pinFile(path: string, daemon: boolean): string {
    const absolute = Pkcs11CertParser.resolveFile(path, '"pinFile"', daemon);

    try {
      accessSync(absolute, constants.R_OK);
    } catch {
      throw new Error(`"pinFile" ${absolute} is not readable.`);
    }

    return absolute;
  }

  private static id(raw: RawEntry): string | undefined {
    const id = Pkcs11CertParser.optionalString(raw, 'id');

    if (id !== undefined && !Pkcs11CertParser.HEX_ID.test(id)) {
      throw new Error('"id" must be a hex-encoded CKA_ID, e.g. "01".');
    }

    return id?.toLowerCase();
  }

  private static certFile(raw: RawEntry, daemon: boolean): string | undefined {
    const path = Pkcs11CertParser.optionalString(raw, 'certFile');

    return path === undefined
      ? undefined
      : Pkcs11CertParser.resolveFile(path, '"certFile"', daemon);
  }

  private static maxConcurrency(raw: RawEntry): number {
    const value = raw.maxConcurrency ?? 1;

    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
      throw new Error('"maxConcurrency" must be an integer of at least 1.');
    }

    return value;
  }
}
