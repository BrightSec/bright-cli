import { Pkcs11Cert } from './Pkcs11Cert';
import { accessSync, constants, statSync } from 'node:fs';
import { normalize } from 'node:path';

export interface Pkcs11CertParserOptions {
  defaultModule?: string;
  env?: NodeJS.ProcessEnv;
}

type RawEntry = Record<string, unknown>;

export class Pkcs11CertParser {
  private static readonly KNOWN_FIELDS: ReadonlySet<string> = new Set([
    'hostname',
    'port',
    'module',
    'pinFile',
    'pinEnv',
    'token',
    'object',
    'id',
    'cert',
    'maxConcurrency'
  ]);
  private static readonly HEX_ID = /^(?:[0-9a-f]{2})+$/i;

  /**
   * Turns raw `--pkcs11-cert` entries (JSON strings from the CLI/env or objects
   * from the config file) into validated descriptors.
   *
   * @throws Error naming the offending entry; nothing is partially applied.
   */
  public static parse(
    entries: unknown[] | undefined,
    { defaultModule, env = process.env }: Pkcs11CertParserOptions = {}
  ): Pkcs11Cert[] {
    return (entries ?? []).map((entry: unknown, index: number) => {
      const raw = Pkcs11CertParser.toObject(entry, index);

      try {
        return Pkcs11CertParser.toDescriptor(raw, defaultModule, env);
      } catch (e) {
        throw new Error(
          `Option --pkcs11-cert #${index + 1}${Pkcs11CertParser.describeHost(
            raw
          )}: ${e.message}`
        );
      }
    });
  }

  private static toObject(entry: unknown, index: number): RawEntry {
    let value = entry;

    if (typeof entry === 'string') {
      try {
        value = JSON.parse(entry);
      } catch {
        throw new Error(`Option --pkcs11-cert #${index + 1}: invalid JSON.`);
      }
    }

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
    defaultModule: string | undefined,
    env: NodeJS.ProcessEnv
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
      module: Pkcs11CertParser.module(raw, defaultModule),
      ...Pkcs11CertParser.pinSource(raw, env),
      token: Pkcs11CertParser.optionalString(raw, 'token'),
      object: Pkcs11CertParser.optionalString(raw, 'object'),
      id: Pkcs11CertParser.id(raw),
      cert: Pkcs11CertParser.cert(raw),
      maxConcurrency: Pkcs11CertParser.maxConcurrency(raw)
    };
  }

  private static assertKnownFields(raw: RawEntry): void {
    if ('pin' in raw) {
      throw new Error(
        'a literal "pin" is not accepted, because it would be stored in the process arguments and the daemon service definition. Use "pinFile" or "pinEnv".'
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

  private static module(
    raw: RawEntry,
    defaultModule: string | undefined
  ): string {
    const module =
      Pkcs11CertParser.optionalString(raw, 'module') ?? defaultModule;

    if (!module) {
      throw new Error(
        'specify "module" (path to the PKCS#11 library of the card vendor) or set --pkcs11-module.'
      );
    }

    return Pkcs11CertParser.existingFile(module, 'module');
  }

  private static pinSource(
    raw: RawEntry,
    env: NodeJS.ProcessEnv
  ): Pick<Pkcs11Cert, 'pinFile' | 'pinEnv'> {
    const pinFile = Pkcs11CertParser.optionalString(raw, 'pinFile');
    const pinEnv = Pkcs11CertParser.optionalString(raw, 'pinEnv');

    if (!pinFile === !pinEnv) {
      throw new Error('specify exactly one of "pinFile" or "pinEnv".');
    }

    if (pinEnv) {
      if (!env[pinEnv]) {
        throw new Error(
          `environment variable "${pinEnv}" referenced by "pinEnv" is not set.`
        );
      }

      return { pinEnv };
    }

    const path = Pkcs11CertParser.existingFile(pinFile, 'pinFile');

    try {
      accessSync(path, constants.R_OK);
    } catch {
      throw new Error(`"pinFile" ${path} is not readable.`);
    }

    return { pinFile: path };
  }

  private static id(raw: RawEntry): string | undefined {
    const id = Pkcs11CertParser.optionalString(raw, 'id');

    if (id !== undefined && !Pkcs11CertParser.HEX_ID.test(id)) {
      throw new Error('"id" must be a hex-encoded CKA_ID, e.g. "01".');
    }

    return id?.toLowerCase();
  }

  private static cert(raw: RawEntry): string {
    const cert = Pkcs11CertParser.optionalString(raw, 'cert') ?? 'token';

    return cert === 'token'
      ? cert
      : Pkcs11CertParser.existingFile(cert, 'cert');
  }

  private static maxConcurrency(raw: RawEntry): number {
    const value = raw.maxConcurrency ?? 1;

    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
      throw new Error('"maxConcurrency" must be an integer of at least 1.');
    }

    return value;
  }

  private static existingFile(path: string, field: string): string {
    const normalized = normalize(path);

    let isFile = false;
    try {
      isFile = statSync(normalized).isFile();
    } catch {
      // reported below
    }

    if (!isFile) {
      throw new Error(`"${field}" file ${normalized} does not exist.`);
    }

    return normalized;
  }
}
