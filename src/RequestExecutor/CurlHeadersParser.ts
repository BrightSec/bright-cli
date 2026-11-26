export type ParsedHeaders = Record<string, string | string[]>;

/**
 * Parses the raw header dump libcurl collects for a transfer (all response
 * blocks: 1xx, redirects, final) and returns the fields of the last block.
 *
 * Not delegated to node-libcurl's `parseHeaders`: it splits on `/:\s(.+)/`,
 * which corrupts empty values (`name:`), values without a space after the
 * colon, and loses repeated fields.
 */
export class CurlHeadersParser {
  // Always an array, even for a single field (RFC 6265 §3: Set-Cookie must not
  // be folded), and what consumers have always received.
  private static readonly ARRAY_HEADERS: ReadonlySet<string> = new Set([
    'set-cookie'
  ]);

  // Single-valued by definition; consumers (content-type charset detection,
  // bridges) expect a string. A duplicate keeps the last value, as before.
  // Same set Node's http module collapses.
  private static readonly SINGLETON_HEADERS: ReadonlySet<string> = new Set([
    'age',
    'authorization',
    'content-length',
    'content-type',
    'etag',
    'expires',
    'from',
    'host',
    'if-modified-since',
    'if-unmodified-since',
    'last-modified',
    'location',
    'max-forwards',
    'proxy-authorization',
    'referer',
    'retry-after',
    'server',
    'user-agent'
  ]);

  private static readonly UTF8 = new TextDecoder('utf-8', { fatal: true });

  public static parse(raw: Buffer): ParsedHeaders {
    // latin1 maps every byte 1:1, so no byte is lost before values are decoded.
    const lines = raw.toString('latin1').split(/\r?\n/);
    let block: [string, string][] = [];
    let last = block;

    for (const line of lines) {
      // "/" is not a token character, so no field name can look like a status line.
      if (line.startsWith('HTTP/')) {
        block = [];
        last = block;
      } else if (line !== '') {
        CurlHeadersParser.appendField(line, block);
      }
    }

    return CurlHeadersParser.group(last);
  }

  private static appendField(line: string, block: [string, string][]): void {
    // Obsolete line folding (RFC 9112 §5.2): the continuation extends the
    // previous value, joined by a single space.
    if (/^[ \t]/.test(line) && block.length > 0) {
      block[block.length - 1][1] += ` ${line.trim()}`;

      return;
    }

    const colon = line.indexOf(':');
    if (colon <= 0) {
      return;
    }

    block.push([
      line.slice(0, colon).trim().toLowerCase(),
      line.slice(colon + 1).replace(/^[ \t]+|[ \t]+$/g, '')
    ]);
  }

  private static group(fields: [string, string][]): ParsedHeaders {
    const grouped = new Map<string, string[]>();

    for (const [name, value] of fields) {
      const values = grouped.get(name);
      if (values) {
        values.push(value);
      } else {
        grouped.set(name, [value]);
      }
    }

    const result: ParsedHeaders = {};
    for (const [name, rawValues] of grouped) {
      const values = rawValues.map((value) =>
        CurlHeadersParser.decodeValue(value)
      );

      if (CurlHeadersParser.SINGLETON_HEADERS.has(name)) {
        result[name] = values[values.length - 1];
      } else if (
        values.length === 1 &&
        !CurlHeadersParser.ARRAY_HEADERS.has(name)
      ) {
        result[name] = values[0];
      } else {
        result[name] = values;
      }
    }

    return result;
  }

  // The request side sends header strings as UTF-8, so valid UTF-8 must be
  // decoded to round-trip. Bytes that are not valid UTF-8 (obs-text) stay as
  // latin1 code points instead of becoming U+FFFD.
  private static decodeValue(latin1Value: string): string {
    if (/^[\t\x20-\x7e]*$/.test(latin1Value)) {
      return latin1Value;
    }

    try {
      return CurlHeadersParser.UTF8.decode(Buffer.from(latin1Value, 'latin1'));
    } catch {
      return latin1Value;
    }
  }
}
