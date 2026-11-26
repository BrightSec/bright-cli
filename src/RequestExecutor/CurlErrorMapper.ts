import { CurlCode, Easy } from '@brightsec/node-libcurl';
import { constants } from 'node:os';

/**
 * Translates libcurl failures into the Node.js-style error codes (`ENOTFOUND`,
 * `ECONNREFUSED`, `ETIMEDOUT`, ...) that the repeater has always reported as
 * `errorCode`. Downstream consumers (bridges, the engine) classify target
 * failures by these codes, so a bare numeric CURLcode must never leak out.
 */
export class CurlErrorMapper {
  private static readonly CURL_CODE_TO_ERROR_CODE: ReadonlyMap<
    CurlCode,
    string
  > = new Map([
    [CurlCode.CURLE_COULDNT_RESOLVE_HOST, 'ENOTFOUND'],
    [CurlCode.CURLE_COULDNT_RESOLVE_PROXY, 'ENOTFOUND'],
    [CurlCode.CURLE_COULDNT_CONNECT, 'ECONNREFUSED'],
    [CurlCode.CURLE_OPERATION_TIMEDOUT, 'ETIMEDOUT'],
    // Node reports a peer that closes without replying as "socket hang up"
    // with `ECONNRESET`.
    [CurlCode.CURLE_GOT_NOTHING, 'ECONNRESET'],
    [CurlCode.CURLE_SEND_ERROR, 'EPIPE'],
    [CurlCode.CURLE_RECV_ERROR, 'ECONNRESET'],
    [CurlCode.CURLE_SSL_CONNECT_ERROR, 'EPROTO']
  ]);

  // Socket-level failures where libcurl records the underlying errno, which is
  // more precise than the CURLcode (e.g. `EHOSTUNREACH` vs `ECONNREFUSED`, both
  // reported as CURLE_COULDNT_CONNECT).
  private static readonly SOCKET_CURL_CODES: ReadonlySet<CurlCode> = new Set([
    CurlCode.CURLE_COULDNT_CONNECT,
    CurlCode.CURLE_SEND_ERROR,
    CurlCode.CURLE_RECV_ERROR
  ]);

  private static readonly ERRNO_NAMES: ReadonlyMap<number, string> = new Map(
    Object.entries(constants.errno)
      .reverse()
      .map(([name, value]: [string, number]) => [
        value,
        CurlErrorMapper.normalizeErrnoName(name)
      ])
  );

  // Several codes share this generic description, so it cannot identify one.
  private static readonly UNKNOWN_ERROR_DESCRIPTION = 'Unknown error';

  // libcurl error descriptions (`curl_easy_strerror`), longest first so a
  // description that ends with a shorter one is matched before it.
  private static readonly DESCRIPTIONS: readonly [string, CurlCode][] = [
    ...new Map(
      Object.values(CurlCode)
        .filter((value): value is CurlCode => typeof value === 'number')
        .map((code: CurlCode): [string, CurlCode] => [
          Easy.strError(code),
          code
        ])
        .filter(
          ([description]: [string, CurlCode]) =>
            description !== CurlErrorMapper.UNKNOWN_ERROR_DESCRIPTION
        )
    )
  ].sort(
    ([a]: [string, CurlCode], [b]: [string, CurlCode]) => b.length - a.length
  );

  /**
   * Resolves the CURLcode of an error emitted by a `Curl` handle.
   *
   * The binding reports it as a numeric `code`, but only when it can construct
   * its own error class. Otherwise (e.g. when loaded from a separate V8 realm)
   * it falls back to a plain `Error` whose message still carries the libcurl
   * description, so the code is recovered from the message instead.
   */
  public static resolveCurlCode(
    error: Error & { code?: unknown }
  ): CurlCode | undefined {
    if (typeof error.code === 'number') {
      return error.code;
    }

    const message = typeof error.message === 'string' ? error.message : '';

    return CurlErrorMapper.DESCRIPTIONS.find(
      ([description]: [string, CurlCode]) => message.endsWith(description)
    )?.[1];
  }

  public static toErrorCode(curlCode: CurlCode, osErrno?: number): string {
    if (CurlErrorMapper.SOCKET_CURL_CODES.has(curlCode) && osErrno) {
      const errnoName = CurlErrorMapper.ERRNO_NAMES.get(osErrno);

      // Only trust the OS errno when it maps to a canonical Node-style `E*`
      // code. On Windows the entry is a Winsock alias (`WSAECONNREFUSED`);
      // `normalizeErrnoName` strips the `WSA` prefix, and anything that still
      // isn't `E*`-shaped falls through to the CURLcode mapping below.
      if (errnoName && errnoName.startsWith('E')) {
        return errnoName;
      }
    }

    return (
      CurlErrorMapper.CURL_CODE_TO_ERROR_CODE.get(curlCode) ??
      // Keep unmapped failures identifiable by their symbolic libcurl name
      // (e.g. `CURLE_UNSUPPORTED_PROTOCOL`) rather than an opaque number.
      CurlCode[curlCode] ??
      `CURLE_${curlCode}`
    );
  }

  // Winsock errno constants are the UNIX names prefixed with `WSA`
  // (`WSAECONNREFUSED` <-> `ECONNREFUSED`), so stripping that prefix restores
  // the canonical Node-style `E*` name the mapper's contract is built on.
  private static normalizeErrnoName(name: string): string {
    return name.startsWith('WSAE') ? name.slice('WSA'.length) : name;
  }
}
