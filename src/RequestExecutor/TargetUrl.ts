/**
 * Non-throwing, string-only decomposition of a target URL, shared by every
 * consumer on the request-execute path.
 *
 * `new URL()` throws on an authority defect, which would turn an otherwise
 * deliverable scanner request into `ERR_INVALID_URL` before it reaches libcurl.
 * This parser only slices strings, so such a URL travels on and libcurl answers
 * it (e.g. `CURLE_URL_MALFORMAT`).
 *
 * `hostname` is lowercased without IDNA/punycode conversion. Virtual-script and proxy-domain matching key on
 * the raw hostname.
 *
 * `hostname` is `undefined` when there is no authority; consumers then skip
 * host-keyed behaviour instead of matching the string `"null"` against a regex.
 *
 * `path` is kept byte-for-byte because libcurl runs with `PATH_AS_IS`.
 */
export interface TargetUrlParts {
  /** Scheme WITH its trailing colon, e.g. `'http:'`; `undefined` when absent. */
  readonly scheme?: string;
  /** `hostname[:port]` as `configureCurl` needs it; `undefined` when absent. */
  readonly host?: string;
  /** Lowercased hostname without port or IPv6 brackets; no IDNA conversion. */
  readonly hostname?: string;
  /** `user:pass` userinfo for libcurl `USERPWD`; `undefined` when absent. */
  readonly userinfo?: string;
  /** Raw path+query+hash, never normalised. Defaults to `'/'`. */
  readonly path: string;
}

export class TargetUrl {
  private static readonly SCHEME_SEPARATOR = '://';

  /**
   * Decompose a URL string. Never throws. An unparseable authority yields
   * `hostname === undefined` (and `host`/`scheme`/`userinfo` as available).
   */
  public static parse(url: string): TargetUrlParts {
    const path = TargetUrl.extractPath(url);

    const separatorIndex = url.indexOf(TargetUrl.SCHEME_SEPARATOR);

    // Origin-form target: no authority, so hostname stays undefined.
    if (separatorIndex === -1) {
      return { path };
    }

    const scheme = url.slice(0, separatorIndex + 1); // include trailing ':'
    const afterScheme = url.slice(
      separatorIndex + TargetUrl.SCHEME_SEPARATOR.length
    );

    // The authority ends at the first path/query/hash delimiter.
    const authorityEnd = afterScheme.search(/[/?#]/);
    const authority =
      authorityEnd === -1 ? afterScheme : afterScheme.slice(0, authorityEnd);

    return TargetUrl.decomposeAuthority(scheme, authority, path);
  }

  /**
   * Replace the userinfo component of a URL with `***`, so a rejection message
   * can quote the offending value without leaking credentials
   * (`http://user:pass@host/` → `http://***@host/`). Never throws; when there is
   * no userinfo the input is returned unchanged.
   */
  public static redact(url: string): string {
    const separatorIndex = url.indexOf(TargetUrl.SCHEME_SEPARATOR);

    if (separatorIndex === -1) {
      return url;
    }

    const afterSchemeStart = separatorIndex + TargetUrl.SCHEME_SEPARATOR.length;
    const afterScheme = url.slice(afterSchemeStart);

    const authorityEnd = afterScheme.search(/[/?#]/);
    const authority =
      authorityEnd === -1 ? afterScheme : afterScheme.slice(0, authorityEnd);

    const atIndex = authority.lastIndexOf('@');

    if (atIndex === -1) {
      return url;
    }

    const rest = authorityEnd === -1 ? '' : afterScheme.slice(authorityEnd);

    return `${url.slice(0, afterSchemeStart)}***@${authority.slice(
      atIndex + 1
    )}${rest}`;
  }

  private static decomposeAuthority(
    scheme: string,
    authority: string,
    path: string
  ): TargetUrlParts {
    if (!authority) {
      return { scheme, path };
    }

    const atIndex = authority.lastIndexOf('@');
    const userinfo =
      atIndex === -1 ? undefined : authority.slice(0, atIndex) || undefined;
    const host = atIndex === -1 ? authority : authority.slice(atIndex + 1);

    return {
      scheme,
      path,
      ...(userinfo !== undefined ? { userinfo } : {}),
      ...(host ? { host } : {}),
      ...(host ? { hostname: TargetUrl.extractHostname(host) } : {})
    };
  }

  /** Strips port and IPv6 brackets and lowercases, without IDNA conversion. */
  private static extractHostname(host: string): string {
    // Bracketed IPv6 literal: `[::1]` or `[::1]:8080`.
    if (host.startsWith('[')) {
      const closing = host.indexOf(']');

      if (closing !== -1) {
        return host.slice(1, closing).toLowerCase();
      }
    }

    const colonIndex = host.indexOf(':');
    const withoutPort = colonIndex === -1 ? host : host.slice(0, colonIndex);

    return withoutPort.toLowerCase();
  }

  /**
   * Extract the raw path+query+hash from a URL string without any
   * percent-encoding normalisation. Preserved verbatim from the previous
   * `HttpRequestExecutor.buildRawPath` so `PATH_AS_IS` behaviour is unchanged.
   */
  private static extractPath(url: string): string {
    const separatorIndex = url.indexOf(TargetUrl.SCHEME_SEPARATOR);
    const withoutProtocol =
      separatorIndex === -1
        ? url
        : url.slice(separatorIndex + TargetUrl.SCHEME_SEPARATOR.length);
    const pathStart = withoutProtocol.search(/[/?#]/);

    if (pathStart === -1) {
      return '/';
    }

    return withoutProtocol[pathStart] === '/'
      ? withoutProtocol.slice(pathStart)
      : `/${withoutProtocol.slice(pathStart)}`;
  }
}
