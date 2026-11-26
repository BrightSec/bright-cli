import { TargetUrl } from './TargetUrl';

describe('TargetUrl', () => {
  describe('parse', () => {
    it('should decompose scheme, host, hostname, userinfo and path', () => {
      const parts = TargetUrl.parse(
        'http://user:pass@example.com:8080/a/b?q=1#f'
      );

      expect(parts).toEqual({
        scheme: 'http:',
        host: 'example.com:8080',
        hostname: 'example.com',
        userinfo: 'user:pass',
        path: '/a/b?q=1#f'
      });
    });

    it('should lowercase the hostname but leave the path casing untouched', () => {
      const parts = TargetUrl.parse('https://EXAMPLE.com/Path');

      expect(parts.hostname).toBe('example.com');
      expect(parts.host).toBe('EXAMPLE.com');
      expect(parts.path).toBe('/Path');
    });

    it('should default the path to "/" when the URL has none', () => {
      const parts = TargetUrl.parse('http://example.com');

      expect(parts.host).toBe('example.com');
      expect(parts.path).toBe('/');
    });

    it('should NOT apply IDNA/punycode to an internationalised hostname', () => {
      const parts = TargetUrl.parse('http://☃.net/x');

      expect(parts.hostname).toBe('☃.net');
    });

    it('should strip brackets from a bracketed IPv6 host and keep the port on host', () => {
      const parts = TargetUrl.parse('http://[::1]:8080/x');

      expect(parts.host).toBe('[::1]:8080');
      expect(parts.hostname).toBe('::1');
      expect(parts.path).toBe('/x');
    });

    it('should preserve an underscore host verbatim', () => {
      const parts = TargetUrl.parse('http://under_score/y');

      expect(parts.hostname).toBe('under_score');
    });

    // Authority shapes `new URL()` rejects; parse must not throw on them.
    const authorityDefects: [name: string, url: string][] = [
      ['non-numeric port', 'http://host:notaport/'],
      ['port > 65535', 'http://host:99999/'],
      ['unbracketed IPv6', 'http://::1/'],
      ['space in host', 'http://ho st/'],
      ['[not-ipv6]', 'http://[not-ipv6]/'],
      ['empty string', '']
    ];

    it.each(authorityDefects)('should not throw for %s', (_name, url) => {
      expect(() => TargetUrl.parse(url)).not.toThrow();
    });

    it('should still expose the scheme for an unbracketed IPv6 authority', () => {
      expect(TargetUrl.parse('http://::1/').scheme).toBe('http:');
    });

    it('should yield hostname undefined for an empty string', () => {
      expect(TargetUrl.parse('').hostname).toBeUndefined();
    });

    // The 19 scanner-controlled path malformations that must pass through
    // untouched — no percent-encoding normalisation — because libcurl is
    // driven with PATH_AS_IS.
    const pathMalformations: [name: string, url: string, expected: string][] = [
      ['space in path', 'http://h/path with spaces', '/path with spaces'],
      ['raw tab', 'http://h/a\tb', '/a\tb'],
      ['raw newline', 'http://h/a\nb', '/a\nb'],
      ['raw non-ascii latin1', 'http://h/caf\u00e9', '/caf\u00e9'],
      ['bad percent %zz', 'http://h/%zz', '/%zz'],
      ['lone percent', 'http://h/%', '/%'],
      ['double percent', 'http://h/%%', '/%%'],
      ['backslash', 'http://h/a\\b', '/a\\b'],
      ['fragment', 'http://h/p#frag', '/p#frag'],
      ['asterisk path', 'http://h/*', '/*'],
      ['query only', 'http://h?q=1', '/?q=1'],
      ['encoded slash', 'http://h/a%2fb', '/a%2fb'],
      ['double slash path', 'http://h//a//b', '//a//b'],
      ['semicolon params', 'http://h/a;b=c', '/a;b=c'],
      ['plus in query', 'http://h/a?x=1+2', '/a?x=1+2'],
      ['at in path', 'http://h/a@b', '/a@b'],
      ['colon in path', 'http://h/a:b', '/a:b'],
      ['unicode in query', 'http://h/a?q=\u2603', '/a?q=\u2603'],
      ['trailing dotdot', 'http://h/a/../b', '/a/../b']
    ];

    it.each(pathMalformations)(
      'should preserve the raw path for %s',
      (_name, url, expected) => {
        expect(TargetUrl.parse(url).path).toBe(expected);
      }
    );
  });

  describe('redact', () => {
    it('should replace userinfo with *** while preserving the rest', () => {
      expect(TargetUrl.redact('http://user:pass@host:8080/p?q=1')).toBe(
        'http://***@host:8080/p?q=1'
      );
    });

    it('should redact userinfo with no password', () => {
      expect(TargetUrl.redact('http://user@host/p')).toBe('http://***@host/p');
    });

    it('should leave a URL without userinfo unchanged', () => {
      expect(TargetUrl.redact('http://host/p')).toBe('http://host/p');
    });

    it('should leave an origin-form value unchanged', () => {
      expect(TargetUrl.redact('/p?q=1')).toBe('/p?q=1');
    });

    it('should not treat an @ in the path as userinfo', () => {
      expect(TargetUrl.redact('http://host/a@b')).toBe('http://host/a@b');
    });
  });
});
