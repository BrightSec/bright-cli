import 'reflect-metadata';
import type { Request as RequestInterface } from './Request';
import { Protocol } from './Protocol';
import fs from 'node:fs';

describe('Request', () => {
  let readFileMock!: jest.Mock;
  let Request!: typeof RequestInterface;
  const certContent = Buffer.from([]);

  beforeEach(async () => {
    readFileMock = jest.fn();
    jest.doMock('node:fs/promises', () => ({ ...fs, readFile: readFileMock }));
    // ADHOC: `jest.doMock` must be called before importing SUT
    Request = (await import('./Request')).Request;
  });

  afterEach(() => {
    jest.resetModules();
    readFileMock.mockReset();
  });

  describe('loadCert', () => {
    it.each(['https://foo.bar', 'wss://foo.bar'])(
      'should read cert for url %s if there was matching certificate configured globally',
      async (url) => {
        //arrange
        const cert = {
          path: '~/cert.pfx',
          hostname: 'foo.bar'
        };
        const request = new Request({
          url,
          headers: {},
          protocol: Protocol.HTTP
        });
        //arrange:mock
        readFileMock.mockImplementation((filePath) =>
          filePath === cert.path
            ? Promise.resolve(certContent)
            : Promise.reject(new Error('no such file'))
        );
        //act
        await request.loadCert(cert);
        //assert
        expect(request.pfx).toBeTruthy();
      }
    );
  });

  describe('toJSON', () => {
    it('should round-trip every option the constructor accepts', () => {
      // arrange
      const options = {
        protocol: Protocol.HTTP,
        url: 'http://foo.bar/',
        method: 'POST',
        headers: { 'x-key': 'value' },
        body: 'AAAA',
        passphrase: 'pass',
        correlationIdRegex: 'x-correlation-id',
        encoding: 'base64' as const,
        maxContentSize: 99,
        timeout: 1234,
        decompress: false,
        keepAlive: true
      };
      const request = new Request(options);

      // act
      const copy = new Request(request.toJSON());

      // assert
      expect(copy).toEqual(
        expect.objectContaining({
          protocol: options.protocol,
          url: options.url,
          method: options.method,
          body: options.body,
          passphrase: options.passphrase,
          encoding: options.encoding,
          maxContentSize: options.maxContentSize,
          timeout: options.timeout,
          decompress: options.decompress,
          keepAlive: options.keepAlive
        })
      );
      expect(copy.headers).toEqual(options.headers);
      expect(copy.correlationIdRegex).toEqual(request.correlationIdRegex);
    });

    it('should preserve an explicit decompress: false rather than defaulting it back to true', () => {
      // arrange
      // `decompress` defaults to `true` in the constructor, so omitting it from
      // `toJSON()` silently flips it instead of merely dropping it.
      const request = new Request({
        protocol: Protocol.HTTP,
        url: 'http://foo.bar/',
        decompress: false
      });

      // act
      const copy = new Request(request.toJSON());

      // assert
      expect(copy.decompress).toBe(false);
    });
  });

  describe('setHeaders', () => {
    it('should append headers', () => {
      const request = new Request({
        url: 'http://foo.bar',
        headers: { 'x-key': 'value' },
        protocol: Protocol.HTTP
      });

      request.setHeaders({ 'x-a1': 'a1', 'x-a2': 'a2' });

      expect(request.headers).toEqual({
        'x-key': 'value',
        'x-a1': 'a1',
        'x-a2': 'a2'
      });
    });

    it('should join headers if multiple values is present', () => {
      const request = new Request({
        url: 'http://foo.bar',
        protocol: Protocol.HTTP
      });

      request.setHeaders({ host: ['example.com', 'example1.com'] });

      expect(request.headers).toEqual({
        host: 'example.com, example1.com'
      });
    });
  });

  describe('constructor', () => {
    // The six authority shapes the WHATWG parser (old new URL() predicate)
    // rejected. bridges accepts them and dispatches them, so the CLI must too —
    // they now construct successfully and are answered by libcurl downstream.
    const previouslyRejected = [
      'http://host:notaport/',
      'http://host:99999/',
      'http://::1/',
      'http://ho st/',
      'http://[not-ipv6]/',
      'http://user@host name/'
    ];

    it.each(previouslyRejected)(
      'should accept the previously-rejected authority shape %s',
      (url) => {
        expect(
          () => new Request({ url, protocol: Protocol.HTTP })
        ).not.toThrow();
      }
    );

    it('should trim and store the url', () => {
      const request = new Request({
        url: '  http://foo.bar/x  ',
        protocol: Protocol.HTTP
      });

      expect(request.url).toBe('http://foo.bar/x');
    });

    it('should still reject an empty url', () => {
      expect(() => new Request({ url: '', protocol: Protocol.HTTP })).toThrow(
        /Invalid URL/
      );
    });

    it('should still reject a whitespace-only url', () => {
      expect(
        () => new Request({ url: '   ', protocol: Protocol.HTTP })
      ).toThrow(/Invalid URL/);
    });

    it('should carry the offending value on the rejection message', () => {
      // A blank url is the only surviving rejection; its (empty) value is named.
      expect(() => new Request({ url: '', protocol: Protocol.HTTP })).toThrow(
        'Invalid URL: '
      );
    });

    it('should build the rejection message through the userinfo-redacting formatter', () => {
      // The only surviving rejection is a blank-after-trim url, so the offending
      // value is empty here; the credential-redaction guarantee itself is proven
      // in TargetUrl.spec (redact). This pins that the message is produced via
      // that redacting formatter rather than interpolating a raw url, so a
      // future non-blank rejection could never leak userinfo to Sentry.
      expect(() => new Request({ url: '', protocol: Protocol.HTTP })).toThrow(
        'Invalid URL: '
      );
    });

    it('should accept a credentialed url without leaking it (no rejection path)', () => {
      expect(
        () =>
          new Request({
            url: 'http://user:pass@host/',
            protocol: Protocol.HTTP
          })
      ).not.toThrow();
    });

    // The trace id must never reach the target. bridges carries it as a `traceId`
    // DTO field, and the guarantee that an old repeater cannot leak it rests on
    // this constructor's FIXED destructured param list — an unknown key is
    // discarded, never copied into `headers`. If a future refactor switches to
    // `Object.assign(this, opts)` or a `...rest` capture, this test must fail
    // loudly rather than silently reintroduce the leak.
    it('should discard an unknown traceId option and never place it in headers', () => {
      const request = new Request({
        url: 'http://foo.bar',
        protocol: Protocol.HTTP,
        headers: { 'x-key': 'value' },
        // cast: `traceId` is not part of RequestOptions on the cli side by design
        ...({ traceId: 'trace-abc12345' } as object)
      });

      expect(request.headers).toEqual({ 'x-key': 'value' });
      expect(request.headers).not.toHaveProperty('traceId');
      expect(request.headers).not.toHaveProperty('x-bridge-trace-id');
    });
  });
});
