import 'reflect-metadata';
import { HttpRequestExecutor } from './HttpRequestExecutor';
import { VirtualScript, VirtualScripts, VirtualScriptType } from '../Scripts';
import { Protocol } from './Protocol';
import { Request, RequestOptions, Cert } from './Request';
import { RequestExecutorOptions } from './RequestExecutorOptions';
import { CertificatesCache } from './CertificatesCache';
import { CertificatesResolver } from './CertificatesResolver';
import { Pkcs11Cert } from './Pkcs11Cert';
import { CurlHandlePool } from './Pkcs11/CurlHandlePool';
import { Pkcs11Client } from './Pkcs11/Pkcs11Client';
import { Pkcs11Error, Pkcs11ErrorCode } from './Pkcs11/Pkcs11Error';
import { Pkcs11Identity } from './Pkcs11/Pkcs11Preflight';
import {
  anyString,
  anything,
  instance,
  mock,
  reset,
  spy,
  verify,
  when
} from 'ts-mockito';
import { Curl } from '@brightsec/node-libcurl';
import http from 'node:http';
import { once } from 'node:events';
import net, { AddressInfo } from 'node:net';
import { promisify } from 'node:util';
import {
  brotliCompress,
  constants,
  gzip,
  deflate,
  deflateRaw
} from 'node:zlib';

// The real client writes an OpenSSL config and points OPENSSL_CONF at it, which
// would leak into every other test in this worker.
jest.mock('./Pkcs11/Pkcs11Client');

// A short latency budget guard for the repeater's outbound request path.
//
// The repeater handles one inbound event per request, so it issues outbound
// requests serially. That is the pattern that regresses when the native libcurl
// binding stops draining completions promptly: the transfer itself finishes in
// microseconds, but the `end` event is only delivered once libcurl's multi timer
// fires. Concurrency masks it, because other in-flight transfers keep waking the
// event loop - only a serialized measurement exposes it.
//
// Asserting on the MEAN is deliberate. The observed failure mode is periodic
// rather than uniform: on an affected runtime roughly every third request stalls
// (measured 711, 201, 95, 702, 226, 149, ... ms) while the rest look merely
// sluggish, so the median stays low enough to slip past a threshold that the
// mean trips decisively. Against a loopback server a healthy path averages well
// under a millisecond, so the budget below leaves two orders of magnitude of
// headroom for a loaded CI runner while still catching a single stalled request.
const MEASURED_REQUESTS = 12;
const WARMUP_REQUESTS = 3;
const MAX_MEAN_LATENCY_MS = 50;

const serversToClose: http.Server[] = [];

async function startServer(
  handler?: (req: http.IncomingMessage, res: http.ServerResponse) => void
): Promise<{
  port: number;
  baseUrl: string;
  server: net.Server;
  received: () => Promise<string>;
  close: () => void;
}> {
  if (handler) {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;
    serversToClose.push(server);

    return {
      port,
      baseUrl: `http://127.0.0.1:${port}`,
      server,
      received: () =>
        Promise.reject(new Error('received() is not available in HTTP mode')),
      close: () => server.close()
    };
  }

  return new Promise((resolve) => {
    let resolveReceived: (data: string) => void;
    const receivedPromise = new Promise<string>((res) => {
      resolveReceived = res;
    });

    const server = net.createServer((socket) => {
      let raw = '';
      socket.on('data', (chunk) => {
        raw += chunk.toString('latin1');
        // Resolve immediately so the test can inspect the data, then send a
        // minimal HTTP/1.1 response so libcurl does not hang waiting for one.
        resolveReceived(raw);
        socket.write(
          'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        );
        socket.end();
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        port,
        baseUrl: `http://127.0.0.1:${port}`,
        server,
        received: () => receivedPromise,
        close: () => server.close()
      });
    });
  });
}

/** Returns the first line (request-line) of a raw HTTP request string. */
function extractRequestLine(raw: string): string {
  return raw.split('\r\n')[0];
}

const createRequest = (options?: Partial<RequestOptions>) => {
  const requestOptions: RequestOptions = {
    url: 'http://127.0.0.1:1',
    headers: {},
    protocol: Protocol.HTTP,
    ...options
  };
  const request = new Request(requestOptions);
  const spiedRequest = spy(request);
  when(spiedRequest.method).thenReturn(options?.method ?? 'GET');

  return { requestOptions, request, spiedRequest };
};

describe('HttpRequestExecutor', () => {
  const virtualScriptsMock = mock<VirtualScripts>();
  const certificatesCacheMock = mock<CertificatesCache>();
  const certificatesResolverMock = mock<CertificatesResolver>();

  let MultiSpy!: jest.SpyInstance;

  const buildSut = (options: RequestExecutorOptions = {}) =>
    new HttpRequestExecutor(
      instance(virtualScriptsMock),
      options,
      certificatesCacheMock,
      instance(certificatesResolverMock)
    );

  beforeEach(() => {
    // Spy on the Multi constructor so tests can assert on call count.
    // Capture the real constructor before installing the spy so that the
    // mock implementation can call through without recursion.
    type CurlLibModule = typeof import('@brightsec/node-libcurl');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const curlModule = require('@brightsec/node-libcurl') as CurlLibModule;
    const RealMulti = curlModule.Multi;
    MultiSpy = jest
      .spyOn(curlModule, 'Multi')
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .mockImplementation(
        () => new (RealMulti as any)()
      ) as unknown as jest.SpyInstance;
  });

  afterEach(() => {
    MultiSpy?.mockRestore();

    reset<
      | VirtualScripts
      | RequestExecutorOptions
      | CertificatesCache
      | CertificatesResolver
    >(virtualScriptsMock, certificatesCacheMock, certificatesResolverMock);

    return Promise.all(
      serversToClose.splice(0).map(
        (server) =>
          new Promise<void>((resolve) => {
            server.closeAllConnections();
            server.close(resolve);
          })
      )
    );
  });

  describe('protocol', () => {
    it('should return HTTP', () => {
      // arrange
      const sut = buildSut();

      // act
      const protocol = sut.protocol;

      // assert
      expect(protocol).toBe(Protocol.HTTP);
    });
  });

  describe('execute', () => {
    it('should call setHeaders on the provided request if additional headers were configured globally', async () => {
      // arrange
      const headers = { testHeader: 'test-header-value' };
      const sut = buildSut({ headers });
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const { request, spiedRequest } = createRequest({ url: `${baseUrl}/` });

      // act
      await sut.execute(request);

      // assert
      verify(spiedRequest.setHeaders(headers)).once();
    });

    it('should not call setHeaders on the provided request if there were no additional headers configured', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const { request, spiedRequest } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      verify(spiedRequest.setHeaders(anything())).never();
    });

    it('should transform the request if there is a suitable vm', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const { request, requestOptions } = createRequest({
        url: `${baseUrl}/`
      });
      const { hostname: virtualScriptId } = new URL(requestOptions.url);
      const virtualScript = new VirtualScript(
        virtualScriptId,
        VirtualScriptType.LOCAL,
        'console.log("test code");'
      );
      const spiedVirtualScript = spy(virtualScript);
      when(spiedVirtualScript.exec(anyString(), anything())).thenResolve(
        requestOptions
      );
      when(virtualScriptsMock.find(virtualScriptId)).thenReturn(
        virtualScript,
        undefined
      );
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      verify(spiedVirtualScript.exec(anyString(), anything())).once();
    });

    it('should not transform the request if there is no suitable vm', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const { request, spiedRequest } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      verify(spiedRequest.toJSON()).never();
    });

    it('should call loadCert on the provided request if there were certificates configured globally', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const { request, spiedRequest } = createRequest({ url: `${baseUrl}/` });
      const certs: Cert[] = [
        {
          path: '/tmp/cert.pem',
          hostname: new URL(request.url).hostname
        }
      ];
      when(certificatesResolverMock.resolve(request, anything())).thenReturn(
        certs
      );
      const sut = buildSut({ certs });

      // act
      await sut.execute(request);

      // assert
      verify(spiedRequest.loadCert(anything())).once();
    });

    it('should not call loadCert on the provided request if there were no certificates configured', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const { request, spiedRequest } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      verify(spiedRequest.loadCert(anything())).never();
    });

    it('should perform an external http request', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{}');
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({ statusCode: 200, body: '{}' });
    });

    it('should complete HEAD requests with a nonzero Content-Length and no body', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'application/json',
          'content-length': '12345'
        });
        res.end();
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'HEAD'
      });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({
        statusCode: 200,
        body: '',
        headers: { 'content-length': '12345' }
      });
      expect(response.errorCode).toBeUndefined();
    });

    it('should populate ttfb as a non-negative integer milliseconds value', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{}');
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.ttfb).toBeGreaterThanOrEqual(0);
      expect(Number.isInteger(response.ttfb)).toBe(true);
    });

    it('should not populate ttfb on connection error', async () => {
      // arrange
      const { request } = createRequest({ url: 'http://127.0.0.1:1/' });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.ttfb).toBeUndefined();
    });

    it('should handle HTTP errors', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end('{}');
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({ statusCode: 500, body: '{}' });
    });

    it('should preserve directory traversal', async () => {
      // arrange
      const path = '/public/../../../../../../etc/passwd';
      let receivedPath: string;
      const { baseUrl } = await startServer((req, res) => {
        receivedPath = req.url;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{}');
      });
      const { request } = createRequest({ url: `${baseUrl}${path}` });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({ statusCode: 200 });
      expect(receivedPath).toBe(path);
    });

    it('should preserve query string when URL has no explicit path', async () => {
      // arrange
      let receivedPath: string;
      const { port } = await startServer((req, res) => {
        receivedPath = req.url;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{}');
      });
      const { request } = createRequest({
        url: `http://127.0.0.1:${port}?x=1&y=2`
      });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({ statusCode: 200 });
      expect(receivedPath).toBe('/?x=1&y=2');
    });

    it('should report ETIMEDOUT when the target does not respond in time', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, _res) => {
        // Never respond — triggers timeout
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({ timeout: 50 });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({
        protocol: Protocol.HTTP,
        statusCode: undefined,
        errorCode: 'ETIMEDOUT',
        message: expect.any(String)
      });
    });

    it('should report ECONNREFUSED when the target refuses the connection', async () => {
      // arrange
      const { request } = createRequest({
        url: 'http://127.0.0.1:1/'
      });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({
        protocol: Protocol.HTTP,
        statusCode: undefined,
        errorCode: 'ECONNREFUSED',
        message: expect.any(String)
      });
    });

    it('should report ENOTFOUND when the target host cannot be resolved', async () => {
      // arrange
      // RFC 6761: `.invalid` names are guaranteed never to resolve.
      const { request } = createRequest({
        url: 'http://repeater-spec.invalid/'
      });
      const sut = buildSut({ timeout: 5000 });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({
        statusCode: undefined,
        errorCode: 'ENOTFOUND'
      });
    });

    it('should report ECONNRESET when the target closes the connection without replying', async () => {
      // arrange
      const server = net.createServer((socket) =>
        socket.on('data', () => socket.end())
      );
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const { port } = server.address() as AddressInfo;
      const { request } = createRequest({ url: `http://127.0.0.1:${port}/` });
      const sut = buildSut({ timeout: 5000 });

      try {
        // act
        const response = await sut.execute(request);

        // assert
        expect(response).toMatchObject({
          statusCode: undefined,
          errorCode: 'ECONNRESET'
        });
      } finally {
        server.close();
      }
    });

    it('should report ECONNRESET when the target resets the connection', async () => {
      // arrange
      const server = net.createServer((socket) =>
        socket.on('data', () => socket.resetAndDestroy())
      );
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const { port } = server.address() as AddressInfo;
      const { request } = createRequest({ url: `http://127.0.0.1:${port}/` });
      const sut = buildSut({ timeout: 5000 });

      try {
        // act
        const response = await sut.execute(request);

        // assert
        expect(response).toMatchObject({
          statusCode: undefined,
          errorCode: 'ECONNRESET'
        });
      } finally {
        server.close();
      }
    });

    it('should report EPROTO when the TLS handshake fails', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => res.end());
      const { request } = createRequest({
        url: baseUrl.replace('http://', 'https://')
      });
      const sut = buildSut({ timeout: 5000 });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({
        statusCode: undefined,
        errorCode: 'EPROTO'
      });
    });

    it('should truncate response body with not white-listed mime type', async () => {
      // arrange
      const bigBody = 'x'.repeat(1025);
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/x-custom' });
        res.end(bigBody);
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({ maxContentLength: 1 });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body?.length).toEqual(1024);
      expect(response.body).toEqual(bigBody.slice(0, 1024));
    });

    it('should not truncate response body if its smaller than limit and it is in allowed mime types', async () => {
      // arrange
      const bigBody = 'x'.repeat(1025);
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/x-custom' });
        res.end(bigBody);
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({
        maxBodySize: 1025,
        whitelistMimes: [
          { type: 'application/x-custom', allowTruncation: false }
        ]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(bigBody);
    });

    it('should truncate response body if its larger than limit and it is in allowed mime types that require truncation', async () => {
      // arrange
      const bigBody = 'x'.repeat(1025);
      const expected = bigBody.slice(0, 1024);
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end(bigBody);
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({
        maxBodySize: 1024,
        whitelistMimes: [{ type: 'text/plain', allowTruncation: true }]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(expected);
    });

    it('should omit response body if its larger than limit and it is in allowed mime types that require omission', async () => {
      // arrange
      const bigBody = 'x'.repeat(1025);
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(bigBody);
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({
        maxBodySize: 1024,
        whitelistMimes: [{ type: 'application/json', allowTruncation: false }]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual('');
    });

    it('should decode response body if content-encoding is brotli', async () => {
      // arrange
      const expected = 'x'.repeat(100);
      const compressed = await promisify(brotliCompress)(expected);
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'text/plain',
          'content-encoding': 'br'
        });
        res.end(compressed);
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        decompress: true
      });
      const sut = buildSut({
        maxBodySize: 2000,
        whitelistMimes: [{ type: 'text/plain', allowTruncation: true }]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(expected);
    });

    it('should prevent decoding response body if decompress option is disabled', async () => {
      // arrange
      const expected = 'x'.repeat(100);
      const compressed = await promisify(gzip)(expected, {
        flush: constants.Z_SYNC_FLUSH,
        finishFlush: constants.Z_SYNC_FLUSH
      });
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'text/plain',
          'content-encoding': 'gzip'
        });
        res.end(compressed);
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        decompress: false,
        encoding: 'base64'
      });
      const sut = buildSut({
        maxBodySize: 2000,
        whitelistMimes: [{ type: 'text/plain', allowTruncation: true }]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(compressed.toString('base64'));
      expect(response.headers).toMatchObject({ 'content-encoding': 'gzip' });
    });

    it('should decode response body if content-encoding is gzip', async () => {
      // arrange
      const expected = 'x'.repeat(100);
      const compressed = await promisify(gzip)(expected, {
        flush: constants.Z_SYNC_FLUSH,
        finishFlush: constants.Z_SYNC_FLUSH
      });
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'text/plain',
          'content-encoding': 'gzip'
        });
        res.end(compressed);
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        decompress: true
      });
      const sut = buildSut({
        maxBodySize: 2000,
        whitelistMimes: [{ type: 'text/plain', allowTruncation: true }]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(expected);
    });

    it('should decode response body if content-encoding is deflate', async () => {
      // arrange
      const expected = 'x'.repeat(100);
      const compressed = await promisify(deflate)(expected, {
        flush: constants.Z_SYNC_FLUSH,
        finishFlush: constants.Z_SYNC_FLUSH
      });
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'text/plain',
          'content-encoding': 'deflate'
        });
        res.end(compressed);
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        decompress: true
      });
      const sut = buildSut({
        maxBodySize: 2000,
        whitelistMimes: [{ type: 'text/plain', allowTruncation: true }]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(expected);
    });

    it('should decode response body if content-encoding is deflate and content does not have zlib headers', async () => {
      // arrange
      const expected = 'x'.repeat(100);
      const compressed = await promisify(deflateRaw)(expected, {
        flush: constants.Z_SYNC_FLUSH,
        finishFlush: constants.Z_SYNC_FLUSH
      });
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'text/plain',
          'content-encoding': 'deflate'
        });
        res.end(compressed);
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        decompress: true
      });
      const sut = buildSut({
        maxBodySize: 2000,
        whitelistMimes: [{ type: 'text/plain', allowTruncation: true }]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(expected);
    });

    it('should decode and truncate gzipped response body if content-type is not in allowed list', async () => {
      // arrange
      const bigBody = 'x'.repeat(1025);
      const expected = bigBody.slice(0, 1024);
      const compressed = await promisify(gzip)(bigBody, {
        flush: constants.Z_SYNC_FLUSH,
        finishFlush: constants.Z_SYNC_FLUSH
      });
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'text/html',
          'content-encoding': 'gzip'
        });
        res.end(compressed);
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        decompress: true
      });
      const sut = buildSut({
        maxContentLength: 1,
        whitelistMimes: [{ type: 'text/plain', allowTruncation: true }]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(expected);
    });

    it('should not truncate response body if allowed mime type starts with actual one', async () => {
      // arrange
      const bigBody = 'x'.repeat(1025);
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, {
          'content-type': 'application/x-custom-with-suffix'
        });
        res.end(bigBody);
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({
        maxBodySize: 1025,
        whitelistMimes: [
          { type: 'application/x-custom', allowTruncation: false }
        ]
      });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual(bigBody);
    });

    it('should skip truncate on 204 response status', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(204);
        res.end();
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({ maxContentLength: 1 });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual('');
    });

    it('should send requests with unescaped characters in the path (Case 1)', async () => {
      // arrange
      let receivedPath: string;
      const { port } = await startServer((req, res) => {
        receivedPath = req.url;
        res.writeHead(200);
        res.end('ok');
      });
      const { request } = createRequest({
        url: `http://127.0.0.1:${port}/path|with|pipes`
      });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.statusCode).toBe(200);
      expect(receivedPath).toBe('/path|with|pipes');
    });

    it('should write a malformed path verbatim on the wire', async () => {
      // arrange
      // Paths containing characters that are illegal in an HTTP request-line
      // (e.g. spaces and colons that mimic a status line) must be forwarded
      // exactly as supplied. A raw TCP server is used to capture the bytes
      // before any HTTP parsing can strip or reject them.
      const fixture = await startServer();
      const rawPath = '/?msg=Server: ESA1 HTTP/1.1';
      const { request } = createRequest({
        url: `http://127.0.0.1:${fixture.port}${rawPath}`
      });
      const sut = buildSut();

      // act
      // Run the executor and the TCP capture concurrently: execute() will
      // block until it gets an HTTP response, which the TCP server sends as
      // soon as it receives the request.
      const results = await Promise.all([
        sut.execute(request),
        fixture.received()
      ]);
      fixture.close();

      // assert
      expect(extractRequestLine(results[1])).toBe(`GET ${rawPath} HTTP/1.1`);
    });

    it('should not send the libcurl default User-Agent header', async () => {
      // arrange
      let receivedUserAgent: string | undefined;
      const { baseUrl } = await startServer((req, res) => {
        receivedUserAgent = req.headers['user-agent'];
        res.writeHead(200);
        res.end('ok');
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      expect(receivedUserAgent).toBeUndefined();
    });

    it('should preserve a caller-supplied User-Agent header', async () => {
      // arrange
      let receivedUserAgent: string | undefined;
      const { baseUrl } = await startServer((req, res) => {
        receivedUserAgent = req.headers['user-agent'];
        res.writeHead(200);
        res.end('ok');
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        headers: { 'User-Agent': 'my-scanner/1.0' }
      });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      expect(receivedUserAgent).toBe('my-scanner/1.0');
    });

    it('should forward a caller-supplied Host header verbatim to the server', async () => {
      // arrange
      // The scanner sends security-test payloads in the Host header (e.g. Host
      // injection, SSRF probes). The value must reach the server byte-for-byte;
      // libcurl's URL-derived Host is overridden by the HTTPHEADER entry.
      let receivedHeaders: http.IncomingHttpHeaders | undefined;
      const { baseUrl } = await startServer((req, res) => {
        receivedHeaders = req.headers;
        res.writeHead(200);
        res.end('ok');
      });
      const { request } = createRequest({
        url: `${baseUrl}/`,
        headers: { host: 'evil.example.com' }
      });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      expect(receivedHeaders?.['host']).toBe('evil.example.com');
    });

    it('should forward a Host header containing an injection payload verbatim', async () => {
      // arrange
      let receivedHeaders: http.IncomingHttpHeaders | undefined;
      const { baseUrl } = await startServer((req, res) => {
        receivedHeaders = req.headers;
        res.writeHead(200);
        res.end('ok');
      });
      const injectionPayload = 'evil.internal; X-Forwarded-Host: attacker.com';
      const { request } = createRequest({
        url: `${baseUrl}/some-proper-url`,
        headers: { host: injectionPayload }
      });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      expect(receivedHeaders?.['host']).toBe(injectionPayload);
    });

    it('should send Authorization header when URL contains embedded credentials', async () => {
      // arrange
      let receivedAuthorization: string | undefined;
      const { port } = await startServer((req, res) => {
        receivedAuthorization = req.headers['authorization'];
        res.writeHead(200);
        res.end('ok');
      });
      const { request } = createRequest({
        url: `http://user:password@127.0.0.1:${port}/`
      });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      // libcurl sends HTTP Basic auth when USERPWD is set
      expect(receivedAuthorization).toBe(
        `Basic ${Buffer.from('user:password').toString('base64')}`
      );
    });

    it('should not send Authorization header when URL has no embedded credentials', async () => {
      // arrange
      let receivedAuthorization: string | undefined;
      const { baseUrl } = await startServer((req, res) => {
        receivedAuthorization = req.headers['authorization'];
        res.writeHead(200);
        res.end('ok');
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      await sut.execute(request);

      // assert
      expect(receivedAuthorization).toBeUndefined();
    });

    it('should send Accept-Encoding: identity when decompress is false and no accept-encoding header is provided', async () => {
      // arrange
      const fixture = await startServer();
      const { request } = createRequest({
        url: `http://127.0.0.1:${fixture.port}/`,
        decompress: false
      });
      const sut = buildSut();

      // act
      const results = await Promise.all([
        sut.execute(request),
        fixture.received()
      ]);
      fixture.close();

      // assert
      const headers = results[1].toLowerCase();
      expect(headers).toContain('accept-encoding: identity');
    });

    it('should not duplicate Accept-Encoding when caller already supplies one and decompress is false', async () => {
      // arrange
      const fixture = await startServer();
      const { request } = createRequest({
        url: `http://127.0.0.1:${fixture.port}/`,
        decompress: false,
        headers: { 'accept-encoding': 'gzip, deflate' }
      });
      const sut = buildSut();

      // act
      const results = await Promise.all([
        sut.execute(request),
        fixture.received()
      ]);
      fixture.close();

      // assert
      const acceptEncodingHeaders = results[1]
        .split('\r\n')
        .filter((line) => line.toLowerCase().startsWith('accept-encoding:'));
      expect(acceptEncodingHeaders).toHaveLength(1);
      expect(acceptEncodingHeaders[0].toLowerCase()).toBe(
        'accept-encoding: gzip, deflate'
      );
    });

    it('should not send Accept-Encoding: identity when decompress is true', async () => {
      // arrange
      const fixture = await startServer();
      const { request } = createRequest({
        url: `http://127.0.0.1:${fixture.port}/`,
        decompress: true
      });
      const sut = buildSut();

      // act
      const results = await Promise.all([
        sut.execute(request),
        fixture.received()
      ]);
      fixture.close();

      // assert
      const identityHeaders = results[1]
        .split('\r\n')
        .filter((line) => line.toLowerCase() === 'accept-encoding: identity');
      expect(identityHeaders).toHaveLength(0);
    });

    it('should include ttfb in a successful response', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.ttfb).toBeGreaterThanOrEqual(0);
    });

    it('should include ttfb even on HTTP error responses', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(500);
        res.end('error body');
      });
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.statusCode).toBe(500);
      expect(response.ttfb).toBeDefined();
    });

    it('should not include ttfb when the request fails before reaching the target', async () => {
      // arrange
      const { request } = createRequest({ url: 'http://127.0.0.1:1/' });
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.errorCode).toBeDefined();
      expect(response.ttfb).toBeUndefined();
    });

    it('should reuse the TCP connection across requests when reuseConnection is true', async () => {
      // arrange
      // Connection reuse is provided by a per-host Multi handle whose
      // connection pool survives individual Curl handle teardown.
      // When reuseConnection is true we set TCP_KEEPALIVE and TCP_KEEPIDLE and
      // wire each Curl handle to a dedicated per-host Multi so that
      // MAX_HOST_CONNECTIONS applies per origin.
      let connectionCount = 0;
      const { server, baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
      });
      server.on('connection', () => {
        connectionCount++;
      });
      const reuseExecutor = new HttpRequestExecutor(
        instance(virtualScriptsMock),
        { reuseConnection: true },
        certificatesCacheMock,
        instance(certificatesResolverMock)
      );
      const { request: req1 } = createRequest({ url: `${baseUrl}/a` });
      const { request: req2 } = createRequest({ url: `${baseUrl}/b` });
      const { request: req3 } = createRequest({ url: `${baseUrl}/c` });

      // act
      await reuseExecutor.execute(req1);
      await reuseExecutor.execute(req2);
      await reuseExecutor.execute(req3);

      // assert
      // All three requests should travel over the same TCP connection.
      expect(connectionCount).toBe(1);
    });

    it('should open a new TCP connection for each request when reuseConnection is false', async () => {
      // arrange
      // When reuseConnection is false we set FRESH_CONNECT and FORBID_REUSE
      // to match the node default-off keepAlive behaviour, ensuring each
      // request opens a fresh TCP connection.
      let connectionCount = 0;
      const { server, baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      server.on('connection', () => {
        connectionCount++;
      });
      const { request: req1 } = createRequest({ url: `${baseUrl}/a` });
      const { request: req2 } = createRequest({ url: `${baseUrl}/b` });
      const sut = buildSut();

      // act
      await sut.execute(req1);
      await sut.execute(req2);

      // assert
      expect(connectionCount).toBe(2);
    });

    it('should send Connection: close header on the wire when reuseConnection is false', async () => {
      // arrange
      // FRESH_CONNECT / FORBID_REUSE are client-side only; the server still needs
      // to be told to close the connection.  The executor must inject the header
      // when the caller has not supplied one.
      const fixture = await startServer();
      const { request } = createRequest({
        url: `http://127.0.0.1:${fixture.port}/`
      });
      const sut = buildSut();

      // act
      const results = await Promise.all([
        sut.execute(request),
        fixture.received()
      ]);
      fixture.close();

      // assert
      const headers = results[1].toLowerCase();
      expect(headers).toContain('connection: close');
    });

    it('should not duplicate Connection header when the caller already supplies one', async () => {
      // arrange
      // If the caller provides their own Connection header (e.g. "keep-alive")
      // the executor must NOT append an additional Connection: close line.
      const fixture = await startServer();
      const { request } = createRequest({
        url: `http://127.0.0.1:${fixture.port}/`,
        headers: { Connection: 'keep-alive' }
      });
      const sut = buildSut();

      // act
      const results = await Promise.all([
        sut.execute(request),
        fixture.received()
      ]);
      fixture.close();

      // assert
      const connectionHeaders = results[1]
        .split('\r\n')
        .filter((line) => line.toLowerCase().startsWith('connection:'));
      expect(connectionHeaders).toHaveLength(1);
      expect(connectionHeaders[0].toLowerCase()).toBe('connection: keep-alive');
    });

    it('should reuse the same Multi handle for multiple requests to the same host', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200);
        res.end('ok');
      });
      const sut = buildSut({ reuseConnection: true });
      const { request: req1 } = createRequest({ url: `${baseUrl}/a` });
      const { request: req2 } = createRequest({ url: `${baseUrl}/b` });
      const { request: req3 } = createRequest({ url: `${baseUrl}/c` });

      // act
      await sut.execute(req1);
      await sut.execute(req2);
      await sut.execute(req3);

      // assert
      expect(MultiSpy).toHaveBeenCalledTimes(1);
    });

    it('should call onResponse script hook and modify response', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('original');
      });
      const { request } = createRequest({ url: baseUrl });
      const { hostname: virtualScriptId } = new URL(baseUrl);
      const virtualScript = new VirtualScript(
        virtualScriptId,
        VirtualScriptType.LOCAL,
        'module.exports.handle = (req) => req; module.exports.onResponse = (res) => ({ ...res, body: "intercepted" });'
      );
      virtualScript.compile();
      when(virtualScriptsMock.find(virtualScriptId)).thenReturn(
        undefined,
        virtualScript
      );
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual('intercepted');
    });

    it('should pass through response if onResponse returns void', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('original');
      });
      const { request } = createRequest({ url: baseUrl });
      const { hostname: virtualScriptId } = new URL(baseUrl);
      const virtualScript = new VirtualScript(
        virtualScriptId,
        VirtualScriptType.LOCAL,
        'module.exports.handle = (req) => req; module.exports.onResponse = () => {};'
      );
      virtualScript.compile();
      when(virtualScriptsMock.find(virtualScriptId)).thenReturn(
        undefined,
        virtualScript
      );
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual('original');
    });

    it('should pass through response if onResponse is not exported', async () => {
      // arrange
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('original');
      });
      const { request } = createRequest({ url: baseUrl });
      const { hostname: virtualScriptId } = new URL(baseUrl);
      const virtualScript = new VirtualScript(
        virtualScriptId,
        VirtualScriptType.LOCAL,
        'module.exports.handle = (req) => req;'
      );
      virtualScript.compile();
      when(virtualScriptsMock.find(virtualScriptId)).thenReturn(
        undefined,
        virtualScript
      );
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.body).toEqual('original');
    });

    /** Builds a deterministic 0x00..0xFF repeating pattern. */
    const binaryPattern = (size: number): Buffer => {
      const pattern = Buffer.alloc(size);

      for (let i = 0; i < size; i++) {
        pattern[i] = i % 256;
      }

      return pattern;
    };

    /** Offset of the first differing byte, or -1 when both buffers match. */
    const firstMismatch = (actual: Buffer, expected: Buffer): number => {
      const length = Math.min(actual.length, expected.length);

      for (let i = 0; i < length; i++) {
        if (actual[i] !== expected[i]) {
          return i;
        }
      }

      return actual.length === expected.length ? -1 : length;
    };

    const startBodyCapturingServer = async () => {
      let resolveRequest!: (value: {
        method: string;
        headers: http.IncomingHttpHeaders;
        body: Buffer;
      }) => void;
      const received = new Promise<{
        method: string;
        headers: http.IncomingHttpHeaders;
        body: Buffer;
      }>((resolve) => {
        resolveRequest = resolve;
      });

      const { baseUrl } = await startServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => chunks.push(chunk));
        req.on('end', () => {
          resolveRequest({
            method: req.method,
            headers: req.headers,
            body: Buffer.concat(chunks)
          });
          res.writeHead(200);
          res.end('ok');
        });
      });

      return { baseUrl, received };
    };

    it('should forward a base64 encoded binary body byte-exactly', async () => {
      // arrange
      const expected = binaryPattern(4096);
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        body: expected.toString('base64'),
        encoding: 'base64'
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { body } = await received;

      // assert
      expect(firstMismatch(body, expected)).toBe(-1);
      expect(body.length).toBe(expected.length);
    });

    it('should forward a binary body larger than the libcurl upload buffer byte-exactly', async () => {
      // arrange
      // 256 KiB spans several read callback invocations.
      const expected = binaryPattern(256 * 1024);
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        body: expected.toString('base64'),
        encoding: 'base64'
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { body } = await received;

      // assert
      expect(firstMismatch(body, expected)).toBe(-1);
      expect(body.length).toBe(expected.length);
    });

    it('should forward multi-byte UTF-8 characters in an unencoded body byte-exactly', async () => {
      // arrange
      const text = 'héllo wörld — 日本語 🎉';
      const expected = Buffer.from(text, 'utf8');
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        body: text
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { body } = await received;

      // assert
      expect(body.toString('utf8')).toEqual(text);
      expect(firstMismatch(body, expected)).toBe(-1);
    });

    it('should declare the decoded byte length as Content-Length', async () => {
      // arrange
      const expected = binaryPattern(4096);
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        body: expected.toString('base64'),
        encoding: 'base64'
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { headers } = await received;

      // assert
      expect(headers['content-length']).toEqual(`${expected.length}`);
      expect(headers['transfer-encoding']).toBeUndefined();
    });

    it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'GET'])(
      'should preserve the %s method while sending a body',
      async (method: string) => {
        // arrange
        const expected = binaryPattern(1024);
        const { baseUrl, received } = await startBodyCapturingServer();
        const { request } = createRequest({
          url: `${baseUrl}/`,
          method,
          body: expected.toString('base64'),
          encoding: 'base64'
        });
        const sut = buildSut();

        // act
        await sut.execute(request);
        const { method: receivedMethod, body } = await received;

        // assert
        expect(receivedMethod).toEqual(method);
        expect(firstMismatch(body, expected)).toBe(-1);
      }
    );

    /**
     * Registers a script for the host of the given URL. The request is built
     * without the ts-mockito spy used by `createRequest`, because the spy
     * replaces the private method field and breaks `Request.toJSON()`, which
     * the script transformation relies on.
     */
    const withVirtualScript = (
      url: string,
      handle: (options: RequestOptions) => RequestOptions
    ) => {
      const { hostname: virtualScriptId } = new URL(url);
      const virtualScript = new VirtualScript(
        virtualScriptId,
        VirtualScriptType.LOCAL,
        'console.log("test code");'
      );
      const spiedVirtualScript = spy(virtualScript);
      when(spiedVirtualScript.exec(anyString(), anything())).thenCall(
        (_entrypoint: string, options: RequestOptions) =>
          Promise.resolve(handle(options))
      );
      when(virtualScriptsMock.find(virtualScriptId)).thenReturn(
        virtualScript,
        undefined
      );
    };

    it('should keep the body byte-exact when a script leaves it untouched', async () => {
      // arrange
      const expected = binaryPattern(4096);
      const { baseUrl, received } = await startBodyCapturingServer();
      const request = new Request({
        protocol: Protocol.HTTP,
        url: `${baseUrl}/`,
        method: 'POST',
        body: expected.toString('base64'),
        encoding: 'base64'
      });
      withVirtualScript(request.url, (options) => options);
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { body } = await received;

      // assert
      expect(firstMismatch(body, expected)).toBe(-1);
      expect(body.length).toBe(expected.length);
    });

    it('should send the rewritten body when a script modifies it', async () => {
      // arrange
      const { baseUrl, received } = await startBodyCapturingServer();
      const request = new Request({
        protocol: Protocol.HTTP,
        url: `${baseUrl}/`,
        method: 'POST',
        body: binaryPattern(4096).toString('base64'),
        encoding: 'base64'
      });
      withVirtualScript(request.url, (options) => ({
        ...options,
        body: 'rewritten by the script'
      }));
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { body } = await received;

      // assert
      expect(body.toString()).toEqual('rewritten by the script');
    });

    it('should honour an encoding a script adds without touching the body', async () => {
      // arrange
      // `Request.toJSON()` does not carry `encoding`, so a script that sets one
      // is asking for its own body to be decoded. Restoring the original body
      // and encoding here would silently drop that instruction.
      const expected = binaryPattern(1024);
      const { baseUrl, received } = await startBodyCapturingServer();
      const request = new Request({
        protocol: Protocol.HTTP,
        url: `${baseUrl}/`,
        method: 'POST',
        body: expected.toString('base64')
      });
      withVirtualScript(request.url, (options) => ({
        ...options,
        encoding: 'base64'
      }));
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { body } = await received;

      // assert
      expect(firstMismatch(body, expected)).toBe(-1);
    });

    it('should honour a per-request timeout after a script transform', async () => {
      // arrange
      // The executor is built without a timeout, so the only one in play is the
      // per-request value. If the script transform drops it, nothing bounds the
      // request and the slow response arrives successfully.
      const { baseUrl } = await startServer((_req, res) => {
        setTimeout(() => res.end('too late'), 1000);
      });
      const request = new Request({
        protocol: Protocol.HTTP,
        url: `${baseUrl}/`,
        method: 'GET',
        timeout: 50
      });
      withVirtualScript(request.url, (options) => options);
      const sut = buildSut();

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.statusCode).toBeUndefined();
      expect(response.errorCode).toBeDefined();
    });

    it('should hand the script every request option except the body encoding', async () => {
      // arrange
      // The body the script receives is already decoded, so reporting the
      // original `encoding` alongside it would describe it incorrectly.
      const { baseUrl, received } = await startBodyCapturingServer();
      const request = new Request({
        protocol: Protocol.HTTP,
        url: `${baseUrl}/`,
        method: 'POST',
        body: binaryPattern(64).toString('base64'),
        encoding: 'base64',
        timeout: 5000,
        maxContentSize: 7,
        decompress: false
      });
      let seen: RequestOptions | undefined;
      withVirtualScript(request.url, (options) => {
        seen = options;

        return options;
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      await received;

      // assert
      expect(seen).toMatchObject({
        timeout: 5000,
        maxContentSize: 7,
        decompress: false
      });
      expect(seen.encoding).toBeUndefined();
    });

    it('should keep the body byte-exact when a script re-declares the original encoding', async () => {
      // arrange
      // The script echoes back the encoding the request already had, so it has
      // not asked for anything new. Treating that as a script-supplied encoding
      // would base64-decode the lossy decoded view instead of the real body.
      const expected = binaryPattern(4096);
      const { baseUrl, received } = await startBodyCapturingServer();
      const request = new Request({
        protocol: Protocol.HTTP,
        url: `${baseUrl}/`,
        method: 'POST',
        body: expected.toString('base64'),
        encoding: 'base64'
      });
      withVirtualScript(request.url, (options) => ({
        ...options,
        encoding: 'base64'
      }));
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { body } = await received;

      // assert
      expect(firstMismatch(body, expected)).toBe(-1);
      expect(body.length).toBe(expected.length);
    });

    it('should keep the body byte-exact when a script only changes headers', async () => {
      // arrange
      const expected = binaryPattern(4096);
      const { baseUrl, received } = await startBodyCapturingServer();
      const request = new Request({
        protocol: Protocol.HTTP,
        url: `${baseUrl}/`,
        method: 'POST',
        body: expected.toString('base64'),
        encoding: 'base64'
      });
      withVirtualScript(request.url, (options) => ({
        ...options,
        headers: { ...options.headers, 'x-script': 'applied' }
      }));
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { headers, body } = await received;

      // assert
      expect(headers['x-script']).toEqual('applied');
      expect(firstMismatch(body, expected)).toBe(-1);
    });

    it('should not send an Expect: 100-continue header', async () => {
      // arrange
      // A 100-continue handshake changes what the target observes and stalls
      // the body by up to a second when the target does not answer it.
      const expected = binaryPattern(8192);
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        body: expected.toString('base64'),
        encoding: 'base64'
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { headers } = await received;

      // assert
      expect(headers.expect).toBeUndefined();
    });

    it('should not add a default Content-Type to a body sent without one', async () => {
      // arrange
      // libcurl adds "Content-Type: application/x-www-form-urlencoded" on its
      // own for a POSTFIELDS body but not for an upload. Leaving it off matches
      // the pre-v13.12.0 behaviour, which wrote the body to a raw node socket.
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        body: 'payload'
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { headers } = await received;

      // assert
      expect(headers['content-type']).toBeUndefined();
    });

    it('should forward a caller-supplied Content-Type verbatim', async () => {
      // arrange
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: binaryPattern(1024).toString('base64'),
        encoding: 'base64'
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { headers } = await received;

      // assert
      expect(headers['content-type']).toEqual('application/octet-stream');
    });

    it('should not duplicate or override a caller-supplied Content-Length', async () => {
      // arrange
      // Security payloads deliberately declare a Content-Length that does not
      // match the body, so the upload path must not append its own value.
      const fixture = await startServer();
      const { request } = createRequest({
        url: `${fixture.baseUrl}/`,
        method: 'POST',
        headers: { 'Content-Length': '5' },
        body: '0123456789'
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const raw = await fixture.received();
      fixture.close();

      // assert
      expect(
        raw.split('\r\n').filter((line) => /^content-length:/i.test(line))
      ).toEqual(['Content-Length: 5']);
    });

    it('should send neither a body nor Content-Length when the request has no body', async () => {
      // arrange
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({ url: `${baseUrl}/`, method: 'POST' });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { method, headers, body } = await received;

      // assert
      expect(method).toEqual('POST');
      expect(body.length).toBe(0);
      expect(headers['content-length']).toBeUndefined();
      expect(headers['transfer-encoding']).toBeUndefined();
    });

    it('should send an empty body when the encoded body decodes to zero bytes', async () => {
      // arrange
      // A pad-only base64 string decodes to no bytes at all.
      const { baseUrl, received } = await startBodyCapturingServer();
      const { request } = createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        body: '=',
        encoding: 'base64'
      });
      const sut = buildSut();

      // act
      await sut.execute(request);
      const { headers, body } = await received;

      // assert
      expect(body.length).toBe(0);
      expect(headers['content-length']).toEqual('0');
    });

    // CURLOPT_SEEKFUNCTION contract, see the libcurl documentation.
    const SEEK_SET = 0;
    const SEEK_CUR = 1;
    const SEEK_END = 2;
    const CURL_SEEKFUNC_OK = 0;
    const CURL_SEEKFUNC_FAIL = 1;

    type ReadCallback = (target: Buffer, size: number, nmemb: number) => number;
    type SeekCallback = (position: number, origin: number) => number;

    /**
     * Runs a request and returns the options the executor handed to libcurl,
     * so the read and seek callbacks can be exercised the way libcurl drives
     * them when it has to send the same request twice.
     */
    const executeCapturingCurlOptions = async (
      request: Request
    ): Promise<Map<string, unknown>> => {
      const setOptSpy = jest.spyOn(Curl.prototype, 'setOpt');

      try {
        await buildSut().execute(request);

        const captured = new Map<string, unknown>();

        for (const call of setOptSpy.mock.calls) {
          captured.set(String(call[0]), call[1]);
        }

        return captured;
      } finally {
        setOptSpy.mockRestore();
      }
    };

    /** Drains the read callback in fixed-size chunks, as libcurl does. */
    const drain = (read: ReadCallback, chunkSize: number): Buffer => {
      const chunks: Buffer[] = [];
      let written: number;
      let guard = 0;

      do {
        const target = Buffer.alloc(chunkSize);
        written = read(target, 1, chunkSize);
        chunks.push(target.subarray(0, Math.max(written, 0)));
      } while (written > 0 && ++guard < 1024);

      return Buffer.concat(chunks);
    };

    const uploadRequest = (baseUrl: string, body: Buffer) =>
      createRequest({
        url: `${baseUrl}/`,
        method: 'POST',
        body: body.toString('base64'),
        encoding: 'base64'
      }).request;

    it('should register a seek callback alongside the read callback', async () => {
      // arrange
      const { baseUrl } = await startBodyCapturingServer();
      const request = uploadRequest(baseUrl, binaryPattern(1024));

      // act
      const options = await executeCapturingCurlOptions(request);

      // assert
      expect(options.get('UPLOAD')).toBe(true);
      expect(options.get('INFILESIZE_LARGE')).toBe(1024);
      expect(typeof options.get('READFUNCTION')).toBe('function');
      // Without a seek callback libcurl reports the body as non-seekable and
      // cannot replay it, which breaks authentication negotiation.
      expect(typeof options.get('SEEKFUNCTION')).toBe('function');
    });

    it('should replay the body byte-for-byte after seeking back to the start', async () => {
      // arrange
      const expected = binaryPattern(4096);
      const { baseUrl } = await startBodyCapturingServer();
      const options = await executeCapturingCurlOptions(
        uploadRequest(baseUrl, expected)
      );
      const read = options.get('READFUNCTION') as ReadCallback;
      const seek = options.get('SEEKFUNCTION') as SeekCallback;

      // act
      // The body is fully consumed at this point, which is the state libcurl
      // is in when it has to send the request a second time.
      const atEof = read(Buffer.alloc(64), 1, 64);
      const seekResult = seek(0, SEEK_SET);
      const replayed = drain(read, 512);

      // assert
      expect(atEof).toBe(0);
      expect(seekResult).toBe(CURL_SEEKFUNC_OK);
      expect(firstMismatch(replayed, expected)).toBe(-1);
    });

    it('should resolve seek positions against the requested origin', async () => {
      // arrange
      const expected = binaryPattern(1024);
      const { baseUrl } = await startBodyCapturingServer();
      const options = await executeCapturingCurlOptions(
        uploadRequest(baseUrl, expected)
      );
      const read = options.get('READFUNCTION') as ReadCallback;
      const seek = options.get('SEEKFUNCTION') as SeekCallback;
      const readNext = (length: number): Buffer => {
        const target = Buffer.alloc(length);
        read(target, 1, length);

        return target;
      };

      // act
      const fromSet = seek(8, SEEK_SET);
      const afterSet = readNext(8);
      const fromCur = seek(4, SEEK_CUR);
      const afterCur = readNext(4);
      const fromEnd = seek(-16, SEEK_END);
      const afterEnd = drain(read, 64);

      // assert
      expect(fromSet).toBe(CURL_SEEKFUNC_OK);
      expect(afterSet).toEqual(expected.subarray(8, 16));
      expect(fromCur).toBe(CURL_SEEKFUNC_OK);
      expect(afterCur).toEqual(expected.subarray(20, 24));
      expect(fromEnd).toBe(CURL_SEEKFUNC_OK);
      expect(afterEnd).toEqual(expected.subarray(expected.length - 16));
    });

    it('should reject seek positions outside the body', async () => {
      // arrange
      const expected = binaryPattern(1024);
      const { baseUrl } = await startBodyCapturingServer();
      const options = await executeCapturingCurlOptions(
        uploadRequest(baseUrl, expected)
      );
      const seek = options.get('SEEKFUNCTION') as SeekCallback;

      // act
      const beforeStart = seek(-1, SEEK_SET);
      const pastEnd = seek(expected.length + 1, SEEK_SET);
      const withinBody = seek(0, SEEK_SET);

      // assert
      expect(beforeStart).toBe(CURL_SEEKFUNC_FAIL);
      expect(pastEnd).toBe(CURL_SEEKFUNC_FAIL);
      expect(withinBody).toBe(CURL_SEEKFUNC_OK);
    });

    it('should never write past the buffer window libcurl asked for', async () => {
      // arrange
      const expected = binaryPattern(4096);
      const { baseUrl } = await startBodyCapturingServer();
      const options = await executeCapturingCurlOptions(
        uploadRequest(baseUrl, expected)
      );
      const read = options.get('READFUNCTION') as ReadCallback;
      const seek = options.get('SEEKFUNCTION') as SeekCallback;
      const target = Buffer.alloc(expected.length);

      // act
      seek(0, SEEK_SET);
      const written = read(target, 1, 128);

      // assert
      expect(written).toBe(128);
      expect(target.subarray(0, 128)).toEqual(expected.subarray(0, 128));
      // Bytes 128.. of the pattern are non-zero, so an overrun would show up.
      expect(target.subarray(128).every((byte) => byte === 0)).toBe(true);
    });

    it('should handle kerberos-enabled requests gracefully', async () => {
      // When kerberos is enabled, the executor sets HTTPAUTH=Negotiate and
      // activates connection reuse (shared Multi) for SPNEGO handshake.
      // If GSSAPI is unavailable, curl returns an error response (not a throw).
      const { baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
      });
      const sut = buildSut({
        kerberos: { enabled: true }
      });
      const { request } = createRequest({ url: `${baseUrl}/a` });

      // Must not throw — returns either 200 (if GSSAPI works) or error response
      const response = await sut.execute(request);

      expect(response).toBeDefined();
      expect(response.protocol).toBe(Protocol.HTTP);
    });

    it('should not apply kerberos when kerberos is not enabled', async () => {
      // arrange
      let connectionCount = 0;
      const { server, baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
      });
      server.on('connection', () => {
        connectionCount++;
      });
      const sut = buildSut({});
      const { request: req1 } = createRequest({ url: `${baseUrl}/a` });
      const { request: req2 } = createRequest({ url: `${baseUrl}/b` });

      // act
      await sut.execute(req1);
      await sut.execute(req2);

      // assert — no connection reuse without kerberos or reuseConnection
      expect(connectionCount).toBe(2);
    });

    it('should only apply kerberos to matching domains when kerberos-domains is specified', async () => {
      // arrange
      let connectionCount = 0;
      const { server, baseUrl } = await startServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
      });
      server.on('connection', () => {
        connectionCount++;
      });

      // kerberos only for *.example.com — 127.0.0.1 won't match
      const sut = buildSut({
        kerberos: {
          enabled: true,
          domains: ['*.example.com']
        }
      });

      // Requests to 127.0.0.1 do NOT match *.example.com,
      // so kerberos won't apply and connections won't be reused
      const { request: req1 } = createRequest({ url: `${baseUrl}/a` });
      const { request: req2 } = createRequest({ url: `${baseUrl}/b` });

      // act
      await sut.execute(req1);
      await sut.execute(req2);

      // assert — no kerberos applied, so FRESH_CONNECT used
      expect(connectionCount).toBe(2);
    });

    it('should deliver serialized requests without waiting on libcurl timers', async () => {
      // arrange
      const { baseUrl } = await startServer((req, res) => {
        req.resume();
        req.on('end', () => res.end('ok'));
      });
      const sut = buildSut({ timeout: 30000 });
      const measureOnce = async (): Promise<number> => {
        const startedAt = process.hrtime.bigint();

        await sut.execute(
          new Request({ url: baseUrl, method: 'GET', protocol: Protocol.HTTP })
        );

        return Number(process.hrtime.bigint() - startedAt) / 1e6;
      };

      // the first requests pay for JIT and the initial native setup
      for (let i = 0; i < WARMUP_REQUESTS; i++) {
        await measureOnce();
      }

      // act
      const latencies: number[] = [];
      for (let i = 0; i < MEASURED_REQUESTS; i++) {
        latencies.push(await measureOnce());
      }

      const mean = latencies.reduce((a, b) => a + b, 0) / latencies.length;

      // assert
      // Assert via objectContaining so Jest prints the whole received object on
      // failure: the runtime, the mean, the max and every sample. That is enough
      // to tell a real regression from a noisy runner without rerunning.
      expect({
        node: process.version,
        meanMs: Math.round(mean),
        maxMs: Math.round(Math.max(...latencies)),
        budgetMs: MAX_MEAN_LATENCY_MS,
        samplesMs: latencies.map((value) => Math.round(value)),
        withinBudget: mean < MAX_MEAN_LATENCY_MS
      }).toEqual(expect.objectContaining({ withinBudget: true }));
    }, 60000);

    const pkcs11Cert: Pkcs11Cert = {
      hostname: '127.0.0.1',
      module: '/opt/vendor.so',
      pinEnv: 'CARD_PIN',
      cert: 'token',
      maxConcurrency: 1
    };

    const mockPkcs11Client = () => {
      const client = {
        warmUp: jest.fn(),
        match: jest.fn(() => [pkcs11Cert]),
        identity: jest.fn(() =>
          Promise.resolve<Pkcs11Identity>({
            // OpenSSL's built-in provider: setting SSLENGINE succeeds, and plain
            // HTTP never reaches the handshake that would use the key URI.
            provider: 'default',
            keyUri: 'pkcs11:token=card;id=%01;type=private?pin-value=1234',
            certUri: 'pkcs11:token=card;id=%01;type=cert',
            tls12Only: true
          })
        ),
        pool: jest.fn()
      };
      jest
        .mocked(Pkcs11Client)
        .mockImplementation(() => client as unknown as Pkcs11Client);

      return client;
    };

    it('should start the PKCS#11 checks when the executor is created', () => {
      // arrange
      const client = mockPkcs11Client();

      // act
      buildSut({ pkcs11: { certs: [pkcs11Cert] } });

      // assert
      expect(client.warmUp).toHaveBeenCalledTimes(1);
    });

    it('should return the PKCS#11 error code without sending the request', async () => {
      // arrange
      const client = mockPkcs11Client();
      const handler = jest.fn((_req, res) => res.end('ok'));
      const { baseUrl } = await startServer(handler);
      client.identity.mockRejectedValue(
        new Pkcs11Error(Pkcs11ErrorCode.PIN_INCORRECT, 'PIN rejected')
      );
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({ pkcs11: { certs: [pkcs11Cert] } });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response).toMatchObject({
        errorCode: 'PKCS11_PIN_INCORRECT',
        message: 'PIN rejected'
      });
      expect(handler).not.toHaveBeenCalled();
      expect(client.pool).not.toHaveBeenCalled();
    });

    it('should try the matching certificates one after another', async () => {
      // arrange
      const client = mockPkcs11Client();
      const second = { ...pkcs11Cert, token: 'backup' };
      client.match.mockReturnValue([pkcs11Cert, second]);
      client.identity
        .mockRejectedValueOnce(
          new Pkcs11Error(Pkcs11ErrorCode.TOKEN_NOT_FOUND, 'no card', true)
        )
        .mockRejectedValueOnce(
          new Pkcs11Error(Pkcs11ErrorCode.KEY_NOT_FOUND, 'no key', true)
        );
      const { request } = createRequest({ url: 'https://127.0.0.1:1/' });
      const sut = buildSut({ pkcs11: { certs: [pkcs11Cert, second] } });

      // act
      const response = await sut.execute(request);

      // assert
      expect(client.identity.mock.calls).toEqual([[pkcs11Cert], [second]]);
      expect(response).toMatchObject({ errorCode: 'PKCS11_KEY_NOT_FOUND' });
      verify(certificatesResolverMock.resolve(anything(), anything())).never();
    });

    it('should send the requests on one long-lived keep-alive handle', async () => {
      // arrange
      const client = mockPkcs11Client();
      const connections: string[] = [];
      const { baseUrl } = await startServer((req, res) => {
        connections.push(req.headers.connection ?? '');
        res.end('ok');
      });
      const create = jest.fn(() => new Curl());
      const pool = new CurlHandlePool(1, create);
      client.pool.mockReturnValue(pool);
      const sut = buildSut({ pkcs11: { certs: [pkcs11Cert] } });

      // act
      const responses = [];
      for (let i = 0; i < 3; i++) {
        responses.push(
          await sut.execute(createRequest({ url: `${baseUrl}/` }).request)
        );
      }

      // assert
      try {
        expect(responses.map(({ statusCode }) => statusCode)).toEqual([
          200, 200, 200
        ]);
        expect(create).toHaveBeenCalledTimes(1);
        expect(connections).not.toContain('close');
      } finally {
        await new Promise((resolve) => setImmediate(resolve));
        pool.close();
      }
    });

    it('should serve a URL without a PKCS#11 certificate as before', async () => {
      // arrange
      const client = mockPkcs11Client();
      client.match.mockReturnValue([]);
      const { baseUrl } = await startServer((_req, res) => res.end('ok'));
      const { request } = createRequest({ url: `${baseUrl}/` });
      const sut = buildSut({ pkcs11: { certs: [pkcs11Cert] } });

      // act
      const response = await sut.execute(request);

      // assert
      expect(response.statusCode).toBe(200);
      expect(client.identity).not.toHaveBeenCalled();
    });
  });
});
