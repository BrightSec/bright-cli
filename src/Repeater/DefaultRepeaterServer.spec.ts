import 'reflect-metadata';
import {
  DefaultRepeaterServer,
  DefaultRepeaterServerOptions
} from './DefaultRepeaterServer';
import { RepeaterErrorCodes, RepeaterServerEvents } from './RepeaterServer';
import { ProxyFactory } from '../Utils';
import { instance, mock, reset } from 'ts-mockito';
import io from 'socket.io-client';
import { EventEmitter } from 'node:events';

jest.mock('socket.io-client', () => jest.fn());

// Model Sentry's per-scope fork. `withScope` runs its callback with a FRESH scope
// (as the real async-context strategy does for concurrent forwards);
// `captureException` snapshots the active scope's tags so a test can assert which
// trace id an error was tagged with.
const capturedTags: Record<string, unknown>[] = [];
jest.mock('@sentry/node', () => {
  let activeTags: Record<string, unknown> = {};

  return {
    captureException: jest.fn(() => {
      capturedTags.push({ ...activeTags });
    }),
    captureMessage: jest.fn(),
    withScope: (
      cb: (scope: { setTag: (k: string, v: unknown) => void }) => unknown
    ) => {
      const previous = activeTags;
      const scopeTags: Record<string, unknown> = {};
      activeTags = scopeTags;
      const scope = {
        setTag: (k: string, v: unknown) => {
          scopeTags[k] = v;
        }
      };

      const restore = () => {
        activeTags = previous;
      };

      try {
        const result = cb(scope);
        if (result instanceof Promise) {
          return result.finally(restore);
        }
        restore();

        return result;
      } catch (e) {
        restore();
        throw e;
      }
    }
  };
});

class FakeSocket extends EventEmitter {
  public readonly io = new EventEmitter();
  public readonly connect = jest.fn();
  public readonly disconnect = jest.fn();
}

describe('DefaultRepeaterServer', () => {
  const options: DefaultRepeaterServerOptions = {
    uri: 'http://localhost:8080',
    token: 'dummy-token'
  };
  const proxyFactoryMock = mock<ProxyFactory>();
  const lookupMock = io as unknown as jest.MockedFunction<() => FakeSocket>;

  let socket!: FakeSocket;
  let server!: DefaultRepeaterServer;

  const connectionError = (code?: RepeaterErrorCodes) => {
    const err = new Error('Connection refused.');

    if (code) {
      Object.assign(err, { data: { code, message: err.message } });
    }

    return err;
  };

  const connect = async () => {
    const connecting = server.connect('example.com');
    socket.emit('connect');

    await connecting;
  };

  beforeEach(() => {
    jest.useFakeTimers();

    capturedTags.length = 0;
    socket = new FakeSocket();
    lookupMock.mockReturnValue(socket);

    server = new DefaultRepeaterServer(instance(proxyFactoryMock), options);
  });

  afterEach(() => {
    jest.useRealTimers();
    lookupMock.mockReset();
    reset<ProxyFactory>(proxyFactoryMock);
  });

  describe('connect', () => {
    it('should reconnect after a retryable connection error', async () => {
      // arrange
      await connect();

      // act
      socket.emit('connect_error', connectionError());

      // assert
      jest.advanceTimersByTime(999);
      expect(socket.connect).not.toHaveBeenCalled();

      jest.advanceTimersByTime(6_500);
      expect(socket.connect).toHaveBeenCalledTimes(1);
    });

    it('should keep a single pending reconnection while attempts keep failing', async () => {
      // arrange
      await connect();

      // act
      for (let i = 0; i < 5; i++) {
        socket.emit('connect_error', connectionError());
      }

      // assert
      expect(jest.getTimerCount()).toBe(1);

      jest.advanceTimersByTime(6_500);
      expect(socket.connect).toHaveBeenCalledTimes(1);
    });

    it.each([
      RepeaterErrorCodes.REPEATER_UNAUTHORIZED,
      RepeaterErrorCodes.REPEATER_NOT_PERMITTED
    ])(
      'should not reconnect after a terminal %s connection error',
      async (code: RepeaterErrorCodes) => {
        // arrange
        server.on(RepeaterServerEvents.ERROR, jest.fn());

        await connect();

        // act
        socket.emit('connect_error', connectionError(code));

        // assert
        expect(jest.getTimerCount()).toBe(0);

        jest.advanceTimersByTime(6_500);
        expect(socket.connect).not.toHaveBeenCalled();
      }
    );

    it('should surface a terminal connection error to the consumer', async () => {
      // arrange
      const handler = jest.fn();
      server.on(RepeaterServerEvents.ERROR, handler);

      await connect();

      // act
      socket.emit(
        'connect_error',
        connectionError(RepeaterErrorCodes.REPEATER_UNAUTHORIZED)
      );

      // assert
      expect(handler).toHaveBeenCalledWith(
        expect.objectContaining({
          code: RepeaterErrorCodes.REPEATER_UNAUTHORIZED,
          message: 'Connection refused.'
        })
      );
    });
  });

  describe('disconnect', () => {
    it('should not touch the socket when a pending reconnection fires after teardown', async () => {
      // arrange
      await connect();

      for (let i = 0; i < 5; i++) {
        socket.emit('connect_error', connectionError());
      }

      // act
      server.disconnect();

      // assert
      expect(() => jest.advanceTimersByTime(6_500)).not.toThrow();
      expect(socket.connect).not.toHaveBeenCalled();
    });

    it('should not schedule a reconnection when a connection error arrives during teardown', async () => {
      // arrange
      await connect();
      // A terminal error drives the consumer to tear the server down from
      // within the error handler, i.e. synchronously mid-dispatch.
      server.on(RepeaterServerEvents.ERROR, () => server.disconnect());

      // act
      socket.emit(
        'connect_error',
        connectionError(RepeaterErrorCodes.REPEATER_UNAUTHORIZED)
      );

      // assert
      expect(jest.getTimerCount()).toBe(0);
      expect(() => jest.advanceTimersByTime(6_500)).not.toThrow();
      expect(socket.connect).not.toHaveBeenCalled();
    });

    it('should leave no pending timers behind', async () => {
      // arrange
      await connect();
      socket.emit('connect_error', connectionError());

      // act
      server.disconnect();

      // assert
      expect(jest.getTimerCount()).toBe(0);
      expect(socket.disconnect).toHaveBeenCalled();
    });
  });

  describe('deploy', () => {
    it('should time out rather than throw when the socket is torn down before the deploy is flushed', async () => {
      // arrange
      await connect();
      const deploying = server.deploy(
        { repeaterId: 'dummy-id' },
        { version: '0.0.0', scriptsLoaded: false, localScriptsLoaded: false }
      );

      // act
      server.disconnect();

      // assert
      expect(() => jest.runAllTicks()).not.toThrow();

      jest.advanceTimersByTime(60_000);
      await expect(deploying).rejects.toThrow('No response.');
    });
  });

  describe('wrapEventListener', () => {
    const emitRequest = (event: Record<string, unknown>) =>
      socket.emit(
        'request',
        event,
        // socket.io ack callback
        () => undefined
      );

    it('tags the per-request Sentry scope with trace_id when the request carries one', async () => {
      // arrange — a handler that throws so handleEventError captures inside scope
      server.on(RepeaterServerEvents.REQUEST, () => {
        throw new Error('boom');
      });
      await connect();

      // act
      emitRequest({
        protocol: 'http',
        url: 'http://target.test/',
        traceId: 'trace-abc12345'
      });
      await Promise.resolve();

      // assert
      expect(capturedTags).toHaveLength(1);
      expect(capturedTags[0]).toEqual({ trace_id: 'trace-abc12345' });
    });

    it('does not tag trace_id when the request carries none', async () => {
      // arrange
      server.on(RepeaterServerEvents.REQUEST, () => {
        throw new Error('boom');
      });
      await connect();

      // act
      emitRequest({ protocol: 'http', url: 'http://target.test/' });
      await Promise.resolve();

      // assert
      expect(capturedTags).toHaveLength(1);
      expect(capturedTags[0]).not.toHaveProperty('trace_id');
    });

    it('does not cross-contaminate trace_id tags across two requests', async () => {
      // arrange
      server.on(RepeaterServerEvents.REQUEST, () => {
        throw new Error('boom');
      });
      await connect();

      // act — two distinct forwards, each with its own trace id
      emitRequest({
        protocol: 'http',
        url: 'http://a.test/',
        traceId: 'trace-aaaa1111'
      });
      emitRequest({
        protocol: 'http',
        url: 'http://b.test/',
        traceId: 'trace-bbbb2222'
      });
      await Promise.resolve();

      // assert — each capture carries only its own request's trace id
      expect(capturedTags).toHaveLength(2);
      expect(capturedTags).toEqual([
        { trace_id: 'trace-aaaa1111' },
        { trace_id: 'trace-bbbb2222' }
      ]);
    });
  });
});
