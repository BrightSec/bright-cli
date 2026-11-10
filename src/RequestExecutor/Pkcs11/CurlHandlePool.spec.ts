import { CurlHandlePool } from './CurlHandlePool';
import { Curl } from '@brightsec/node-libcurl';

describe('CurlHandlePool', () => {
  const handle = () => ({ close: jest.fn() } as unknown as Curl);

  describe('acquire', () => {
    it('should create handles up to the pool size', async () => {
      // arrange
      const create = jest.fn(handle);
      const pool = new CurlHandlePool(2, create);

      // act
      const first = await pool.acquire();
      const second = await pool.acquire();

      // assert
      expect(first).not.toBe(second);
      expect(create).toHaveBeenCalledTimes(2);
    });

    it('should reuse a released handle instead of creating one', async () => {
      // arrange
      const create = jest.fn(handle);
      const pool = new CurlHandlePool(2, create);
      const first = await pool.acquire();
      pool.release(first);

      // act
      const second = await pool.acquire();

      // assert
      expect(second).toBe(first);
      expect(create).toHaveBeenCalledTimes(1);
    });

    it('should wait for a handle when the pool is exhausted', async () => {
      // arrange
      const pool = new CurlHandlePool(1, handle);
      const first = await pool.acquire();
      const waiting = pool.acquire();

      // act
      pool.release(first);

      // assert
      await expect(waiting).resolves.toBe(first);
    });

    it('should time out when no handle frees up', async () => {
      // arrange
      jest.useFakeTimers();
      const pool = new CurlHandlePool(1, handle);
      const first = await pool.acquire();
      const waiting = pool.acquire(100);

      // act
      jest.advanceTimersByTime(100);

      // assert
      try {
        await expect(waiting).rejects.toMatchObject({ code: 'ETIMEDOUT' });
        pool.release(first);
        await expect(pool.acquire()).resolves.toBe(first);
      } finally {
        jest.useRealTimers();
      }
    });
  });

  describe('close', () => {
    it('should close the idle handles', async () => {
      // arrange
      const pool = new CurlHandlePool(1, handle);
      const curl = await pool.acquire();
      pool.release(curl);

      // act
      pool.close();

      // assert
      expect(curl.close).toHaveBeenCalledTimes(1);
    });
  });
});
