import { Curl } from '@brightsec/node-libcurl';

interface Waiter {
  resolve: (curl: Curl) => void;
  reject: (error: Error) => void;
  timer?: NodeJS.Timeout;
}

/**
 * A fixed set of long-lived easy handles. curl loads the OpenSSL provider per
 * handle and unloads it on close, which tears down the PKCS#11 module state
 * shared by the whole process; reusing handles keeps that state intact.
 */
export class CurlHandlePool {
  private readonly idle: Curl[] = [];
  private readonly waiters: Waiter[] = [];
  private created = 0;

  constructor(
    private readonly size: number,
    private readonly create: () => Curl = () => new Curl()
  ) {}

  /**
   * @throws Error with code ETIMEDOUT when no handle frees up within `timeoutMs`.
   */
  public acquire(timeoutMs?: number): Promise<Curl> {
    const curl = this.idle.pop();

    if (curl) {
      return Promise.resolve(curl);
    }

    if (this.created < this.size) {
      this.created++;

      return Promise.resolve(this.create());
    }

    return new Promise<Curl>((resolve, reject) => {
      const waiter: Waiter = { resolve, reject };

      if (timeoutMs !== undefined) {
        waiter.timer = setTimeout(() => {
          this.waiters.splice(this.waiters.indexOf(waiter), 1);
          reject(
            Object.assign(
              new Error(
                'Timed out waiting for a free PKCS#11 connection to the target.'
              ),
              { code: 'ETIMEDOUT' }
            )
          );
        }, Math.max(0, timeoutMs));
        waiter.timer.unref?.();
      }

      this.waiters.push(waiter);
    });
  }

  public release(curl: Curl): void {
    const waiter = this.waiters.shift();

    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(curl);

      return;
    }

    this.idle.push(curl);
  }

  public close(): void {
    this.idle.splice(0).forEach((curl: Curl) => curl.close());
  }
}
