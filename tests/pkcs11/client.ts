import { Curl, Multi } from '@brightsec/node-libcurl';

export type CurlOptions = Record<string, string | number | boolean>;

export interface ClientJob {
  url: string;
  curlOptions: CurlOptions;
  requests?: number;
  // Reuse up to this many keep-alive connections; otherwise every request gets a fresh one.
  pool?: number;
}

export interface ClientResult {
  succeeded: number;
  failed: number;
  bodies: string[];
  errors: { curlCode: number; message: string }[];
}

// PKCS#11 modules and providers print diagnostics to stdout, so the result is
// tagged to be found among them.
export const RESULT_MARKER = 'PKCS11_CLIENT_RESULT ';

const perform = (
  job: ClientJob,
  multi?: Multi
): Promise<{ body?: string; error?: { curlCode: number; message: string } }> =>
  new Promise((resolve) => {
    const curl = new Curl();
    curl.setOpt('URL', job.url);
    // The test target uses a self-signed server certificate; only the client side is under test.
    curl.setOpt('SSL_VERIFYPEER', false);
    curl.setOpt('SSL_VERIFYHOST', 0);
    curl.setOpt('TIMEOUT_MS', 10_000);

    for (const [name, value] of Object.entries(job.curlOptions)) {
      curl.setOpt(name as Parameters<Curl['setOpt']>[0], value as never);
    }

    if (multi) {
      curl.setOpt('TCP_KEEPALIVE', 1);
      curl.setMulti(multi);
    } else {
      curl.setOpt('FRESH_CONNECT', 1);
      curl.setOpt('FORBID_REUSE', 1);
    }

    curl.on('end', (_status: number, body: string | Buffer) => {
      setImmediate(() => curl.close());
      resolve({ body: body.toString() });
    });
    curl.on('error', (err: Error, curlCode: number) => {
      setImmediate(() => curl.close());
      resolve({ error: { curlCode, message: err.message } });
    });
    curl.perform();
  });

export const runJob = async (job: ClientJob): Promise<ClientResult> => {
  const total = job.requests ?? 1;
  const workers = job.pool ?? 1;
  const multi = job.pool ? new Multi() : undefined;
  multi?.setOpt('MAX_HOST_CONNECTIONS', job.pool);

  const result: ClientResult = {
    succeeded: 0,
    failed: 0,
    bodies: [],
    errors: []
  };
  let started = 0;

  const worker = async (): Promise<void> => {
    while (started < total) {
      started++;
      const { body, error } = await perform(job, multi);
      if (error) {
        result.failed++;
        result.errors.push(error);
      } else {
        result.succeeded++;
        result.bodies.push(body);
      }
    }
  };

  await Promise.all(Array.from({ length: workers }, worker));
  multi?.close();

  return result;
};

if (require.main === module) {
  const job: ClientJob = JSON.parse(process.argv[2]);
  void runJob(job).then((result) =>
    process.stdout.write(`\n${RESULT_MARKER}${JSON.stringify(result)}\n`)
  );
}
