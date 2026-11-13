import { Curl, Multi } from '@brightsec/node-libcurl';

export type CurlOptions = Record<string, string | number | boolean>;

export interface ClientJob {
  url: string;
  curlOptions: CurlOptions;
  requests?: number;
  // Reuse up to this many keep-alive connections; otherwise every request gets a fresh one.
  pool?: number;
  // Keep one easy handle per worker for the whole job instead of one per request.
  // curl loads the OpenSSL provider per handle, so this is what keeps a single
  // provider instance (and the PKCS#11 module state) alive across requests.
  persistentHandles?: boolean;
  // Workers for persistentHandles jobs without a pool.
  concurrency?: number;
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

type Outcome = { body?: string; error?: { curlCode: number; message: string } };

const createHandle = (job: ClientJob, multi?: Multi): Curl => {
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

  return curl;
};

const perform = (curl: Curl): Promise<Outcome> =>
  new Promise((resolve) => {
    const onEnd = (_status: number, body: string | Buffer) => {
      curl.off('error', onError);
      resolve({ body: body.toString() });
    };
    const onError = (err: Error, curlCode: number) => {
      curl.off('end', onEnd);
      resolve({ error: { curlCode, message: err.message } });
    };
    curl.once('end', onEnd);
    curl.once('error', onError);
    curl.perform();
  });

const performOnce = async (job: ClientJob, multi?: Multi): Promise<Outcome> => {
  const curl = createHandle(job, multi);
  const outcome = await perform(curl);
  setImmediate(() => curl.close());

  return outcome;
};

export const runJob = async (job: ClientJob): Promise<ClientResult> => {
  const total = job.requests ?? 1;
  const workers = job.pool ?? job.concurrency ?? 1;
  const multi = job.pool ? new Multi() : undefined;
  multi?.setOpt('MAX_HOST_CONNECTIONS', job.pool);

  const result: ClientResult = {
    succeeded: 0,
    failed: 0,
    bodies: [],
    errors: []
  };
  let started = 0;
  const handles: Curl[] = [];

  const worker = async (): Promise<void> => {
    const handle = job.persistentHandles ? createHandle(job, multi) : undefined;
    if (handle) {
      handles.push(handle);
    }

    while (started < total) {
      started++;
      const { body, error } = handle
        ? await perform(handle)
        : await performOnce(job, multi);
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
  // Closing a handle unloads its provider instance, which tears down the module
  // state that handshakes still running on other handles depend on.
  handles.forEach((handle: Curl) => handle.close());
  multi?.close();

  return result;
};

if (require.main === module) {
  const job: ClientJob = JSON.parse(process.argv[2]);
  void runJob(job).then((result) =>
    process.stdout.write(`\n${RESULT_MARKER}${JSON.stringify(result)}\n`)
  );
}
