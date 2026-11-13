import 'reflect-metadata';
import { HttpRequestExecutor } from '../../src/RequestExecutor/HttpRequestExecutor';
import { Pkcs11jsModule } from '../../src/RequestExecutor/Pkcs11/Pkcs11jsModule';
import { Pkcs11Options } from '../../src/RequestExecutor/Pkcs11Cert';
import { Protocol } from '../../src/RequestExecutor/Protocol';
import { Request } from '../../src/RequestExecutor/Request';
import { CertificatesCache } from '../../src/RequestExecutor/CertificatesCache';
import { CertificatesResolver } from '../../src/RequestExecutor/CertificatesResolver';
import { VirtualScripts } from '../../src/Scripts';

export interface RepeaterJob {
  urls: string[];
  pkcs11: Pkcs11Options;
  concurrency?: number;
  timeout?: number;
}

export interface RepeaterResult {
  responses: { statusCode?: number; errorCode?: string; body?: string }[];
  logins: number;
}

export const RESULT_MARKER = 'PKCS11_REPEATER_RESULT ';

/** Sends requests through the Repeater's HTTP executor with PKCS#11 certificates. */
export const runRepeater = async (
  job: RepeaterJob
): Promise<RepeaterResult> => {
  let logins = 0;
  const login = Pkcs11jsModule.prototype.login;
  Pkcs11jsModule.prototype.login = function (
    this: Pkcs11jsModule,
    ...args: Parameters<Pkcs11jsModule['login']>
  ): void {
    logins++;

    return login.apply(this, args);
  };

  const executor = new HttpRequestExecutor(
    { find: (): undefined => undefined } as unknown as VirtualScripts,
    { pkcs11: job.pkcs11, timeout: job.timeout ?? 10_000 },
    {} as CertificatesCache,
    { resolve: (): [] => [] } as unknown as CertificatesResolver
  );
  await executor.prepare();

  const responses: RepeaterResult['responses'] = [];
  const queue = [...job.urls];
  const worker = async (): Promise<void> => {
    for (let url = queue.shift(); url; url = queue.shift()) {
      const { statusCode, errorCode, body } = await executor.execute(
        new Request({ url, method: 'GET', protocol: Protocol.HTTP })
      );
      responses.push({ statusCode, errorCode, body });
    }
  };

  await Promise.all(Array.from({ length: job.concurrency ?? 1 }, worker));

  return { responses, logins };
};

if (require.main === module) {
  const job: RepeaterJob = JSON.parse(process.argv[2]);
  void runRepeater(job).then((result) => {
    process.stdout.write(`\n${RESULT_MARKER}${JSON.stringify(result)}\n`);
    // The pooled easy handles are never closed, so they keep the loop alive.
    process.exit(0);
  });
}
