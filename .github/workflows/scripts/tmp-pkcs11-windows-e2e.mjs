// TODO: temporary. Remove together with ../tmp-pkcs11-windows-e2e.yml.
//
// One case of the PKCS#11 end-to-end check: loads a client certificate into a
// SoftHSM2 token, starts the Repeater with it, has the Bright cloud send one
// request through the Repeater to the mTLS target, and checks the outcome.
//
// Usage: node tmp-pkcs11-windows-e2e.mjs <positive|negative> <client.p12>
//
// Environment: BRIGHT_HOSTNAME, BRIGHT_PROJECT_ID, BRIGHT_API_KEY,
// BRIGHT_REPEATER_ID, REPEATER_BIN, PKCS11_MODULE, PKCS11_WORK_DIR.
// softhsm2-util, pkcs11-tool and openssl must be on PATH.

import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const TARGET_HOST = 'ao-https-mtls-pkcs11.nlb.brokencrystals.nexploit.app';
const TARGET_URL = `https://${TARGET_HOST}/`;
const TOKEN_LABEL = 'bright-remote';
const P12_PASSWORD = '1234';
const PIN = '1234';
const SO_PIN = '5678';
const REPEATER_START_TIMEOUT_MS = 90_000;
const EXECUTE_TIMEOUT_MS = 240_000;

const fail = (message) => {
  process.stderr.write(`E2E FAILED: ${message}\n`);
  process.exit(1);
};

const env = (name, fallback) => {
  const value = process.env[name] ?? fallback;
  if (!value) {
    fail(`${name} is not set`);
  }

  return value;
};

const [testCase, p12Arg] = process.argv.slice(2);
if (!['positive', 'negative'].includes(testCase) || !p12Arg) {
  fail('usage: tmp-pkcs11-windows-e2e.mjs <positive|negative> <client.p12>');
}

const hostname = env('BRIGHT_HOSTNAME', 'app.brightsec.com');
const projectId = env('BRIGHT_PROJECT_ID');
const apiKey = env('BRIGHT_API_KEY');
const repeaterId = env('BRIGHT_REPEATER_ID');
const repeaterBin = resolve(env('REPEATER_BIN'));
const pkcs11Module = resolve(env('PKCS11_MODULE'));
// Forward slashes: the paths end up in JSON and in softhsm2.conf.
const slash = (path) => path.replace(/\\/g, '/');
const work = slash(resolve(env('PKCS11_WORK_DIR')));
const p12 = resolve(p12Arg);
const softhsmConf = `${work}/softhsm2.conf`;
const pinFile = `${work}/pin.txt`;

const toolEnv = {
  ...process.env,
  SOFTHSM2_CONF: softhsmConf,
  // Git Bash tools would otherwise rewrite "/CN=..." style arguments into paths.
  MSYS_NO_PATHCONV: '1'
};

const run = (command, args) =>
  execFileSync(command, args, { env: toolEnv, encoding: 'utf8' });

const loadCertificate = () => {
  rmSync(`${work}/tokens`, { recursive: true, force: true });
  mkdirSync(`${work}/tokens`, { recursive: true });
  writeFileSync(
    softhsmConf,
    `directories.tokendir = ${work}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n`
  );
  writeFileSync(pinFile, PIN);

  const keyPem = `${work}/key.pem`;
  const keyP8 = `${work}/key.p8`;
  const certPem = `${work}/cert.pem`;
  const certDer = `${work}/cert.der`;
  const pass = `pass:${P12_PASSWORD}`;

  try {
    run('openssl', ['pkcs12', '-in', p12, '-passin', pass, '-nocerts', '-nodes', '-out', keyPem]);
    run('openssl', ['pkcs8', '-topk8', '-nocrypt', '-in', keyPem, '-out', keyP8]);
    run('openssl', ['pkcs12', '-in', p12, '-passin', pass, '-nokeys', '-clcerts', '-out', certPem]);
    run('openssl', ['x509', '-in', certPem, '-outform', 'der', '-out', certDer]);
    process.stdout.write(
      run('openssl', ['x509', '-in', certPem, '-noout', '-subject', '-issuer'])
    );

    run('softhsm2-util', [
      '--init-token', '--free', '--label', TOKEN_LABEL, '--pin', PIN, '--so-pin', SO_PIN
    ]);
    run('softhsm2-util', [
      '--import', keyP8, '--token', TOKEN_LABEL, '--label', 'client', '--id', '01', '--pin', PIN
    ]);
    run('pkcs11-tool', [
      '--module', pkcs11Module, '--token-label', TOKEN_LABEL, '--login', '--pin', PIN,
      '--write-object', certDer, '--type', 'cert', '--label', 'client', '--id', '01'
    ]);
  } finally {
    // As on a real smart card, the private key exists only on the token.
    rmSync(keyPem, { force: true });
    rmSync(keyP8, { force: true });
  }

  process.stdout.write(
    run('pkcs11-tool', [
      '--module', pkcs11Module, '--token-label', TOKEN_LABEL, '--login', '--pin', PIN,
      '--list-objects', '--type', 'cert'
    ])
  );
};

// A customer machine has no OpenSSL on PATH: the bundle must load its
// pkcs11prov.dll and libcrypto from next to the executable.
const repeaterEnv = () => {
  const result = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!/^(path|softhsm2_conf|openssl_modules|openssl_conf|pkcs11_module_path|pkcs11_provider_module)$/i.test(key)) {
      result[key] = value;
    }
  }
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  result.SOFTHSM2_CONF = softhsmConf;
  result.PATH =
    process.platform === 'win32'
      ? `${systemRoot}\\System32;${systemRoot}`
      : process.env.PATH;

  return result;
};

const stripAnsi = (text) => text.replace(/\x1b\[[0-9;]*m/g, '');

const startRepeater = async () => {
  const args = [
    'repeater',
    '--hostname', hostname,
    '--token', apiKey,
    '--id', repeaterId,
    '--pkcs11-module', pkcs11Module,
    '--pkcs11-cert', JSON.stringify({ hostname: TARGET_HOST, token: TOKEN_LABEL, pinFile }),
    '--log-level', '4'
  ];
  const child = spawn(repeaterBin, args, { env: repeaterEnv() });
  const repeater = { child, log: '', exited: false };

  const onData = (chunk) => {
    const text = stripAnsi(chunk.toString());
    repeater.log += text;
    for (const line of text.split(/\r?\n/).filter(Boolean)) {
      process.stdout.write(`[repeater] ${line}\n`);
    }
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);

  const exited = new Promise((resolve) =>
    child.once('exit', (code) => {
      repeater.exited = true;
      resolve(code);
    })
  );
  child.once('error', (e) => fail(`cannot start the Repeater: ${e.message}`));
  repeater.exitedPromise = exited;

  const deadline = Date.now() + REPEATER_START_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (/The Repeater \(.+\) started/.test(repeater.log)) {
      return repeater;
    }
    if (repeater.exited) {
      return repeater;
    }
    await sleep(500);
  }

  await stopRepeater(repeater);
  fail('the Repeater did not connect to the Bright cloud in time');
};

const stopRepeater = async (repeater) => {
  if (!repeater.exited) {
    repeater.child.kill();
    await Promise.race([repeater.exitedPromise, sleep(10_000)]);
  }
};

// The previous case's (or run's) connection can still be registered for a
// moment after its process was killed, which rejects a new one with the same ID.
const startRepeaterWithRetry = async () => {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const repeater = await startRepeater();
    if (!repeater.exited) {
      return repeater;
    }
    process.stdout.write(`The Repeater exited before it started (attempt ${attempt})\n`);
    await sleep(15_000);
  }
  fail('the Repeater exited before it started, 3 times');
};

const execute = async () => {
  const url = `https://${hostname}/api/v2/projects/${projectId}/entry-points/execute`;
  const body = JSON.stringify({
    repeaterId,
    request: { method: 'GET', url: TARGET_URL },
    parameters: []
  });

  // Right after the deploy, the cloud may not yet consider the Repeater connected.
  for (let attempt = 1; attempt <= 6; attempt++) {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Api-Key ${apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body,
      signal: AbortSignal.timeout(EXECUTE_TIMEOUT_MS)
    });
    const text = await res.text();
    process.stdout.write(`execute: HTTP ${res.status} ${text}\n`);

    if (res.status === 400 && text.includes('The repeater is not connected')) {
      await sleep(5_000);
      continue;
    }
    if (res.status !== 200) {
      return { error: `the execute API answered HTTP ${res.status}` };
    }

    return { result: JSON.parse(text) };
  }

  return { error: 'the cloud never considered the Repeater connected' };
};

const waitForLog = async (repeater, pattern, timeoutMs) => {
  const deadline = Date.now() + timeoutMs;
  while (!pattern.test(repeater.log) && Date.now() < deadline) {
    await sleep(250);
  }

  return pattern.test(repeater.log);
};

const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const check = async (repeater, result) => {
  const { response, error } = result;

  if (testCase === 'positive') {
    if (response?.status !== 200) {
      return `expected HTTP 200 from the target, got ${response?.status ?? `no response (error: ${JSON.stringify(error)})`}`;
    }
    if (!String(response.body).includes('Certificate is valid!')) {
      return `expected "Certificate is valid!" in the body, got ${JSON.stringify(response.body)}`;
    }
    if (!(await waitForLog(repeater, /Executing HTTP request with a PKCS#11 certificate/, 5_000))) {
      return 'the Repeater did not use the PKCS#11 certificate';
    }

    return;
  }

  if (response?.status === 200) {
    return 'expected the TLS handshake to fail, got HTTP 200';
  }
  if (!error) {
    return `expected an error, got ${JSON.stringify(result)}`;
  }
  // The cloud only reports a generic Repeater error; the TLS cause is in the
  // Repeater log. With TLS 1.3 the client sees the rejection after its side of
  // the handshake (receive failure), with TLS 1.2 during it (connect error).
  const tlsRejected = new RegExp(
    `PKCS#11 certificate for ${escape(TARGET_HOST)} failed: .*(Failure when receiving data from the peer|SSL connect error)`
  );
  if (!(await waitForLog(repeater, tlsRejected, 5_000))) {
    return 'the Repeater log does not show the target rejecting the certificate in the TLS handshake';
  }
};

const main = async () => {
  process.stdout.write(`== ${testCase}: ${p12}\n`);
  loadCertificate();

  const repeater = await startRepeaterWithRetry();
  let problem;
  try {
    const { result, error } = await execute();
    problem = error ?? (await check(repeater, result));
  } finally {
    await stopRepeater(repeater);
  }

  if (problem) {
    fail(`${testCase}: ${problem}`);
  }
  process.stdout.write(`E2E PASSED: ${testCase}\n`);
};

main().catch((e) => fail(e.stack ?? String(e)));
