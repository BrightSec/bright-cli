// TODO: temporary. Remove together with ../tmp-pkcs11-windows-e2e.yml.
//
// One case of the PKCS#11 end-to-end check: loads a client certificate into a
// SoftHSM2 token, starts the Repeater with it, has the Bright cloud send one
// request through the Repeater to the mTLS target, and checks the outcome.
//
// Usage: node tmp-pkcs11-windows-e2e.mjs <case> <client.p12>
//
// Cases: positive, negative, and the library discovery ones, where the
// Repeater gets no --pkcs11-module and must find PKCS11_PLANTED_MODULE, a copy
// of SoftHSM2 under the name of a card vendor's library:
//   discovery-not-found  only a 32-bit copy is planted; the Repeater must
//                        refuse to start and say it needs the 64-bit build
//   discovery-positive   as positive, through the planted x64 copy
//   discovery-hint       the wanted token is missing; the error must say the
//                        library was picked automatically
//
// Environment: BRIGHT_HOSTNAME, BRIGHT_PROJECT_ID, BRIGHT_API_KEY,
// BRIGHT_REPEATER_ID, REPEATER_BIN, PKCS11_MODULE, PKCS11_WORK_DIR, and
// PKCS11_PLANTED_MODULE for the discovery cases.
// softhsm2-util, pkcs11-tool and openssl must be on PATH.

import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

// A dedicated instance (Helm release ao-https-mtls-win-e2e, built-in
// MyCompany Root CA): the manual checks reconfigure ao-https-mtls-pkcs11.
const TARGET_HOST = 'ao-https-mtls-win-e2e.nlb.brokencrystals.nexploit.app';
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
  const raw = process.env[name] ?? fallback;
  // Pasted secrets often carry a trailing newline; keys and IDs never contain whitespace.
  const value = raw?.trim();
  if (!value) {
    fail(`${name} is not set`);
  }
  if (value !== raw) {
    process.stdout.write(`warning: ${name} had surrounding whitespace, trimmed\n`);
  }

  return value;
};

const CASES = [
  'positive',
  'negative',
  'discovery-not-found',
  'discovery-positive',
  'discovery-hint'
];
const [testCase, p12Arg] = process.argv.slice(2);
if (!CASES.includes(testCase) || !p12Arg) {
  fail(`usage: tmp-pkcs11-windows-e2e.mjs <${CASES.join('|')}> <client.p12>`);
}
const discovery = testCase.startsWith('discovery-');
// What the Repeater's cert entry asks for: a token that is not there, in the hint case.
const wantedToken = testCase === 'discovery-hint' ? 'no-such-token' : TOKEN_LABEL;
const NOT_FOUND_TIMEOUT_MS = 60_000;

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
const plantedModule = discovery ? env('PKCS11_PLANTED_MODULE') : undefined;
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
    if (!/^(path|softhsm2_conf|openssl_modules|openssl_conf|pkcs11_module_path|pkcs11_provider_module)$/i.test(key)
      // The repeater command reads REPEATER_* variables as options, e.g. REPEATER_BIN as --bin.
      && !/^repeater_/i.test(key)) {
      result[key] = value;
    }
  }
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  result.SOFTHSM2_CONF = softhsmConf;
  // Logs why the WebSocket to the cloud closes (transport error, ping timeout, server disconnect).
  result.DEBUG = 'engine.io-client:socket,socket.io-client:manager,socket.io-client:socket';
  // The WebSocket closes a few ms after a PKCS#11 request starts: show the TLS/TCP error behind it.
  result.NODE_DEBUG = 'tls,net';
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
    ...(discovery ? [] : ['--pkcs11-module', pkcs11Module]),
    '--pkcs11-cert', JSON.stringify({ hostname: TARGET_HOST, token: wantedToken, pinFile }),
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

const execute = async (targetUrl) => {
  const url = `https://${hostname}/api/v2/projects/${projectId}/entry-points/execute`;
  const body = JSON.stringify({
    repeaterId,
    request: { method: 'GET', url: targetUrl },
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

const reconnects = (repeater) =>
  (repeater.log.match(/Reconnecting to Bright cloud/g) ?? []).length;

// With no response and no error the cloud's reachability probe through the
// Repeater got no reply, so the request itself was never sent.
const noReply = (repeater, result) =>
  !result.response && !result.error
    ? `the cloud got no reply through the Repeater (connectivity: ${result.connectivity}); ` +
      `the Repeater reconnected to the cloud ${reconnects(repeater)} time(s)`
    : undefined;

// A target without a PKCS#11 certificate: tells a Repeater-to-cloud problem
// from one caused by the PKCS#11 request.
const CONTROL_URL = 'https://example.com/';

const control = async (repeater) => {
  const before = reconnects(repeater);
  const { result, error } = await execute(CONTROL_URL);
  await sleep(5_000);
  process.stdout.write(
    `control (no PKCS#11): ${error ?? `status ${result.response?.status ?? 'none'}, connectivity ${result.connectivity}`}; ` +
      `Repeater reconnects during it: ${reconnects(repeater) - before}\n`
  );
};

const connectedPlanted = () =>
  new RegExp(
    `PKCS#11: --pkcs11-module is not set; connected the .+ library ${escape(plantedModule)} \\(\\d+ tokens? present\\)`
  );

const check = async (repeater, result) => {
  const { response, error } = result;

  if (testCase === 'discovery-positive' && !connectedPlanted().test(repeater.log)) {
    return `the Repeater did not log that it connected ${plantedModule}`;
  }

  if (testCase === 'positive' || testCase === 'discovery-positive') {
    const lost = noReply(repeater, result);
    if (lost) {
      return lost;
    }
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

  if (response) {
    return `expected the TLS handshake to fail, got HTTP ${response.status}`;
  }
  // The cloud probes the target through the Repeater first; the rejected
  // handshake fails that probe, so the API answers "unreachable" with neither
  // response nor error. A lost reply looks the same, hence the reconnect check.
  if (reconnects(repeater)) {
    return `the Repeater lost its cloud connection ${reconnects(repeater)} time(s), so the outcome is not the target's`;
  }
  // With TLS 1.3 the client sees the rejection after its side of the
  // handshake (receive failure), with TLS 1.2 during it (connect error).
  const tlsRejected = new RegExp(
    `PKCS#11 certificate for ${escape(TARGET_HOST)} failed: .*(Failure when receiving data from the peer|SSL connect error)`
  );
  if (!(await waitForLog(repeater, tlsRejected, 5_000))) {
    return 'the Repeater log does not show the target rejecting the certificate in the TLS handshake';
  }
};

// The Repeater reports every login problem as the same "Failed to log in";
// the REST API tells a bad key, another environment and a foreign ID apart.
const checkCredentials = async () => {
  const lookup = (host) =>
    fetch(`https://${host}/api/v1/repeaters/${repeaterId}`, {
      headers: { Authorization: `Api-Key ${apiKey}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(30_000)
    });

  const res = await lookup(hostname);
  if (res.ok) {
    const repeater = await res.json();
    process.stdout.write(
      `credentials: the API key sees repeater "${repeater.name}" on ${hostname}` +
        ` (status: ${repeater.status}, projects: ${repeater.projectIds?.length ? repeater.projectIds.join(", ") : "any"})\n`
    );

    return;
  }

  const hint = {
    401: 'the API key is not valid on this environment',
    403: 'the API key lacks the repeaters:read scope (the e2e needs all scopes)',
    404: "the repeater ID does not exist in the API key's organization"
  }[res.status];
  process.stdout.write(`credentials: GET /api/v1/repeaters/<id> on ${hostname} -> HTTP ${res.status}: ${hint ?? (await res.text())}\n`);

  if (res.status === 401) {
    const other = hostname === 'app.brightsec.com' ? 'development.playground.brightsec.com' : 'app.brightsec.com';
    const otherRes = await lookup(other).catch(() => undefined);
    if (otherRes && otherRes.status !== 401) {
      process.stdout.write(`credentials: the same key is accepted on ${other} (HTTP ${otherRes.status}): the secrets are for that environment\n`);
    }
  }
  fail(`the API key or repeater ID secret does not work on ${hostname}`);
};

// The Repeater must stop during option validation, before it logs in to the cloud.
const checkNotFound = async () => {
  writeFileSync(pinFile, PIN);
  const repeater = await startRepeater();
  if (!repeater.exited) {
    await stopRepeater(repeater);

    return 'the Repeater started although no 64-bit PKCS#11 library is installed';
  }
  const code = await repeater.exitedPromise;
  const expected = [
    /No PKCS#11 library for your smart card was found, and --pkcs11-module is not set\./,
    new RegExp(`${escape(plantedModule)}: this is the 32-bit version\\. Bright CLI is 64-bit`)
  ];
  const missing = expected.filter((pattern) => !pattern.test(repeater.log));
  if (missing.length) {
    return `the Repeater output lacks ${missing.join(', ')}`;
  }
  if (/connected the .+ library/.test(repeater.log)) {
    return 'the Repeater connected a library although only a 32-bit one is installed';
  }
  if (code === 0) {
    return 'the Repeater exited with code 0';
  }
};

const checkHint = async (repeater) => {
  if (!connectedPlanted().test(repeater.log)) {
    return `the Repeater did not log that it connected ${plantedModule}`;
  }
  const hint = new RegExp(
    `Token "${wantedToken}" not found; .*The PKCS#11 library ${escape(plantedModule)} was selected automatically because --pkcs11-module is not set\\.`
  );
  if (!(await waitForLog(repeater, hint, 30_000))) {
    return 'the pre-flight error does not say that the library was selected automatically';
  }
};

const main = async () => {
  process.stdout.write(`== ${testCase}: ${p12}\n`);

  if (testCase === 'discovery-not-found') {
    mkdirSync(work, { recursive: true });
    const problem = await Promise.race([
      checkNotFound(),
      sleep(NOT_FOUND_TIMEOUT_MS).then(() => 'the Repeater neither started nor stopped in time')
    ]);
    if (problem) {
      fail(`${testCase}: ${problem}`);
    }
    process.stdout.write(`E2E PASSED: ${testCase}\n`);

    return;
  }

  await checkCredentials();
  loadCertificate();

  const repeater = await startRepeaterWithRetry();
  let problem;
  try {
    if (testCase === 'discovery-hint') {
      problem = await checkHint(repeater);
    } else {
      await control(repeater);
      const { result, error } = await execute(TARGET_URL);
      problem = error ?? (await check(repeater, result));
    }
  } finally {
    await stopRepeater(repeater);
  }

  if (problem) {
    fail(`${testCase}: ${problem}`);
  }
  process.stdout.write(`E2E PASSED: ${testCase}\n`);
};

main().catch((e) => fail(e.stack ?? String(e)));
