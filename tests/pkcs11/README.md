# PKCS#11 test environment

A software token ([SoftHSM2](https://github.com/softhsm/SoftHSMv2)) and an mTLS target, for developing and testing smart-card (PKCS#11) client certificates without hardware.

`setup.sh` creates a throwaway token `bright-test` (user PIN `1234`) holding an RSA-2048 client key and its certificate, both labelled `client`. The private key exists only on the token. The target only accepts clients presenting a certificate issued by the test CA.

`tls-stack.spec.ts` checks that the `@brightsec/node-libcurl` binding can complete that handshake with the key on the token. It runs in CI on changes to this folder or to `package-lock.json`.

## Run on Linux (Docker)

```bash
docker build -t bright-cli-pkcs11 tests/pkcs11
docker run --rm -v "$PWD":/app -v bright-cli-pkcs11-node-modules:/app/node_modules bright-cli-pkcs11 \
  bash -c 'npm ci -q --ignore-scripts && npm rebuild @brightsec/node-libcurl \
    && tests/pkcs11/setup.sh && . tests/pkcs11/.work/pkcs11.env && npm run test:pkcs11'
```

The named volume keeps the Linux `node_modules` apart from the host's.

## Run on macOS

```bash
brew install softhsm libp11 opensc
tests/pkcs11/setup.sh
. tests/pkcs11/.work/pkcs11.env
npm run test:pkcs11
```

Homebrew's libp11 is built against OpenSSL 4, which has no engines, so the engine test is skipped on macOS.

## Run on Windows (Git Bash)

Install [OpenSC](https://github.com/OpenSC/OpenSC/releases) (for `pkcs11-tool`), unpack the [SoftHSM2 portable build](https://github.com/disig/SoftHSM2-for-Windows/releases) and the [libp11 x64 build](https://github.com/OpenSC/libp11/releases) (which contains `pkcs11prov.dll`), and point `setup.sh` at them:

```bash
export PKCS11_TEST_SOFTHSM_DIR=/c/tools/SoftHSM2       # contains bin/ and lib/softhsm2-x64.dll
export PKCS11_TEST_PROVIDER_DIR=/c/tools/libp11        # contains pkcs11prov.dll
export PKCS11_TEST_OPENSSL_DIR="/c/Program Files/OpenSSL/bin"  # contains libcrypto-3-x64.dll
tests/pkcs11/setup.sh
. tests/pkcs11/.work/pkcs11.env
npm run test:pkcs11
```

`pkcs11prov.dll` links against `libcrypto-3-x64.dll`, which libp11 doesn't ship; the generated `pkcs11.env` puts all three directories on `PATH` so Windows can resolve the DLLs. The engine test is skipped: the Windows binding has no engine loader.

## Manual testing

After loading `pkcs11.env`, start the target with:

```bash
npx ts-node tests/pkcs11/target.ts   # https://localhost:8443/, port via PKCS11_TEST_TARGET_PORT
```

Token URIs:

| Object      | URI                                                   |
| ----------- | ----------------------------------------------------- |
| Private key | `pkcs11:token=bright-test;object=client;type=private` |
| Certificate | `pkcs11:token=bright-test;object=client;type=cert`    |

Inspect the token with `pkcs11-tool --module "$PKCS11_TEST_MODULE" --login --pin 1234 --list-objects`.

## Environment written by `setup.sh`

| Variable                                        | Purpose                                                                                                    |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `SOFTHSM2_CONF`                                 | Points SoftHSM2 at the throwaway token directory.                                                          |
| `OPENSSL_MODULES` / `OPENSSL_ENGINES`           | Directories of the PKCS#11 provider / engine. Required: the binding's built-in paths point at its CI host. |
| `PKCS11_PROVIDER_MODULE` / `PKCS11_MODULE_PATH` | Vendor PKCS#11 module, as read by pkcs11-provider / libp11.                                                |
| `PKCS11_TEST_*`                                 | Token, object, PIN, PKI directory and provider/engine names used by the tests.                             |

## Known limitations

- **One PKCS#11 module per process.** curl loads and unloads the provider together with each easy handle, and the unload tears down state of the process-wide module (`C_Finalize`, `C_CloseAllSessions`). A fresh connection on a _new_ handle in the same process then fails (`PKCS11 Module has not been initialized yet`, or `provider signature failure` with libp11). Keeping the easy handles long-lived avoids it with both providers, without quirks or patches; connection reuse reduces how often it matters. The tests run each case in its own process and cover the long-lived-handle mode explicitly.
- **The PIN goes in the key URI for providers** (`?pin-value=`). Providers ignore `KEYPASSWD`; the engine honours it.
- **libcurl reports every key-loading failure the same way.** A wrong PIN, a missing token and a bad module path all surface as `CURLE_SSL_CERTPROBLEM` (58).
- **SoftHSM2 can't simulate readers or card removal**, and its signing is far faster than a real card's. Use a real card to check error handling and throughput.
- **Not covered:** the Node `tls` (WebSocket) path, which is out of scope.
