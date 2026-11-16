#!/usr/bin/env bash
# Shared part of positive.sh and negative.sh: puts one client certificate on a
# throwaway SoftHSM2 token and sends one request through the Repeater (built from
# this checkout) to a remote mTLS target. A fake Bright cloud on localhost:8000
# (repeater-smoke.ts) issues the request, so no API key is needed.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TOKEN_LABEL=bright-remote-check
PIN=1234
SO_PIN=5678

die() {
  echo "error: $*" >&2
  exit 2
}

softhsm_module() {
  if [ -n "${PKCS11_MODULE:-}" ]; then
    echo "$PKCS11_MODULE"
    return
  fi
  for path in \
    "$(brew --prefix 2>/dev/null)/lib/softhsm/libsofthsm2.so" \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/*-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/pkcs11/libsofthsm2.so; do
    [ -e "$path" ] && { echo "$path"; return; }
  done
  die "SoftHSM2 module not found; install softhsm (brew) or softhsm2 (apt), or set PKCS11_MODULE"
}

check_prerequisites() {
  for tool in softhsm2-util pkcs11-tool openssl node; do
    command -v "$tool" >/dev/null || die "'$tool' not found (see tests/pkcs11/README.md)"
  done
  [ -f "$ROOT/dist/index.js" ] || die "build the CLI first: npm run build"
  node -e "require('pkcs11js')" 2>/dev/null || die "pkcs11js is not installed: rerun npm ci with a C++ toolchain"
}

# Extracts the client certificate and its key from a PKCS#12 file.
from_p12() {
  local p12=$1 pass=$2 out=$3
  [ -f "$p12" ] || die "$p12 not found"
  openssl pkcs12 -in "$p12" -passin "pass:$pass" -nokeys -clcerts -out "$out/client.pem" 2>/dev/null ||
    openssl pkcs12 -legacy -in "$p12" -passin "pass:$pass" -nokeys -clcerts -out "$out/client.pem"
  openssl pkcs12 -in "$p12" -passin "pass:$pass" -nocerts -nodes -out "$out/client.key" 2>/dev/null ||
    openssl pkcs12 -legacy -in "$p12" -passin "pass:$pass" -nocerts -nodes -out "$out/client.key"
}

# Creates the token and imports client.key / client.pem from $1 (label "client", id 01).
# The key file is deleted afterwards: from then on it exists only on the token.
make_token() {
  local work=$1 module
  module=$(softhsm_module)
  mkdir -p "$work/tokens"
  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$work/tokens" > "$work/softhsm2.conf"
  export SOFTHSM2_CONF="$work/softhsm2.conf"

  openssl pkcs8 -topk8 -nocrypt -in "$work/client.key" -out "$work/client.p8"
  openssl x509 -in "$work/client.pem" -outform der -out "$work/client.der"
  softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$PIN" --so-pin "$SO_PIN" >/dev/null
  softhsm2-util --import "$work/client.p8" --token "$TOKEN_LABEL" --label client --id 01 --pin "$PIN" >/dev/null
  pkcs11-tool --module "$module" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
    --write-object "$work/client.der" --type cert --label client --id 01 >/dev/null
  rm -f "$work/client.key" "$work/client.p8"
  echo "$PIN" > "$work/pin.txt"

  echo "Token \"$TOKEN_LABEL\": $(openssl x509 -in "$work/client.pem" -noout -subject), $(openssl x509 -in "$work/client.pem" -noout -issuer)"
}

# Sends GET <url> through the Repeater with the token's certificate; $2 is the
# expected HTTP status or the Repeater's errorCode, "error" for any errorCode.
check_through_repeater() {
  local url=$1 expected=$2 work=$3 module host
  module=$(softhsm_module)
  host=$(node -e 'console.log(new URL(process.argv[1]).hostname)' "$url")
  # The Repeater writes its own OpenSSL config; leftovers from setup.sh must not interfere.
  unset OPENSSL_CONF OPENSSL_MODULES PKCS11_MODULE_PATH PKCS11_PROVIDER_MODULE
  cd "$ROOT"
  # The stand-in cloud accepts any API key; passed through the environment, as
  # REPEATER_<OPTION> works for every repeater option.
  REPEATER_TOKEN=stand-in-cloud node -r ts-node/register/transpile-only tests/pkcs11/repeater-smoke.ts "$url" "$expected" -- \
    node dist/index.js repeater --hostname localhost --id 8PY6wKetVqmfMC9K9g4A7Y \
    --pkcs11-module "$module" \
    --pkcs11-cert "{\"hostname\":\"$host\",\"token\":\"$TOKEN_LABEL\",\"pinFile\":\"$work/pin.txt\"}"
}

usage_url() {
  [ -n "${1:-}" ] || die "usage: $(basename "$0") <target url> [options], e.g. https://mtls.example.com/"
}
