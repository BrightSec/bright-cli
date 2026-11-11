#!/usr/bin/env bash
# Provisions a throwaway SoftHSM2 token plus a test PKI for the PKCS#11 tests,
# then writes the environment the tests (and a manual Repeater run) need to
# tests/pkcs11/.work/pkcs11.env.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${PKCS11_TEST_WORK_DIR:-$HERE/.work}
TOKEN=${PKCS11_TEST_TOKEN:-bright-test}
OBJECT=${PKCS11_TEST_OBJECT:-client}
PIN=${PKCS11_TEST_PIN:-1234}
SO_PIN=${PKCS11_TEST_SO_PIN:-5678}
# Git Bash rewrites arguments starting with "/" into Windows paths; "//" survives as "/".
SUBJ=/

first_existing() {
  for path in "$@"; do
    if [ -e "$path" ]; then
      echo "$path"
      return 0
    fi
  done
}

require() {
  command -v "$1" >/dev/null || {
    echo "error: '$1' not found. $2" >&2
    exit 1
  }
}

# Paths handed to native Windows tools, OpenSSL and Node must be Windows paths.
native() {
  if command -v cygpath >/dev/null; then
    cygpath -m "$1"
  else
    echo "$1"
  fi
}

case "$(uname -s)" in
  Linux)
    INSTALL_HINT='Install: apt-get install softhsm2 opensc pkcs11-provider libengine-pkcs11-openssl openssl'
    MODULE=$(first_existing /usr/lib/*-linux-gnu/softhsm/libsofthsm2.so /usr/lib/softhsm/libsofthsm2.so /usr/lib64/pkcs11/libsofthsm2.so)
    PROVIDER_LIB=$(first_existing /usr/lib/*-linux-gnu/ossl-modules/pkcs11.so /usr/lib64/ossl-modules/pkcs11.so)
    PROVIDER=pkcs11
    if [ -z "$PROVIDER_LIB" ]; then
      # Alpine has no pkcs11-provider package, only libp11's provider.
      INSTALL_HINT='Install: apt-get install softhsm2 opensc pkcs11-provider openssl, or apk add softhsm opensc libp11 openssl'
      PROVIDER_LIB=$(first_existing /usr/lib/ossl-modules/pkcs11prov.so)
      PROVIDER=pkcs11prov
    fi
    ENGINE_LIB=$(first_existing /usr/lib/*-linux-gnu/engines-3/pkcs11.so /usr/lib64/engines-3/pkcs11.so)
    ;;
  Darwin)
    require brew 'Install Homebrew first.'
    INSTALL_HINT='Install: brew install softhsm libp11 opensc'
    BREW=$(brew --prefix)
    MODULE=$(first_existing "$BREW/lib/softhsm/libsofthsm2.so")
    # Homebrew's libp11 is built against OpenSSL 4, which has no engines, so only its provider is available.
    PROVIDER_LIB=$(first_existing "$BREW/lib/ossl-modules/pkcs11prov.dylib")
    PROVIDER=pkcs11prov
    ENGINE_LIB=
    ;;
  MINGW* | MSYS* | CYGWIN*)
    INSTALL_HINT='Set PKCS11_TEST_SOFTHSM_DIR, PKCS11_TEST_PROVIDER_DIR and PKCS11_TEST_OPENSSL_DIR (see README.md)'
    SOFTHSM_DIR=${PKCS11_TEST_SOFTHSM_DIR:-}
    PROVIDER_DIR=${PKCS11_TEST_PROVIDER_DIR:-}
    OPENSSL_DIR=${PKCS11_TEST_OPENSSL_DIR:-}
    MODULE=$(first_existing "$SOFTHSM_DIR/lib/softhsm2-x64.dll")
    PROVIDER_LIB=$(first_existing "$PROVIDER_DIR/pkcs11prov.dll")
    PROVIDER=pkcs11prov
    ENGINE_LIB=
    [ -e "$OPENSSL_DIR/libcrypto-3-x64.dll" ] || {
      echo "error: libcrypto-3-x64.dll not found in PKCS11_TEST_OPENSSL_DIR. $INSTALL_HINT" >&2
      exit 1
    }
    # Windows resolves DLL dependencies through PATH: the 32-bit softhsm2-util
    # needs softhsm2.dll, and pkcs11prov.dll needs libcrypto-3-x64.dll.
    WINDOWS_PATH="$SOFTHSM_DIR/bin:$SOFTHSM_DIR/lib:$PROVIDER_DIR:$OPENSSL_DIR"
    export PATH="$WINDOWS_PATH:$PATH"
    SUBJ=//
    ;;
  *)
    echo "error: unsupported OS $(uname -s); use the Docker image (see README.md)" >&2
    exit 1
    ;;
esac

require softhsm2-util "$INSTALL_HINT"
require pkcs11-tool "$INSTALL_HINT"
require openssl "$INSTALL_HINT"
[ -n "$MODULE" ] || { echo "error: SoftHSM2 module not found. $INSTALL_HINT" >&2; exit 1; }
[ -n "$PROVIDER_LIB" ] || { echo "error: PKCS#11 OpenSSL provider not found. $INSTALL_HINT" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK/tokens" "$WORK/pki"
PKI=$WORK/pki

cat > "$WORK/softhsm2.conf" <<EOF
directories.tokendir = $(native "$WORK/tokens")
objectstore.backend = file
log.level = ERROR
EOF
SOFTHSM2_CONF=$(native "$WORK/softhsm2.conf")
export SOFTHSM2_CONF

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "${SUBJ}CN=Bright PKCS11 Test CA" \
  -keyout "$PKI/ca.key" -out "$PKI/ca.pem" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "${SUBJ}CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$PKI/server.key" -out "$PKI/server.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "${SUBJ}CN=bright-pkcs11-client" \
  -keyout "$PKI/client.key" -out "$PKI/client.csr" 2>/dev/null
openssl x509 -req -days 30 -in "$PKI/client.csr" -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" \
  -CAcreateserial -out "$PKI/client.pem" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$PKI/client.key" -out "$PKI/client.pk8"
openssl x509 -in "$PKI/client.pem" -outform der -out "$PKI/client.der"

softhsm2-util --init-token --free --label "$TOKEN" --pin "$PIN" --so-pin "$SO_PIN" >/dev/null
softhsm2-util --import "$(native "$PKI/client.pk8")" --token "$TOKEN" --label "$OBJECT" --id 01 --pin "$PIN" >/dev/null
pkcs11-tool --module "$(native "$MODULE")" --token-label "$TOKEN" --login --pin "$PIN" \
  --write-object "$(native "$PKI/client.der")" --type cert --label "$OBJECT" --id 01 >/dev/null
# The private key must never exist outside the token, as on a real smart card.
rm -f "$PKI/client.key" "$PKI/client.pk8" "$PKI/client.csr"

{
  echo "export SOFTHSM2_CONF='$SOFTHSM2_CONF'"
  echo "export PKCS11_TEST_DIR='$(native "$PKI")'"
  echo "export PKCS11_TEST_MODULE='$(native "$MODULE")'"
  echo "export PKCS11_TEST_TOKEN='$TOKEN'"
  echo "export PKCS11_TEST_OBJECT='$OBJECT'"
  echo "export PKCS11_TEST_PIN='$PIN'"
  echo "export PKCS11_TEST_PROVIDER='$PROVIDER'"
  echo "export PKCS11_TEST_PROVIDER_LIB='$(native "$PROVIDER_LIB")'"
  # The binding's compiled-in module/engine directories point at its CI build host.
  echo "export OPENSSL_MODULES='$(native "$(dirname "$PROVIDER_LIB")")'"
  # pkcs11-provider reads PKCS11_PROVIDER_MODULE; libp11 (provider and engine) reads PKCS11_MODULE_PATH.
  echo "export PKCS11_PROVIDER_MODULE='$(native "$MODULE")'"
  echo "export PKCS11_MODULE_PATH='$(native "$MODULE")'"
  if [ -n "$ENGINE_LIB" ]; then
    echo "export OPENSSL_ENGINES='$(dirname "$ENGINE_LIB")'"
    echo "export PKCS11_TEST_ENGINE='pkcs11'"
  fi
  if [ -n "${WINDOWS_PATH:-}" ]; then
    echo "export PATH='$WINDOWS_PATH':\"\$PATH\""
  fi
} > "$WORK/pkcs11.env"

# pkcs11-provider tears down module state shared by its other instances when one
# of them is unloaded; the Repeater runs it with this quirk, so the tests do too.
if [ "$PROVIDER" = pkcs11 ]; then
  cat > "$WORK/openssl.cnf" <<EOF
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $PROVIDER_LIB
pkcs11-module-path = $MODULE
pkcs11-module-quirks = no-deinit
activate = 1
EOF
  echo "export OPENSSL_CONF='$(native "$WORK/openssl.cnf")'" >> "$WORK/pkcs11.env"
fi

pkcs11-tool --module "$(native "$MODULE")" --token-label "$TOKEN" --login --pin "$PIN" --list-objects 2>/dev/null \
  | grep -E 'Object;|label:' | sed 's/^/  /'
echo "Token '$TOKEN' ready. Load the environment with: . $WORK/pkcs11.env"
