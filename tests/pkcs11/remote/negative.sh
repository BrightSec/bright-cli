#!/usr/bin/env bash
# Negative case: a client certificate the target does not trust. The target must
# reject it in the TLS handshake, so the Repeater returns an error and no HTTP
# status.
#
# Usage: negative.sh <target url> [client.p12] [p12 password]
#   Without a PKCS#12 file, a self-signed certificate is generated.
. "$(dirname "$0")/lib.sh"

url=${1:-}
usage_url "$url"
p12=${2:-}
pass=${3:-1234}

check_prerequisites
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -n "$p12" ]; then
  from_p12 "$p12" "$pass" "$work"
else
  # Git Bash rewrites arguments starting with "/" into Windows paths; "//" survives as "/".
  subj=/CN=bright-untrusted-client
  case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) subj=/$subj ;; esac
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "$subj" \
    -addext extendedKeyUsage=clientAuth \
    -keyout "$work/client.key" -out "$work/client.pem" 2>/dev/null
fi

make_token "$work"
check_through_repeater "$url" error "$work"
