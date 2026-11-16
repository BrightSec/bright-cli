#!/usr/bin/env bash
# Positive case: a client certificate issued by a CA the target trusts. The
# request must pass mTLS through the Repeater and get the expected HTTP status.
#
# Usage: positive.sh <target url> <client.p12> [p12 password] [expected status]
#   defaults: password 1234, status 200
. "$(dirname "$0")/lib.sh"

url=${1:-}
usage_url "$url"
p12=${2:-}
[ -n "$p12" ] || die "usage: $(basename "$0") <target url> <client.p12> [p12 password] [expected status]"
pass=${3:-1234}
expected=${4:-200}

check_prerequisites
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

from_p12 "$p12" "$pass" "$work"
make_token "$work"
check_through_repeater "$url" "$expected" "$work"
