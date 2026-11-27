#!/usr/bin/env bash
set -euo pipefail

# Check the actual executable, including program headers and eager binding.
runtime=${1:?expected a path to the Android ARM64 runtime executable}
readelf=${READELF:-readelf}
export LC_ALL=C
header=$("$readelf" -Wh "$runtime")
segments=$("$readelf" -Wl "$runtime")
dynamic=$("$readelf" -Wd "$runtime")

require() {
    if ! "$@"; then
        echo "Android ELF check failed: $*" >&2
        exit 1
    fi
}
require grep -Eq 'Class:[[:space:]]+ELF64' <<<"$header"
require grep -Eq 'Machine:[[:space:]]+AArch64' <<<"$header"
require grep -Eq 'Type:[[:space:]]+DYN' <<<"$header"
require grep -Eq '^[[:space:]]*INTERP[[:space:]]' <<<"$segments"
require awk '$1 == "GNU_STACK" { n++; for (i=7; i<NF; i++) if ($i ~ /E/) executable=1 }
             END { exit !(n == 1 && !executable) }' <<<"$segments"
require grep -Eq '^[[:space:]]*GNU_RELRO[[:space:]]' <<<"$segments"
require grep -Eq '\(BIND_NOW\)|\(FLAGS(_1)?\).*\b(NOW|BIND_NOW)\b' <<<"$dynamic"
echo "Android ARM64 PIE, non-executable stack and full RELRO verified"
