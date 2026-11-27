#!/usr/bin/env bash
# DecodeSoft's package repository – the files for https://decodesoft.pl/deso/ (docs/pkg/README.md).
#
#   tools/deso-repo.sh key           once: a new signing key in ~/.deso-keys/ (never in the
#                                    repository, never in an image) and its public half into
#                                    user/etc/desopkg/keys – the key every normal image trusts
#   tools/deso-repo.sh build [OUT]   witaj 1.0.0 and 1.0.1 built with the SDK, packed, the index
#                                    signed with that key: OUT/deso/stable/x86_64/ (default
#                                    ~/Pulpit/deso-repo) – drag OUT/deso onto the server so that
#                                    https://decodesoft.pl/deso/stable/x86_64/index exists
#
# The index is valid for 30 days (desopkg refuses an expired one): run `build` again and upload
# it before then.  Every `build` gets a higher serial (the UTC time, YYYYMMDDHHMM), so a system
# never takes an older index back.  The package `witaj` is tests/pkg/witaj/main.rs (the same
# program PKG TEST uses) with its version filled in.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

KEYID="decodesoft-2026-01"
KEYDIR="$HOME/.deso-keys"
KEY="$KEYDIR/$KEYID.pem"
KEYS="user/etc/desopkg/keys"
VERSIONS=(1.0.0 1.0.1)

command -v openssl >/dev/null 2>&1 || { echo "openssl not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found"; exit 1; }

case "${1:-}" in
  key)
    [ $# = 1 ] || { echo "usage: tools/deso-repo.sh key"; exit 1; }
    if [ -e "$KEY" ]; then
      echo "$KEY already exists - not replaced (systems built with its public key would refuse"
      echo "an index signed with a new one)."
      exit 1
    fi
    mkdir -p "$KEYDIR"
    chmod 700 "$KEYDIR"
    (umask 077 && openssl ecparam -name prime256v1 -genkey -noout -out "$KEY")
    chmod 600 "$KEY"
    python3 tools/desopkg.py keys "$KEY" --keyid "$KEYID" -o "$KEYS"
    echo "private key: $KEY (keep it, back it up, never copy it into the project)"
    echo "public key:  $KEYS (key id $KEYID) - goes into every normal image"
    cat "$KEYS"
    ;;
  build)
    [ $# -le 2 ] || { echo "usage: tools/deso-repo.sh build [OUT]"; exit 1; }
    OUT="${2:-$HOME/Pulpit/deso-repo}"
    [ -f "$KEY" ] || { echo "no signing key $KEY - run tools/deso-repo.sh key first"; exit 1; }
    if ! python3 tools/desopkg.py keys "$KEY" --keyid "$KEYID" | cmp -s - "$KEYS"; then
      echo "$KEYS does not hold the public half of $KEY - images built from this tree would"
      echo "refuse the index (run tools/deso-repo.sh key on a fresh checkout only once)."
      exit 1
    fi
    case "$OUT" in
      "$ROOT"|"$ROOT"/*) echo "OUT must be outside the project ($OUT)"; exit 1 ;;
    esac
    W="$(mktemp -d /tmp/deso-repo.XXXXXX)"
    trap 'rm -rf "$W"' EXIT
    BASE="$OUT/deso/stable/x86_64"
    rm -rf "$OUT/deso"
    mkdir -p "$BASE/packages"
    for v in "${VERSIONS[@]}"; do
      mkdir -p "$W/$v/src" "$W/$v/pkg/bin" "$W/$v/pkg/share/witaj"
      sed "s/^const VERSION: &str = \"0.0.0\";/const VERSION: \&str = \"$v\";/" tests/pkg/witaj/main.rs > "$W/$v/src/witaj.rs"
      grep -q "const VERSION: &str = \"$v\";" "$W/$v/src/witaj.rs" || { echo "witaj: the version line was not found"; exit 1; }
      if ! "$ROOT/sdk/deso-build.sh" build "$W/$v/src/witaj.rs" -o "$W/$v/build" -n witaj > "$W/$v/build.log" 2>&1; then
        cat "$W/$v/build.log"
        echo "witaj $v: the SDK build failed"
        exit 1
      fi
      cp "$W/$v/build/witaj" "$W/$v/pkg/bin/witaj"
      printf 'Witaj w DeSo OS - wersja %s\n' "$v" > "$W/$v/pkg/share/witaj/hello.txt"
      printf 'name=witaj\nversion=%s\nsummary=A greeting for DeSo OS\n' "$v" > "$W/$v/pkg/desopkg.meta"
      python3 tools/desopkg.py pack "$W/$v/pkg" -o "$BASE/packages/witaj-$v.pkg"
    done
    serial="$(date -u +%Y%m%d%H%M)"
    python3 tools/desopkg.py index "$BASE" --serial "$serial" --key "$KEY" --keyid "$KEYID" --days 30
    python3 tools/desopkg.py check "$BASE/index" --keys "$KEYS" --sig "$BASE/index.sig"
    echo
    echo "Ready: $OUT/deso"
    find "$OUT/deso" -type f | sort | sed "s|^$OUT/||"
    echo "Upload the folder deso (with everything in it) to the top of decodesoft.pl, so that"
    echo "  https://decodesoft.pl/deso/stable/x86_64/index"
    echo "  https://decodesoft.pl/deso/stable/x86_64/index.sig"
    echo "  https://decodesoft.pl/deso/stable/x86_64/packages/witaj-1.0.0.pkg"
    echo "open in a browser. Valid for 30 days - build and upload again before then."
    ;;
  *)
    echo "usage: tools/deso-repo.sh key | build [OUT]"
    exit 1
    ;;
esac
