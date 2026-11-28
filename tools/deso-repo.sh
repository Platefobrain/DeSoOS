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
# it before then.  The serial is the UTC time YYYYMMDDHHMM, but always above the serial of the
# index already in OUT (two builds in one minute, or a clock behind it): a system that took the
# last index takes the new one.  The package `witaj` is tests/pkg/witaj/main.rs (the same
# program PKG TEST uses) with its version filled in.
#
# `build` replaces only OUT/deso/stable/x86_64, and only when everything in it is its own work:
# the index already there must carry a good signature, its packages must match it, and any other
# file stops the build (listed, left alone).  The new files are built and checked in
# x86_64.new; then x86_64 → x86_64.old, x86_64.new → x86_64, and x86_64.old is emptied.  If
# that is interrupted, the next `build` puts x86_64.old back first.  Nothing is removed with a
# recursive delete: only the index, its signature and package files, then the empty folders.
#
# Tests (tests/repo-build-test.sh) set DESO_REPO_TEST=1: the test key (tests/pkg/test-key.pem
# and user/etc/desopkg/keys.test) instead of ~/.deso-keys, and DESO_REPO_NOW (the UTC minute),
# DESO_REPO_SDK (the SDK build script) and DESO_REPO_STOP=swap (killed between the two
# renames).  Without DESO_REPO_TEST=1 those are ignored.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

KEYID="decodesoft-2026-01"
KEYDIR="$HOME/.deso-keys"
KEY="$KEYDIR/$KEYID.pem"
KEYS="user/etc/desopkg/keys"
VERSIONS=(1.0.0 1.0.1)
SDK="$ROOT/sdk/deso-build.sh"
NOW=""
STOP=""
if [ "${DESO_REPO_TEST:-}" = 1 ]; then
  KEYID="deso-test-1"
  KEY="$ROOT/tests/pkg/test-key.pem"
  KEYS="user/etc/desopkg/keys.test"
  SDK="${DESO_REPO_SDK:-$SDK}"
  NOW="${DESO_REPO_NOW:-}"
  STOP="${DESO_REPO_STOP:-}"
fi

command -v openssl >/dev/null 2>&1 || { echo "openssl not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found"; exit 1; }

# Removes a folder this script made: the index, its signature and the package files, then the
# empty folders.  Anything else in it stays, and the folder with it (an error, listed).
remove_ours() {
  local d="$1" f
  [ -e "$d" ] || return 0
  rm -f -- "$d/index" "$d/index.sig"
  if [ -d "$d/packages" ] && [ ! -L "$d/packages" ]; then
    for f in "$d"/packages/*.pkg; do
      [ -f "$f" ] && [ ! -L "$f" ] && rm -f -- "$f"
    done
    rmdir -- "$d/packages" 2>/dev/null || true
  fi
  if ! rmdir -- "$d" 2>/dev/null; then
    echo "$d holds files this script did not make - left as it is:"
    (cd "$d" && find . -mindepth 1 | sed 's|^\./|  |' | sort)
    return 1
  fi
}

# `desopkg.py published`: the state of a published folder.  Sets PREV (serial or none), NEXT
# (the serial for a new index); refuses (exit 1, the reason shown) on anything else.
read_published() {
  local d="$1" out
  local args=(published "$d" --keys "$KEYS")
  [ -n "$NOW" ] && args+=(--now "$NOW")
  if ! out="$(python3 tools/desopkg.py "${args[@]}")"; then
    echo "$out"
    return 1
  fi
  PREV="$(printf '%s\n' "$out" | sed -n 's/^serial //p')"
  [ -n "$PREV" ] || PREV=none
  NEXT="$(printf '%s\n' "$out" | sed -n 's/^next //p')"
}

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
    STABLE="$OUT/deso/stable"
    LIVE="$STABLE/x86_64"
    NEW="$STABLE/x86_64.new"
    OLD="$STABLE/x86_64.old"

    # An earlier build stopped half-way: put the old publication back, drop the unfinished one.
    if [ -e "$OLD" ] && [ ! -e "$LIVE" ]; then
      mv -T -- "$OLD" "$LIVE"
      echo "an earlier build stopped while swapping - $LIVE put back as it was"
    fi
    if [ -e "$NEW" ]; then
      echo "removing $NEW (left by an earlier build that did not finish)"
      remove_ours "$NEW" || { echo "stopped - nothing published"; exit 1; }
    fi
    if [ -e "$OLD" ]; then
      echo "removing $OLD (left by an earlier build after the swap)"
      remove_ours "$OLD" || { echo "stopped - nothing published"; exit 1; }
    fi

    # What is published now: its serial, and nothing in it that is not ours.
    if ! read_published "$LIVE"; then
      echo "stopped - $LIVE was not changed (fix or move what is listed above, then build again)"
      exit 1
    fi
    if [ "$PREV" = none ]; then
      echo "published now: nothing - the first index gets serial $NEXT"
    else
      echo "published now: serial $PREV - the new index gets serial $NEXT"
    fi

    W="$(mktemp -d /tmp/deso-repo.XXXXXX)"
    trap 'rm -rf "$W"' EXIT
    BASE="$W/x86_64"
    mkdir -p "$BASE/packages"
    for v in "${VERSIONS[@]}"; do
      mkdir -p "$W/$v/src" "$W/$v/pkg/bin" "$W/$v/pkg/share/witaj"
      sed "s/^const VERSION: &str = \"0.0.0\";/const VERSION: \&str = \"$v\";/" tests/pkg/witaj/main.rs > "$W/$v/src/witaj.rs"
      grep -q "const VERSION: &str = \"$v\";" "$W/$v/src/witaj.rs" || { echo "witaj: the version line was not found"; exit 1; }
      if ! "$SDK" build "$W/$v/src/witaj.rs" -o "$W/$v/build" -n witaj > "$W/$v/build.log" 2>&1; then
        cat "$W/$v/build.log"
        echo "witaj $v: the SDK build failed - nothing published"
        exit 1
      fi
      cp "$W/$v/build/witaj" "$W/$v/pkg/bin/witaj"
      printf 'Witaj w DeSo OS - wersja %s\n' "$v" > "$W/$v/pkg/share/witaj/hello.txt"
      printf 'name=witaj\nversion=%s\nsummary=A greeting for DeSo OS\n' "$v" > "$W/$v/pkg/desopkg.meta"
      python3 tools/desopkg.py pack "$W/$v/pkg" -o "$BASE/packages/witaj-$v.pkg"
    done
    python3 tools/desopkg.py index "$BASE" --serial "$NEXT" --key "$KEY" --keyid "$KEYID" --days 30
    python3 tools/desopkg.py check "$BASE/index" --keys "$KEYS" --sig "$BASE/index.sig"

    # Into x86_64.new next to the live folder, checked there again (the copy, not the source).
    mkdir -p "$NEW/packages"
    cp -- "$BASE/index" "$BASE/index.sig" "$NEW/"
    cp -- "$BASE"/packages/*.pkg "$NEW/packages/"
    WANT="$NEXT"
    if ! read_published "$NEW" || [ "$PREV" != "$WANT" ]; then
      echo "the copy in $NEW did not check out - nothing published"
      remove_ours "$NEW" || true
      exit 1
    fi

    # The live folder once more (something may have been put there during the build), then swap.
    if ! read_published "$LIVE"; then
      echo "stopped - $LIVE changed during the build and was not replaced"
      remove_ours "$NEW" || true
      exit 1
    fi
    if [ "$PREV" != none ] && python3 -c 'import sys; sys.exit(0 if int(sys.argv[1]) >= int(sys.argv[2]) else 1)' "$PREV" "$WANT"; then
      echo "stopped - $LIVE now holds serial $PREV (not below $WANT): another build ran meanwhile"
      remove_ours "$NEW" || true
      exit 1
    fi
    if [ -e "$LIVE" ]; then
      mv -T -- "$LIVE" "$OLD"
    fi
    if [ "$STOP" = swap ]; then
      echo "DESO_REPO_STOP=swap: killed between the two renames"
      rm -rf "$W"
      kill -KILL $$
    fi
    mv -T -- "$NEW" "$LIVE"
    if ! remove_ours "$OLD"; then
      echo "published, but $OLD could not be emptied (see above)"
      exit 1
    fi

    echo
    echo "Ready: $OUT/deso (serial $WANT)"
    find "$LIVE" -type f | sort | sed "s|^$OUT/||"
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
