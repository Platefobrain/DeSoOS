#!/usr/bin/env bash
# The repository build (tools/deso-repo.sh build) on the host: serials, refusals, the lock, swap and
# recovery.  Offline, the test key (DESO_REPO_TEST=1), a fresh OUT in /tmp – never ~/.deso-keys,
# never ~/Pulpit/deso-repo.  The packages are built with the SDK like a real build (sdk/,
# rustc and the x86_64-unknown-none target); REPO_TEST_FAKE_SDK=1 uses a stand-in that writes a
# minimal ABI 1.0 program instead (for machines without the target).
#
#   tests/repo-build-test.sh        "[REPO BUILD TEST] ... PASS", exit 0 when all pass
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

T="$(mktemp -d /tmp/repo-build-test.XXXXXX)"
trap 'rm -rf "$T"' EXIT
OUT="$T/out"
LIVE="$OUT/deso/stable/x86_64"
PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); echo "[REPO BUILD TEST] $1 PASS"; }
bad() { FAIL=$((FAIL + 1)); echo "[REPO BUILD TEST] $1 FAIL"; [ -f "$T/log" ] && sed 's/^/    /' "$T/log"; }

export DESO_REPO_TEST=1
unset DESO_REPO_STOP DESO_REPO_NOW
if [ "${REPO_TEST_FAKE_SDK:-}" = 1 ]; then
  cat > "$T/fake-sdk.sh" <<EOF
#!/usr/bin/env bash
# stand-in for sdk/deso-build.sh: build FILE -o DIR -n NAME
set -e
[ "\$1" = build ] && [ "\$3" = -o ] && [ "\$5" = -n ] || exit 2
mkdir -p "\$4"
python3 -I -c 'import sys; sys.path.insert(0, sys.argv[2]); import desopkg; open(sys.argv[1], "wb").write(desopkg.elf_program())' "\$4/\$6" "$ROOT/tools"
EOF
  chmod +x "$T/fake-sdk.sh"
  export DESO_REPO_SDK="$T/fake-sdk.sh"
  echo "[REPO BUILD TEST] (stand-in SDK)"
fi

# build NOW [env...] – exit code in $RC, output in $T/log
build() {
  local now="$1"
  shift
  env DESO_REPO_NOW="$now" "$@" tools/deso-repo.sh build "$OUT" > "$T/log" 2>&1
  RC=$?
}
serial() { sed -n 's/^serial=//p' "$LIVE/index" 2>/dev/null; }
tree() { (cd "$OUT" && find . -type f -print0 | sort -z | xargs -0 sha256sum; find . | sort) 2>/dev/null | sha256sum; }
leftovers() { [ ! -e "$OUT/deso/stable/x86_64.new" ] && [ ! -e "$OUT/deso/stable/x86_64.old" ]; }

# 1. First build: serial = the clock; the rest of OUT/deso left alone.
mkdir -p "$OUT/deso"
echo siemka > "$OUT/deso/test.txt"
build 202611281038
if [ $RC = 0 ] && [ "$(serial)" = 202611281038 ] && leftovers && [ "$(cat "$OUT/deso/test.txt")" = siemka ] \
   && python3 tools/desopkg.py check "$LIVE/index" --keys user/etc/desopkg/keys.test --sig "$LIVE/index.sig" > /dev/null; then
  ok "1/12 first build: serial 202611281038, signed, other files in deso kept"
else
  bad "1/12 first build (rc $RC, serial $(serial))"
fi

# 2. The same minute again: one above.
build 202611281038
if [ $RC = 0 ] && [ "$(serial)" = 202611281039 ] && leftovers; then
  ok "2/12 two builds in one minute: 202611281039"
else
  bad "2/12 two builds in one minute (rc $RC, serial $(serial))"
fi

# 3. A clock behind the published index: still one above it.
build 202611281038
if [ $RC = 0 ] && [ "$(serial)" = 202611281040 ] && leftovers; then
  ok "3/12 clock behind the published index: 202611281040"
else
  bad "3/12 clock behind the published index (rc $RC, serial $(serial))"
fi

# 4. A later clock: the clock.
build 202611281105
if [ $RC = 0 ] && [ "$(serial)" = 202611281105 ] && leftovers; then
  ok "4/12 later clock: 202611281105"
else
  bad "4/12 later clock (rc $RC, serial $(serial))"
fi

# 5. A damaged index (the last digit of its serial – still a well-formed index, only its
#    signature tells), then a missing signature: refused, nothing changed.
cp "$LIVE/index" "$T/index.good"
python3 - "$LIVE/index" <<'EOF'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
i = b.index(b"\nissued=") - 1  # the last digit of the serial
b[i] = ord("1") if b[i] == ord("0") else b[i] - 1
open(p, "wb").write(bytes(b))
EOF
before="$(tree)"
build 202611281200
r1=$RC
grep -q "REFUSED" "$T/log"; g1=$?
after1="$(tree)"
cp "$T/index.good" "$LIVE/index"
mv "$LIVE/index.sig" "$T/index.sig.good"
before2="$(tree)"
build 202611281200
r2=$RC
grep -q "published_incomplete" "$T/log"; g2=$?
after2="$(tree)"
mv "$T/index.sig.good" "$LIVE/index.sig"
if [ $r1 != 0 ] && [ $g1 = 0 ] && [ "$before" = "$after1" ] && [ $r2 != 0 ] && [ $g2 = 0 ] && [ "$before2" = "$after2" ] && leftovers; then
  ok "5/12 damaged index / missing signature: refused, OUT unchanged"
else
  bad "5/12 damaged index / missing signature (rc $r1/$r2)"
fi

# 6. A file the script did not make: refused, listed, left as it is.
echo moje > "$LIVE/packages/notes.txt"
before="$(tree)"
build 202611281200
if [ $RC != 0 ] && grep -q "published_unknown_files packages/notes.txt" "$T/log" && [ "$before" = "$(tree)" ] \
   && [ "$(cat "$LIVE/packages/notes.txt")" = moje ] && leftovers; then
  ok "6/12 unknown file: refused, listed, kept, OUT unchanged"
else
  bad "6/12 unknown file (rc $RC)"
fi
rm -f "$LIVE/packages/notes.txt"

# 7. The SDK build fails: the published folder stays.
printf '#!/bin/sh\necho "error: simulated build failure"\nexit 1\n' > "$T/broken-sdk.sh"
chmod +x "$T/broken-sdk.sh"
before="$(tree)"
build 202611281200 DESO_REPO_SDK="$T/broken-sdk.sh"
if [ $RC != 0 ] && grep -q "nothing published" "$T/log" && [ "$before" = "$(tree)" ] && [ "$(serial)" = 202611281105 ] && leftovers; then
  ok "7/12 build failure: old publication (202611281105) unchanged"
else
  bad "7/12 build failure (rc $RC, serial $(serial))"
fi

# 8. Killed between the two renames: x86_64 missing, x86_64.old intact; the next build puts it
#    back and publishes above it (its clock is behind 202611281105, so only the restored index
#    gives 202611281106).
old_sha="$(cd "$LIVE" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)"
build 202611281200 DESO_REPO_STOP=swap 2>/dev/null
s1=$RC
held=0
[ ! -e "$LIVE" ] && [ -d "$OUT/deso/stable/x86_64.old" ] \
  && [ "$(cd "$OUT/deso/stable/x86_64.old" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum)" = "$old_sha" ] && held=1
build 202611281100
if [ $s1 != 0 ] && [ $held = 1 ] && [ $RC = 0 ] && grep -q "put back as it was" "$T/log" && [ "$(serial)" = 202611281106 ] && leftovers; then
  ok "8/12 killed during the swap: x86_64.old intact, put back, then 202611281106 published"
else
  bad "8/12 killed during the swap (rc $s1/$RC, held $held, serial $(serial))"
fi

# 9. The serial cannot go past 2^64 - 1: an index at the limit (signed with the test key) refuses.
python3 tools/desopkg.py index "$LIVE" --serial 18446744073709551615 --key tests/pkg/test-key.pem --keyid deso-test-1 > /dev/null
before="$(tree)"
build 202611281300
if [ $RC != 0 ] && grep -q "serial_exhausted" "$T/log" && [ "$before" = "$(tree)" ] && leftovers; then
  ok "9/12 serial 2^64-1 published: refused, OUT unchanged"
else
  bad "9/12 serial at the limit (rc $RC)"
fi

# 10. An empty folder the script did not make: refused and listed like a file, left alone.
mkdir "$LIVE/packages/old"
before="$(tree)"
build 202611281400
if [ $RC != 0 ] && grep -q "published_unknown_files packages/old" "$T/log" && [ "$before" = "$(tree)" ] && [ -d "$LIVE/packages/old" ] && leftovers; then
  ok "10/12 empty unknown folder: refused, listed, kept, OUT unchanged"
else
  bad "10/12 empty unknown folder (rc $RC)"
fi
rmdir "$LIVE/packages/old"
# (9/12 left a published serial of 2^64-1: back to a normal index for the rest.)
python3 tools/desopkg.py index "$LIVE" --serial 202611281400 --key tests/pkg/test-key.pem --keyid deso-test-1 > /dev/null

# 11. Two builds at once on one OUT: the second is refused while the first holds the lock; the
#     first finishes; the lock is gone afterwards.
env DESO_REPO_NOW=202611281500 DESO_REPO_STOP=locked tools/deso-repo.sh build "$OUT" > "$T/log1" 2>&1 &
first=$!
for _ in $(seq 50); do [ -f "$OUT/.deso-repo.lock/pid" ] && break; sleep 0.1; done
before="$(tree)"
build 202611281500
r2=$RC
grep -q "another build (pid $first) is running" "$T/log"; g2=$?
mid="$(tree)"
wait $first
r1=$?
if [ $r2 != 0 ] && [ $g2 = 0 ] && [ "$before" = "$mid" ] && [ $r1 = 0 ] && [ "$(serial)" = 202611281500 ] && [ ! -e "$OUT/.deso-repo.lock" ] && leftovers; then
  ok "11/12 two builds at once: the second refused (OUT unchanged), the first published 202611281500, lock released"
else
  bad "11/12 two builds at once (second rc $r2, first rc $r1, serial $(serial))"; sed 's/^/    first: /' "$T/log1"
fi

# 12. A lock left by a build that is gone (a pid no process has): taken over, then released.
sh -c 'exit 0' & dead=$!; wait $dead
mkdir -p "$OUT/.deso-repo.lock"; echo "$dead" > "$OUT/.deso-repo.lock/pid"
build 202611281600
if [ $RC = 0 ] && grep -q "took over the lock of a build that stopped (pid $dead)" "$T/log" && [ "$(serial)" = 202611281600 ] && [ ! -e "$OUT/.deso-repo.lock" ] && leftovers; then
  ok "12/12 stale lock (pid $dead gone): taken over, 202611281600 published, lock released"
else
  bad "12/12 stale lock (rc $RC, serial $(serial))"
fi

echo "[REPO BUILD TEST] $PASS/12 passed"
[ $FAIL = 0 ]
