#!/usr/bin/env bash
# PKG TEST – desopkg against a test repository on a running DeSo OS:
#
#   tests/pkg-test.sh
#   ACCEL=kvm tests/pkg-test.sh
#   tests/pkg-test.sh --mutants        every mutant of desopkg must be caught
#
# 1. The normal image (./build.sh): nothing of the self-test image in it – no
#    /etc/desopkg/ca or repo.test in build/user/initrd.rs, no crash point, no-memory switch,
#    shell pause, test host or test CA in build/user/desopkg and build/user/sh.
# 2. The test package witaj (tests/pkg/witaj/main.rs) built with the SDK (sdk/deso-build.sh) for
#    each version; tests/pkg/make-repo.py makes the repositories (scenarios), signed with the
#    test key.
# 3. QEMU (./build.sh --selftest) with a DeSoFS volume on the virtio disk and a network card;
#    on the host tests/repo-stub.py (tls.deso:58480, control 58481) and tests/dns-stub.py
#    (53530).  PKG TEST runs /bin/pkgtest through init and the shell (logs/test-pkg-b.log),
#    seven starts of QEMU on one volume:
#      pkg b1      part 1 on a fresh volume
#      pkg b2      part 2: desopkg killed at every crash point, the lock, the shell against gc,
#                  damaged indexes and generations
#      pkg p1..p4  desopkg stopped at K2h, K6, K7h, K9; the kernel says "POWER OFF" and this
#                  script kills QEMU (kill -9) – a power loss at that moment
#      pkg p5      the last check after a power loss
#    --mutants instead: for each mutant (DESO_PKG_MUTANT=sig|serial|expires|paths|order|hash –
#    one check switched off) a self-test build and a fresh volume with the phase "pkg m"; a
#    normal desopkg passes it, every mutant must fail it.
# Ends with the self-test build in build/ (as tests/test.sh leaves it).
set -uo pipefail

T="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$T")"
cd "$ROOT"

MUTANTS=0
case "${1:-}" in
  "") ;;
  --mutants) MUTANTS=1 ;;
  *) echo "usage: tests/pkg-test.sh [--mutants]"; exit 3 ;;
esac
ACCEL="${ACCEL:-tcg}"
case "$ACCEL" in
  kvm) ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: kvm or tcg (got: $ACCEL)"; exit 3 ;;
esac
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
[ -f "$OVMF_CODE" ] || { echo "OVMF not found (sudo apt install ovmf)"; exit 3; }
command -v openssl >/dev/null 2>&1 || { echo "openssl not found"; exit 3; }

mkdir -p logs
LOG="$ROOT/logs/test-pkg-b.log"
: > "$LOG"
W="$(mktemp -d /tmp/deso-pkg-test.XXXXXX)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  rm -rf "$W"
}
trap cleanup EXIT
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "[PKG HOST TEST] $1 PASS" >> "$LOG"; }
bad() { FAIL=$((FAIL + 1)); echo "[PKG HOST TEST] FAIL: $1" >> "$LOG"; }

# ------------------------------------------------------------------ 1. the normal image
if ! ./build.sh > "$W/build-normal.log" 2>&1; then
  tail -n 20 "$W/build-normal.log"
  bad "./build.sh"
else
  leak=""
  for s in /tmp/desopkg-crash /tmp/desopkg-nomem /tmp/sh-pause /etc/desopkg/ca tls.deso "BEGIN CERTIFICATE" "HANG "; do
    for f in build/user/desopkg build/user/sh; do
      grep -aq -- "$s" "$f" && leak="$leak $f:$s"
    done
  done
  grep -q 'repo.test\|"ca"\|tests/tls/ca.pem' build/user/initrd.rs && leak="$leak initrd.rs:test-repository"
  if [ -z "$leak" ]; then
    ok "the normal image has nothing of the self-test image (test CA, repo.test, crash points, no-memory switch, the shell's pause)"
  else
    bad "the normal image holds self-test things:$leak"
  fi
fi

# ------------------------------------------------------------------ 2. the test package and repositories
mkdir -p "$W/home" "$W/wbin" "$W/src"
ENVV=(env -i "PATH=$PATH" "HOME=$W/home")
[ -n "${RUSTUP_HOME:-}" ] && ENVV+=("RUSTUP_HOME=$RUSTUP_HOME")
[ -z "${RUSTUP_HOME:-}" ] && [ -d "$HOME/.rustup" ] && ENVV+=("RUSTUP_HOME=$HOME/.rustup")
[ -n "${RUSTUP_TOOLCHAIN:-}" ] && ENVV+=("RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN")
built=0
for v in 1.0.0 1.0.1 1.1.0 1.1.1 1.1.3 1.1.4; do
  mkdir -p "$W/src/$v"
  sed "s/^const VERSION: &str = \"0.0.0\";/const VERSION: \&str = \"$v\";/" tests/pkg/witaj/main.rs > "$W/src/$v/witaj.rs"
  if (cd / && "${ENVV[@]}" "$ROOT/sdk/deso-build.sh" build "$W/src/$v/witaj.rs" -o "$W/src/$v/build" -n witaj) > "$W/witaj-$v.log" 2>&1; then
    cp "$W/src/$v/build/witaj" "$W/wbin/witaj-$v"
    built=$((built + 1))
  else
    tail -n 5 "$W/witaj-$v.log" >> "$LOG"
  fi
done
if [ "$built" = 6 ]; then ok "witaj built with the SDK for 6 versions"; else bad "witaj: $built of 6 versions built"; fi
if python3 tests/pkg/make-repo.py "$W/repo" "$W/wbin" > "$W/repo.log" 2>&1; then
  ok "$(cat "$W/repo.log")"
else
  bad "make-repo.py: $(tail -n 5 "$W/repo.log")"
fi

# ------------------------------------------------------------------ 3. on DeSo OS

# One start of QEMU on $W/disk.img with the phase "pkg $1"; the log in $W/qemu-$1.log, its PKG
# lines into $LOG.  $2 = end: QEMU ends by itself (isa-debug-exit 33 = PASS); $2 = power: the
# start ends with "POWER OFF at" and is killed (kill -9 – a power loss at that moment).
boot() {
  local phase="$1" mode="$2" q="$W/qemu-$1.log" c=0 qpid
  qemu-system-x86_64 -machine q35 -m 512M -smp 2 "${ACCEL_ARGS[@]}" \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -device qemu-xhci,id=xhci \
    -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on \
    -device usb-storage,bus=xhci.0,port=1,drive=usbboot,bootindex=0 \
    -drive file="$W/disk.img",format=raw,if=none,id=vd0 -device virtio-blk-pci,drive=vd0 \
    -netdev user,id=net0 -device e1000e,netdev=net0,mac=52:54:00:12:34:56 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -fw_cfg name=opt/deso/autotest,string=1 \
    -fw_cfg "name=opt/deso/phase,string=pkg $phase" \
    -serial stdio -display none -no-reboot < /dev/null > "$q" 2>&1 &
  qpid=$!
  local limit=2400 t=0 off=0
  while kill -0 "$qpid" 2>/dev/null; do
    if [ "$mode" = power ] && grep -aq "POWER OFF at" "$q"; then
      kill -9 "$qpid" 2>/dev/null
      off=1
      break
    fi
    if [ "$t" -ge $((limit * 2)) ]; then
      kill -9 "$qpid" 2>/dev/null
      echo "[PKG HOST TEST] pkg $phase: no end after $limit s" >> "$LOG"
      break
    fi
    sleep 0.5
    t=$((t + 1))
  done
  wait "$qpid" 2>/dev/null
  c=$?
  tr -d '\r' < "$q" | grep -a "^\[PKG TEST\]\|^\[RESULT-PKG\|pkgtest: FAIL" >> "$LOG"
  if [ "$mode" = power ]; then
    [ "$off" = 1 ] && return 0
  elif [ "$c" = 33 ]; then
    return 0
  fi
  tr -d '\r' < "$q" | tail -n 25 >> "$LOG"
  return 1
}

fresh_disk() {
  rm -f "$W/disk.img"
  python3 tools/mkdesofs.py "$W/disk.img" --blocks 32768 > "$W/fmt.log" 2>&1
}

servers() {
  export STUB_READY="$W/ready"
  mkdir -p "$STUB_READY"
  python3 "$T/dns-stub.py" 53530 > "$W/dns.log" 2>&1 &
  PIDS+=($!)
  python3 "$T/repo-stub.py" "$W/repo" > "$W/repo-stub.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 100); do
    [ -e "$STUB_READY/dns" ] && [ -e "$STUB_READY/repo" ] && break
    sleep 0.1
  done
  [ -e "$STUB_READY/dns" ] && [ -e "$STUB_READY/repo" ]
}

if [ "$FAIL" != 0 ]; then
  echo "[PKG HOST TEST] QEMU skipped (earlier failures)" >> "$LOG"
elif ! servers; then
  bad "the host servers did not start: $(cat "$W/dns.log" "$W/repo-stub.log")"
elif [ "$MUTANTS" = 1 ]; then
  # 16. Each mutant (one check of desopkg switched off) must fail the sequence "pkg m" that a
  #     normal desopkg passes; a fresh volume each time.  The self-test build without a mutant
  #     is rebuilt at the end.
  for m in none sig serial expires paths order hash; do
    if [ "$m" = none ]; then
      env -u DESO_PKG_MUTANT ./build.sh --selftest > "$W/selftest-$m.log" 2>&1
    else
      DESO_PKG_MUTANT="$m" ./build.sh --selftest > "$W/selftest-$m.log" 2>&1
    fi
    if [ $? != 0 ]; then
      tail -n 20 "$W/selftest-$m.log"
      bad "./build.sh --selftest with the mutant $m"
      continue
    fi
    if ! fresh_disk; then
      bad "tools/mkdesofs.py: $(cat "$W/fmt.log")"
      continue
    fi
    echo "[PKG HOST TEST] mutant $m:" >> "$LOG"
    if boot m end; then
      if [ "$m" = none ]; then ok "without a mutant the sequence passes ($ACCEL)"
      else bad "the mutant $m was NOT caught"; fi
    elif [ "$m" != none ] && grep -aq "\[PKG TEST\] FAIL" "$W/qemu-m.log"; then
      ok "the mutant $m was caught: $(tr -d '\r' < "$W/qemu-m.log" | grep -a -m1 "\[PKG TEST\] FAIL" | cut -c1-200)"
    else
      bad "the sequence failed with the mutant $m without a FAIL line (or without a mutant)"
    fi
  done
  env -u DESO_PKG_MUTANT ./build.sh --selftest > "$W/selftest-end.log" 2>&1 || bad "./build.sh --selftest at the end"
elif ! ./build.sh --selftest > "$W/selftest.log" 2>&1; then
  tail -n 20 "$W/selftest.log"
  bad "./build.sh --selftest"
elif ! fresh_disk; then
  bad "tools/mkdesofs.py: $(cat "$W/fmt.log")"
else
  # Part 1 on a fresh volume, part 2 and the power losses on the same one.
  if boot b1 end; then
    ok "on DeSo OS ($ACCEL): part 1 - desopkg against the test repository"
    if boot b2 end; then
      ok "on DeSo OS ($ACCEL): part 2 - crash points, the lock, the shell against gc, damaged files"
      steps=0
      for n in 1 2 3 4; do
        boot "p$n" power || break
        steps=$n
      done
      if [ "$steps" = 4 ] && boot p5 end; then
        ok "on DeSo OS ($ACCEL): 4 power losses (K2h, K6, K7h, K9) - QEMU killed, the next start finds the old or the new generation whole"
      else
        bad "power losses: stopped after step $steps"
      fi
    else
      bad "part 2 on DeSo OS"
    fi
  else
    bad "part 1 on DeSo OS"
  fi
fi

cat "$LOG"
if [ "$FAIL" = 0 ]; then
  echo "PASS - $PASS checks (logs/test-pkg-b.log)"
  exit 0
fi
echo "FAIL - $FAIL of $((PASS + FAIL)) checks failed (logs/test-pkg-b.log)"
exit 1
