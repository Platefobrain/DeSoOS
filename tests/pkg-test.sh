#!/usr/bin/env bash
# PKG TEST – desopkg against a test repository on a running DeSo OS (V082-B plan §5):
#
#   tests/pkg-test.sh
#   ACCEL=kvm tests/pkg-test.sh
#
# 1. The normal image (./build.sh): nothing of the self-test image in it (V082-B P2-3) – no
#    /etc/desopkg/ca or repo.test in build/user/initrd.rs, no crash point, no-memory switch,
#    test host or test CA in build/user/desopkg and build/user/sh.
# 2. The test package witaj (tests/pkg/witaj/main.rs) built with the SDK (sdk/deso-build.sh) for
#    each version; tests/pkg/make-repo.py makes the repositories (scenarios), signed with the
#    test key.
# 3. QEMU (./build.sh --selftest) with a fresh DeSoFS volume on the virtio disk and a network
#    card, the phase "pkg b1"; on the host tests/repo-stub.py (tls.deso:58480, control 58481)
#    and tests/dns-stub.py (53530).  PKG TEST runs /bin/pkgtest through init and the shell
#    (logs/test-pkg-b.log).
# Ends with the self-test build in build/ (as tests/test.sh leaves it).
set -uo pipefail

T="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$T")"
cd "$ROOT"

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
  for s in /tmp/desopkg-crash /tmp/desopkg-nomem /etc/desopkg/ca tls.deso "BEGIN CERTIFICATE" "HANG "; do
    for f in build/user/desopkg build/user/sh; do
      grep -aq -- "$s" "$f" && leak="$leak $f:$s"
    done
  done
  grep -q 'repo.test\|"ca"\|tests/tls/ca.pem' build/user/initrd.rs && leak="$leak initrd.rs:test-repository"
  if [ -z "$leak" ]; then
    ok "the normal image has nothing of the self-test image (test CA, repo.test, crash points, no-memory switch)"
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
if [ "$FAIL" != 0 ]; then
  echo "[PKG HOST TEST] QEMU skipped (earlier failures)" >> "$LOG"
elif ! ./build.sh --selftest > "$W/selftest.log" 2>&1; then
  tail -n 20 "$W/selftest.log"
  bad "./build.sh --selftest"
elif ! python3 tools/mkdesofs.py "$W/disk.img" --blocks 32768 > "$W/fmt.log" 2>&1; then
  bad "tools/mkdesofs.py: $(cat "$W/fmt.log")"
else
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
  if [ ! -e "$STUB_READY/dns" ] || [ ! -e "$STUB_READY/repo" ]; then
    bad "the host servers did not start: $(cat "$W/dns.log" "$W/repo-stub.log")"
  else
    timeout 2400 qemu-system-x86_64 -machine q35 -m 512M -smp 2 "${ACCEL_ARGS[@]}" \
      -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
      -device qemu-xhci,id=xhci \
      -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on \
      -device usb-storage,bus=xhci.0,port=1,drive=usbboot,bootindex=0 \
      -drive file="$W/disk.img",format=raw,if=none,id=vd0 -device virtio-blk-pci,drive=vd0 \
      -netdev user,id=net0 -device e1000e,netdev=net0,mac=52:54:00:12:34:56 \
      -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
      -fw_cfg name=opt/deso/autotest,string=1 \
      -fw_cfg "name=opt/deso/phase,string=pkg b1" \
      -serial stdio -display none -no-reboot < /dev/null > "$W/qemu.log" 2>&1
    c=$?
    tr -d '\r' < "$W/qemu.log" | grep -a "^\[PKG TEST\]\|^\[RESULT-PKGB\]\|pkgtest: FAIL" >> "$LOG"
    if [ "$c" = 33 ]; then ok "on DeSo OS ($ACCEL): desopkg against the test repository"
    else bad "on DeSo OS: QEMU code $c"; tr -d '\r' < "$W/qemu.log" | tail -n 25 >> "$LOG"; fi
  fi
fi

cat "$LOG"
if [ "$FAIL" = 0 ]; then
  echo "PASS - $PASS checks (logs/test-pkg-b.log)"
  exit 0
fi
echo "FAIL - $FAIL of $((PASS + FAIL)) checks failed (logs/test-pkg-b.log)"
exit 1
