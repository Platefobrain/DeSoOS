#!/usr/bin/env bash
# The SDK outside the repository – builds a program from a copy of sdk/ alone and runs it on
# DeSo OS (docs/abi/SDK.md):
#
#   tests/sdk-test.sh
#   ACCEL=kvm tests/sdk-test.sh
#
# 1. A temporary directory gets sdk/ and nothing else; with an empty environment (a new HOME, no
#    CARGO_HOME, PATH only, working directory /) deso-build.sh makes a new program from the
#    template and builds it.  The result: a static ELF, the ABI 1.0 note, no path of the
#    repository or of the temporary directory in the file or in the build log; the refusals
#    (an existing directory, a bad name, no such file, not a .rs file).
# 2. QEMU (the self-test kernel – ./build.sh --selftest first) with a fresh DeSoFS volume on
#    the virtio disk and the program in the fw_cfg file opt/deso/sdkprog: SDK TEST copies it to
#    /disk/bin through the shell and runs it by name (logs/test-sdk.log).
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

mkdir -p logs
LOG="$ROOT/logs/test-sdk.log"
: > "$LOG"
W="$(mktemp -d /tmp/deso-sdk-test.XXXXXX)"
trap 'rm -rf "$W"' EXIT
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "[SDK HOST TEST] $1 PASS" >> "$LOG"; }
bad() { FAIL=$((FAIL + 1)); echo "[SDK HOST TEST] FAIL: $1" >> "$LOG"; }

# ------------------------------------------------------------------ 1. outside the repository
cp -r "$ROOT/sdk" "$W/sdk"
rm -rf "$W/sdk/template/build"
mkdir -p "$W/home"
# Only PATH (rustc, objcopy, readelf) and a new HOME; rustup finds its toolchain through
# RUSTUP_HOME, which defaults to ~/.rustup – handed over when it exists.
ENVV=(env -i "PATH=$PATH" "HOME=$W/home")
[ -n "${RUSTUP_HOME:-}" ] && ENVV+=("RUSTUP_HOME=$RUSTUP_HOME")
[ -z "${RUSTUP_HOME:-}" ] && [ -d "$HOME/.rustup" ] && ENVV+=("RUSTUP_HOME=$HOME/.rustup")
[ -n "${RUSTUP_TOOLCHAIN:-}" ] && ENVV+=("RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN")
run() { (cd / && "${ENVV[@]}" "$@"); }

APP="$W/apps/sdkhello"
if run "$W/sdk/deso-build.sh" new "$APP" > "$W/new.log" 2>&1 && [ -f "$APP/main.rs" ]; then
  ok "new: $APP/main.rs from the template"
else
  bad "new: $(cat "$W/new.log")"
fi
if run "$W/sdk/deso-build.sh" build "$APP/main.rs" > "$W/build.log" 2>&1; then
  ok "build: $(grep -o 'sdkhello ([0-9]* B, DeSo OS ABI [0-9.]*)' "$W/build.log")"
else
  bad "build: $(tail -n 5 "$W/build.log")"
fi
PROG="$APP/build/sdkhello"
if [ -f "$PROG" ] && readelf -h "$PROG" | grep -q EXEC && [ "$(readelf -lW "$PROG" | grep -c INTERP)" = 0 ]; then
  ok "a static ELF (ET_EXEC, no interpreter)"
else
  bad "not a static ELF"
fi
if readelf -nW "$PROG" 2>/dev/null | grep -A1 "^ *DeSo .*0x00000008" | grep -q "description data: 01 00 00 00 00 00 00 00"; then
  ok "the ABI 1.0 note (DeSo, type 1: 1.0, flags 0)"
else
  bad "no ABI 1.0 note: $(readelf -nW "$PROG" 2>&1 | tail -n 3)"
fi
leak=""
for f in "$PROG" "$PROG.full" "$W/build.log"; do
  [ -f "$f" ] || continue
  grep -aq "$ROOT" "$f" && leak="$leak $f:repository"
  grep -aq "$W" "$f" && [ "$f" != "$W/build.log" ] && leak="$leak $f:temporary directory"
done
if [ -z "$leak" ]; then ok "no path of the repository in the program or the log, no build path in the program"; else bad "paths in:$leak"; fi
[ ! -e "$W/home/.cargo" ] && ok "nothing written to HOME (no cargo, no downloads)" || bad "something wrote $W/home/.cargo"

# Refusals.
refuse() { # $1 = what, $2... = arguments, the message must contain $MSG
  if run "$W/sdk/deso-build.sh" "${@:2}" > "$W/r.log" 2>&1; then bad "$1 accepted"
  elif grep -q "$MSG" "$W/r.log"; then ok "$1 refused ($(head -n 1 "$W/r.log" | cut -c1-90))"
  else bad "$1: $(cat "$W/r.log")"; fi
}
MSG="exists" refuse "new into an existing directory" new "$APP"
MSG="a program name" refuse "a bad name" new "$W/apps/Bad Name"
MSG="no such file" refuse "a missing file" build "$W/apps/none.rs"
printf 'x\n' > "$W/apps/x.txt"
MSG="not a .rs file" refuse "not a .rs file" build "$W/apps/x.txt"

# ------------------------------------------------------------------ 2. on DeSo OS
if ! ./build.sh --selftest > "$W/selftest.log" 2>&1; then
  tail -n 20 "$W/selftest.log"
  bad "./build.sh --selftest"
elif ! python3 tools/mkdesofs.py "$W/disk.img" --blocks 16384 > "$W/fmt.log" 2>&1; then
  bad "tools/mkdesofs.py: $(cat "$W/fmt.log")"
elif [ ! -f "$PROG" ]; then
  bad "no program to run"
else
  timeout 300 qemu-system-x86_64 -machine q35 -m 512M -smp 2 "${ACCEL_ARGS[@]}" \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -device qemu-xhci,id=xhci \
    -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on \
    -device usb-storage,bus=xhci.0,port=1,drive=usbboot,bootindex=0 \
    -drive file="$W/disk.img",format=raw,if=none,id=vd0 -device virtio-blk-pci,drive=vd0 \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -fw_cfg name=opt/deso/autotest,string=1 \
    -fw_cfg "name=opt/deso/phase,string=sdk sdkhello" \
    -fw_cfg "name=opt/deso/sdkprog,file=$PROG" \
    -serial stdio -display none -no-reboot < /dev/null > "$W/qemu.log" 2>&1
  c=$?
  tr -d '\r' < "$W/qemu.log" | grep -a "^\[SDK TEST\]" >> "$LOG"
  if [ "$c" = 33 ]; then ok "on DeSo OS ($ACCEL): copied to /disk/bin by the shell, run by name"
  else bad "on DeSo OS: QEMU code $c"; tr -d '\r' < "$W/qemu.log" | tail -n 15 >> "$LOG"; fi
fi

cat "$LOG"
if [ "$FAIL" = 0 ]; then
  echo "PASS - $PASS checks (logs/test-sdk.log)"
  exit 0
fi
echo "FAIL - $FAIL of $((PASS + FAIL)) checks failed (logs/test-sdk.log)"
exit 1
