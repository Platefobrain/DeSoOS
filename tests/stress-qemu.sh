#!/usr/bin/env bash
# Autostress in QEMU – the same test as on real hardware (DESOOS_AUTOSTRESS),
# but on this computer, before writing the USB stick.
#
#   tests/stress-qemu.sh              build with autostress + QEMU, result on screen
#   tests/stress-qemu.sh --no-build   run only (after your own ./build.sh --autostress=S)
#
# Variables:
#   SECS=60      stress duration in s (default 60)
#   SMP=N        number of QEMU CPUs (default: this computer's cores, at most 16)
#   ACCEL=kvm    kvm (default if /dev/kvm exists) or tcg
#
# Exit codes: 0 = PASS, 1 = FAIL, 2 = timeout / hang, 3 = error.
# Log: logs/stress-qemu.log.  Note: build/ then contains a kernel with autostress –
# make-usb.sh and test.sh build their own anyway.
set -uo pipefail

# Tests live in tests/, the rest of the project one directory up.
T="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$T")"
cd "$ROOT"

SECS="${SECS:-60}"
CORES="$(nproc 2>/dev/null || echo 4)"
SMP="${SMP:-$(( CORES > 16 ? 16 : CORES ))}"
if [ -z "${ACCEL:-}" ]; then
  if [ -w /dev/kvm ]; then ACCEL=kvm; else ACCEL=tcg; fi
fi
case "$ACCEL" in
  kvm)
    [ -w /dev/kvm ] || { echo "ACCEL=kvm: no access to /dev/kvm (sudo usermod -aG kvm $USER, then log out)"; exit 3; }
    ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: tcg or kvm (got: $ACCEL)"; exit 3 ;;
esac

BUILD=1
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 3 ;;
  esac
done

if [ "$BUILD" = 1 ]; then
  ./build.sh --autostress="$SECS" > /dev/null || { echo "ERROR: build failed (run ./build.sh --autostress=$SECS)"; exit 3; }
fi

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
[ -f "$OVMF_CODE" ] || { echo "OVMF not found (sudo apt install ovmf)"; exit 3; }

# Separate, empty disks – disk.img / nvme.img with your files stay untouched.
TMP_DISK="$ROOT/build-stress-disk.img"
TMP_NVME="$ROOT/build-stress-nvme.img"
rm -f "$TMP_DISK" "$TMP_NVME" "$ROOT/build/NvVars"
truncate -s 64M "$TMP_DISK"
truncate -s 64M "$TMP_NVME"
# Test USB stick (FAT32, read-only) – autostress reads from it
# during the stress test (usbd + ublk under load); without python3 – no USB stick.
TMP_USB="$ROOT/build-stress-usb.img"
rm -f "$TMP_USB"
USB_ARGS=()
if command -v python3 >/dev/null 2>&1 && python3 "$T/mkfat32.py" "$TMP_USB" "$ROOT/build/user/sh" 2>/dev/null; then
  USB_ARGS=(-drive if=none,id=usbtest,format=raw,file="$TMP_USB",readonly=on -device usb-storage,drive=usbtest)
fi

mkdir -p "$ROOT/logs"
LOG="$ROOT/logs/stress-qemu.log"
: > "$LOG"
# Boot + 5 s delay + stress + cleanup; headroom for slow TCG.
LIMIT=$(( SECS + 180 ))  # + ipcbench after the stress test
echo "Autostress in QEMU: $ACCEL, $SMP CPU, stress $SECS s (limit ${LIMIT} s)..."

qemu-system-x86_64 \
  -machine q35 -m 1G -smp "$SMP" "${ACCEL_ARGS[@]}" \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -device qemu-xhci,p2=8,p3=8 \
  -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on \
  -device usb-storage,drive=usbboot,bootindex=0 \
  "${USB_ARGS[@]}" \
  -drive file="$TMP_DISK",format=raw,if=none,id=vd0 \
  -device virtio-blk-pci,drive=vd0 \
  -drive file="$TMP_NVME",format=raw,if=none,id=nv0 \
  -device nvme,serial=desoos-stress,drive=nv0 \
  -device edu,addr=06 \
  -serial stdio -display none -no-reboot < /dev/null > "$LOG" 2>&1 &
QPID=$!

START=$(date +%s)
RESULT=2
while kill -0 "$QPID" 2>/dev/null; do
  # [RESULT] is the last line of autostress (after the ipcbench measurement).
  if grep -aqE "\[RESULT\].*pass=1" "$LOG"; then RESULT=0; break; fi
  if grep -aqE "\[RESULT\].*pass=0|\[AUTOSTRESS[^]]*\] FAIL" "$LOG"; then RESULT=1; sleep 1; break; fi
  if grep -aqE "PANIC|panicked" "$LOG"; then sleep 1; RESULT=1; break; fi
  if [ $(( $(date +%s) - START )) -gt "$LIMIT" ]; then RESULT=2; break; fi
  sleep 1
done
sleep 0.5
kill "$QPID" 2>/dev/null
wait "$QPID" 2>/dev/null
rm -f "$TMP_DISK" "$TMP_NVME" "$TMP_USB"

# Result: the autostress report (without the CPU table – that one is in the log).
sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' -e 's/^.*\[AUTOSTRESS[^]]*\]/[AUTOSTRESS]/' "$LOG" | grep -a "^\[AUTOSTRESS\]" \
  | grep -avE "^\[AUTOSTRESS\] +[0-9]+ +[0-9]+ " | sed 's/^\[AUTOSTRESS\] //'
sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' "$LOG" | grep -ao "\[RESULT\].*" | tail -n 1
case "$RESULT" in
  0) echo "== PASS ($(( $(date +%s) - START )) s, log: logs/stress-qemu.log)"; exit 0 ;;
  1) echo "== FAIL – last log lines:"; grep -aE "FAIL|PANIC|panicked|\[LOCK\]|\[WATCHDOG\]" "$LOG" | tail -n 15; exit 1 ;;
  *) echo "== TIMEOUT / hang – last log lines:"; tail -n 15 "$LOG"; exit 2 ;;
esac
