#!/usr/bin/env bash
# Automated self-tests in QEMU – the result as the exit code.
#
#   tests/test.sh              build --selftest + tests (result: PASS / FAIL)
#   tests/test.sh --no-build   run only (e.g. after your own ./build.sh --selftest)
#   tests/test.sh --verbose    show the whole log live
#
# Exit codes: 0 = PASS, 1 = FAIL, 2 = timeout (hang),
#             3 = QEMU exited otherwise (e.g. triple fault / reboot).
# The log stays in logs/test.log.
set -uo pipefail

# Tests live in tests/, the rest of the project one directory up.
T="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$T")"
cd "$ROOT"

BUILD=1
VERBOSE=0
TIMEOUT="${TIMEOUT:-180}"
# Number of QEMU cores.  More virtual CPUs than host threads =
# long stalls (the host suspends the virtual CPU whose turn it is to take
# the Big Kernel Lock; the watchdog reports it) – on a weak host: SMP=2 ./test.sh
SMP="${SMP:-4}"
# QEMU accelerator.
#   ACCEL=tcg (default)   – emulation, multi-threaded (each virtual CPU
#                           in its own host thread – otherwise the Big Kernel Lock
#                           handed over "in turns" causes second-long stalls)
#   ACCEL=kvm             – hardware virtualization (Linux with /dev/kvm):
#                           real parallel hardware, native speed
ACCEL="${ACCEL:-tcg}"
case "$ACCEL" in
  kvm)
    [ -w /dev/kvm ] || { echo "ACCEL=kvm: no access to /dev/kvm (sudo usermod -aG kvm $USER, then log out)"; exit 3; }
    ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: tcg or kvm (got: $ACCEL)"; exit 3 ;;
esac
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --verbose|-v) VERBOSE=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 3 ;;
  esac
done

if [ "$BUILD" = 1 ]; then
  ./build.sh --selftest || { echo "ERROR: build failed"; exit 3; }
fi

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
[ -f "$OVMF_CODE" ] || { echo "OVMF not found (sudo apt install ovmf)"; exit 3; }

# A separate, empty test disk – disk.img with your files stays untouched.
TEST_DISK="$ROOT/build-test-disk.img"
rm -f "$TEST_DISK"
truncate -s 64M "$TEST_DISK"
# A separate, empty disk for the emulated NVMe (the tests write a GPT to it).
TEST_NVME="$ROOT/build-test-nvme.img"
rm -f "$TEST_NVME"
truncate -s 64M "$TEST_NVME"
# Test USB stick (MBR + FAT32, read-only in QEMU): a marker,
# 4 MiB of pattern and three programs from build/user (the test compares them with /bin).
TEST_USB="$ROOT/build-test-usb.img"
rm -f "$TEST_USB"
command -v python3 >/dev/null 2>&1 || { echo "python3 not found (needed for the test USB stick image)"; exit 3; }
python3 "$T/mkfat32.py" "$TEST_USB" "$ROOT/build/user/sh" "$ROOT/build/user/usbd" "$ROOT/build/user/cat" || { echo "ERROR: mkfat32.py"; exit 3; }

# build/ goes to QEMU as a READ-ONLY USB stick (like
# a real USB stick; usbd sees it as a read-only sdX disk).
# It used to be a "fat:rw:" disk – OVMF wrote its NvVars there, and QEMU
# (vvfat) could corrupt build/EFI/BOOT/BOOTX64.EFI in the process.
rm -f "$ROOT/build/NvVars"

mkdir -p "$ROOT/logs"
LOG="$ROOT/logs/test.log"
# QEMU monitor for hot-plugging (USB TEST 6/6): qemu-hotplug.py
# sends it the "[HOTPLUG] …" lines from the log (a hub with a mouse and the test USB stick).
MON="${TMPDIR:-/tmp}/desoos-monitor-$$.sock"
rm -f "$MON"
echo "Running self-tests in QEMU ($ACCEL, $SMP CPU, timeout ${TIMEOUT} s)..."
START=$(date +%s)

# -cpu max / host: NX, SMEP, RDTSCP etc. as on a modern processor (needed by the tests).
# -smp $SMP (default 4): several cores (SMP tests).
# fw_cfg opt/desoos/autotest = the kernel powers QEMU off by itself after the tests
# via isa-debug-exit (port 0xf4): PASS -> 33, FAIL -> 35.
QEMU=(qemu-system-x86_64
  -machine q35 -m 512M -smp "$SMP"
  "${ACCEL_ARGS[@]}"
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:58082-:8081 -device e1000e,netdev=net0,mac=52:54:00:12:34:56
  -device qemu-xhci,id=xhci,p2=8,p3=8
  -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on
  -device usb-storage,bus=xhci.0,port=1,drive=usbboot,bootindex=0
  -device usb-kbd,bus=xhci.0,port=2
  -device usb-hub,bus=xhci.0,port=3,id=hub1
  -device usb-mouse,bus=xhci.0,port=3.1
  -blockdev driver=file,filename="$TEST_USB",node-name=usbtestf,read-only=on
  -blockdev driver=raw,file=usbtestf,node-name=usbtest,read-only=on
  -device usb-storage,bus=xhci.0,port=3.2,drive=usbtest,id=hubdisk
  -monitor unix:"$MON",server=on,wait=off
  -drive file="$TEST_DISK",format=raw,if=none,id=vd0
  -device virtio-blk-pci,drive=vd0
  -drive file="$TEST_NVME",format=raw,if=none,id=nv0
  -device nvme,serial=desoos-test,drive=nv0
  -device edu,addr=06
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
  -fw_cfg name=opt/desoos/autotest,string=1
  -serial stdio -display none -no-reboot)

: > "$LOG"
python3 "$T/qemu-hotplug.py" "$LOG" "$MON" &
HOTPLUG_PID=$!
# DNS server for NET TEST (names under .desoos; the guest asks 10.0.2.2:53530).
python3 "$T/dns-stub.py" 53530 &
DNS_PID=$!
# HTTP server for NET TEST (TCP; the guest connects to 10.0.2.2:58080).
python3 "$T/http-stub.py" 58080 &
HTTP_PID=$!

if [ "$VERBOSE" = 1 ]; then
  timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null 2>&1 | tee "$LOG"
  CODE=${PIPESTATUS[0]}
else
  timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null > "$LOG" 2>&1
  CODE=$?
fi
kill "$HOTPLUG_PID" "$DNS_PID" "$HTTP_PID" 2>/dev/null
wait "$HOTPLUG_PID" "$DNS_PID" "$HTTP_PID" 2>/dev/null
rm -f "$TEST_DISK" "$TEST_NVME" "$TEST_USB" "$MON"
TIME=$(( $(date +%s) - START ))

PASSED=$(grep -c " PASS" "$LOG" || true)
SUMMARY=$(grep -a "Self-tests:" "$LOG" | tail -n1 | sed 's/^.*Self-tests: //')
echo "Log: logs/test.log (${TIME} s, ${PASSED} tests PASS)"
# Service benchmark (kernel vs user space) – the [RESULT-SVC] line from the SVC self-test.
grep -a "^\[RESULT-SVC\]" "$LOG" | tail -n1 || true
# USB controller (xHCI) and usbd – the [RESULT-USB] line from the USB self-test.
grep -a "^\[RESULT-USB\]" "$LOG" | tail -n1 || true

case "$CODE" in
  33)
    echo "PASS - ${SUMMARY}"
    exit 0 ;;
  35)
    echo "FAIL - ${SUMMARY:-kernel reported an error}"
    grep -a -E "FAIL|PANIC|\[EXC\]" "$LOG" | head -n 20
    exit 1 ;;
  124)
    echo "TIMEOUT - tests did not finish within ${TIMEOUT} s (hang?). Last lines:"
    tail -n 15 "$LOG"
    exit 2 ;;
  *)
    echo "ERROR - QEMU exited with code $CODE (triple fault / reboot / missing device?). Last lines:"
    tail -n 15 "$LOG"
    exit 3 ;;
esac
