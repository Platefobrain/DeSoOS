#!/usr/bin/env bash
# Automated self-tests in QEMU – the result as the exit code.
#
#   tests/test.sh              build --selftest + tests (result: PASS / FAIL)
#   tests/test.sh --no-build   run only (e.g. after your own ./build.sh --selftest)
#   tests/test.sh --verbose    show the whole log live
#   LOOP=nobkl:400 tests/test.sh   loop mode: the boot suites once, then only
#                              the named suite 400 times (stops at the first failure);
#                              suites: smp lock tlb alloc nobkl files ipc rights crypto desofs
#
# After a passing run QEMU starts a second time on the same test disk (fw_cfg
# opt/desoos/phase=restart): DeSoFS written by the first start must be mounted at /disk
# by itself and hold the same data (RESTART TEST part 2, [RESULT-FS]).  Not in loop mode.
# Then a short soak (2 min, tests/soak.sh – all workers at once, checkpoints): the soak
# itself keeps working ([RESULT-SOAK], log logs/test-soak.log).  Not in loop mode.
#
# Exit codes: 0 = PASS, 1 = FAIL, 2 = timeout (hang),
#             3 = QEMU exited otherwise (e.g. triple fault / reboot).
# The logs stay in logs/test.log and logs/test-restart.log.
set -uo pipefail

# Tests live in tests/, the rest of the project one directory up.
T="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$T")"
cd "$ROOT"

BUILD=1
VERBOSE=0
LOOP="${LOOP:-}"
# Loop mode takes longer – a larger default timeout (set TIMEOUT to change it).
if [ -n "$LOOP" ]; then TIMEOUT="${TIMEOUT:-3600}"; else TIMEOUT="${TIMEOUT:-240}"; fi
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
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 3 ;;
  esac
done

# Another test (or QEMU from run-qemu.sh) still running?  Both need host port 58082, and
# this script would rebuild build/ and replace the test disks under the running one.
# SO_REUSEADDR (as QEMU uses): connections of the previous run left in TIME_WAIT
# do not count, only a port somebody still listens on.
if ! python3 -c 'import socket; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 58082))' 2>/dev/null; then
  echo "ERROR: another test or QEMU is already running (host port 58082 is busy)."
  echo "Wait for it to finish, or stop it: pkill qemu-system-x86"
  exit 3
fi

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
echo "Running self-tests in QEMU ($ACCEL, $SMP CPU, timeout ${TIMEOUT} s${LOOP:+, loop $LOOP})..."
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
if [ -n "$LOOP" ]; then
  case "$LOOP" in
    *[!a-z0-9:]*|"") echo "LOOP: suite:rounds, e.g. LOOP=nobkl:400 (got: $LOOP)"; exit 3 ;;
  esac
  QEMU+=(-fw_cfg name=opt/desoos/loop,string="$LOOP")
fi

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

# Second start on the same test disk (only after a passing first one, not in loop mode).
LOG2="$ROOT/logs/test-restart.log"
: > "$LOG2"
CODE2=33
TIME2=0
if [ "$CODE" = 33 ] && [ -z "$LOOP" ]; then
  echo "Restarting QEMU on the same test disk (RESTART TEST part 2)..."
  START2=$(date +%s)
  QEMU+=(-fw_cfg name=opt/desoos/phase,string=restart)
  if [ "$VERBOSE" = 1 ]; then
    timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null 2>&1 | tee "$LOG2"
    CODE2=${PIPESTATUS[0]}
  else
    timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null > "$LOG2" 2>&1
    CODE2=$?
  fi
  TIME2=$(( $(date +%s) - START2 ))
fi
rm -f "$TEST_DISK" "$TEST_NVME" "$TEST_USB" "$MON"

# Short soak (only after two passing starts, not in loop mode).
LOG3="$ROOT/logs/test-soak.log"
: > "$LOG3"
CODE3=0
TIME3=0
SOAK_OK=""
if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ -z "$LOOP" ]; then
  echo "Short soak (2 min, tests/soak.sh)..."
  START3=$(date +%s)
  DURATION=2m ACCEL="$ACCEL" SMP="$SMP" SOAK_LOG="$LOG3" "$T/soak.sh" --no-build > "$ROOT/logs/test-soak.out" 2>&1
  CODE3=$?
  TIME3=$(( $(date +%s) - START3 ))
  [ "$CODE3" = 0 ] && SOAK_OK="; short soak: PASS"
fi
TIME=$(( $(date +%s) - START ))

PASSED=$(( $(grep -c " PASS" "$LOG" || true) + $(grep -c " PASS" "$LOG2" || true) + $(grep -c "^\[SOAK TEST\] .* PASS" "$LOG3" || true) ))
# The serial log ends lines with CR LF – the CR goes, or text printed after it overwrites the line.
SUMMARY=$(grep -a "Self-tests:" "$LOG" | tail -n1 | tr -d '\r' | sed 's/^.*Self-tests: //')
SUMMARY2=$(grep -a "Self-tests:" "$LOG2" | tail -n1 | tr -d '\r' | sed 's/^.*Self-tests: //')
echo "Log: logs/test.log + logs/test-restart.log + logs/test-soak.log (${TIME} s, restart ${TIME2} s, soak ${TIME3} s, ${PASSED} tests PASS)"
# Service benchmark (kernel vs user space) – the [RESULT-SVC] line from the SVC self-test.
grep -a "^\[RESULT-SVC\]" "$LOG" | tail -n1 || true
# USB controller (xHCI) and usbd – the [RESULT-USB] line from the USB self-test.
grep -a "^\[RESULT-USB\]" "$LOG" | tail -n1 || true
# The syscall rights table – the [RESULT-RIGHTS] line from RIGHTS TEST.
grep -a "^\[RESULT-RIGHTS\]" "$LOG" | tail -n1 || true
# DeSoCrypto – the [RESULT-CRYPTO] line from CRYPTO TEST.
grep -a "^\[RESULT-CRYPTO\]" "$LOG" | tail -n1 || true
# DeSoFS on /disk after the restart – the [RESULT-FS] line, with the QEMU configuration.
grep -a "^\[RESULT-FS\]" "$LOG2" | tail -n1 | tr -d '\r' | sed "s/\$/ accel=$ACCEL cpus=$SMP mem=512M restart_s=$TIME2/" || true
# The short soak – the [RESULT-SOAK] line (tests/soak.sh adds the QEMU configuration).
grep -a "^\[RESULT-SOAK\]" "$ROOT/logs/test-soak.out" 2>/dev/null | tail -n1 || true
# Loop mode – rounds passed and round times.
grep -a "^\[RESULT-LOOP\]" "$LOG" | tail -n1 || true
grep -a "^\[LOOP\] .*FAILED" "$LOG" | tail -n1 || true

if [ "$CODE" = 33 ] && [ "$CODE2" != 33 ]; then
  case "$CODE2" in
    35) echo "FAIL - restart: ${SUMMARY2:-kernel reported an error}"
        grep -a -E "FAIL|PANIC|\[EXC\]" "$LOG2" | head -n 20
        exit 1 ;;
    124) echo "TIMEOUT - the restart did not finish within ${TIMEOUT} s. Last lines:"
        tail -n 15 "$LOG2"
        exit 2 ;;
    *) echo "ERROR - restart: QEMU exited with code $CODE2. Last lines:"
        tail -n 15 "$LOG2"
        exit 3 ;;
  esac
fi

if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ "$CODE3" != 0 ]; then
  echo "FAIL - short soak: tests/soak.sh ended with code $CODE3 (1 FAIL, 2 HANG, 3 QEMU, 4 timeout). Its summary:"
  tail -n 25 "$ROOT/logs/test-soak.out"
  exit 1
fi

case "$CODE" in
  33)
    if [ -n "$SUMMARY2" ]; then
      echo "PASS - ${SUMMARY}; restart: ${SUMMARY2}${SOAK_OK}"
    else
      echo "PASS - ${SUMMARY}"
    fi
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
