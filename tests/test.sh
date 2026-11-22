#!/usr/bin/env bash
# Automated self-tests in QEMU – the result as the exit code.
#
#   tests/test.sh              build --selftest + tests (result: PASS / FAIL)
#   tests/test.sh --no-build   run only (e.g. after your own ./build.sh --selftest)
#   tests/test.sh --verbose    show the whole log live
#   LOOP=nobkl:400 tests/test.sh   loop mode: the boot suites once, then only
#                              the named suite 400 times (stops at the first failure);
#                              suites: smp lock tlb alloc nobkl files ipc rights abi startup crypto rng certs desofs
#
# After a passing run QEMU starts a second time on the same test disk (fw_cfg
# opt/deso/phase=restart): DeSoFS written by the first start must be mounted at /disk
# by itself and hold the same data (RESTART TEST part 2, [RESULT-FS]).  Then a third start
# without the virtio and NVMe disks (opt/deso/phase=usbrestart): the writable USB stick the
# first start formatted must become /disk by itself, with its last known good time (USB RESTART
# TEST, logs/test-usbrestart.log).  Then two starts from an image made by tools/mkusb.py – the
# code of make-usb.sh --with-disk – with nothing else attached (phases onestick1 / onestick2):
# UEFI boots BOOTX64.EFI from the image's ESP, /usb0 = its ESP read-only, /disk = its "DeSo OS
# system" partition read-write; the second start finds the first one's file and LKG, and the ESP
# is the same byte for byte afterwards (ONE STICK TEST, logs/test-onestick.log).  Not in loop mode.
# Then a short soak (2 min, tests/soak.sh on a RAM disk – all workers at once, checkpoints): the soak
# itself keeps working ([RESULT-SOAK], log logs/test-soak.log).  Not in loop mode.
#
# Exit codes: 0 = PASS, 1 = FAIL, 2 = timeout (hang),
#             3 = QEMU exited otherwise (e.g. triple fault / reboot), or a host test
#                 server could not get its ports.
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
if [ -n "$LOOP" ]; then TIMEOUT="${TIMEOUT:-3600}"; else TIMEOUT="${TIMEOUT:-600}"; fi
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

# The ABI (abi/abi.toml, docs/abi/README.md) on the host, before anything is built: the locks,
# the description, the generator, the code against the description and the mutations
# (tools/abigen.py --test, logs/test-abi.log).  The kernel's half is ABI TEST in QEMU.
mkdir -p "$ROOT/logs"
LOG_ABI="$ROOT/logs/test-abi.log"
if ! python3 tools/abigen.py --test > "$LOG_ABI" 2>&1; then
  grep -a -E "FAIL|NOT CAUGHT|^    " "$LOG_ABI" | head -n 30
  echo "FAIL - ABI host test (logs/test-abi.log)"
  exit 1
fi
# The names: "deso" in every name, "DeSo OS" for the project – the old name stays only
# in the history (CHANGELOG.md, docs/RELEASE.md), in lines marked "fixed test data" (bytes signed long ago)
# and in local files that are not part of the tree.
OLD_NAME=$(find . \( -path ./build -o -path ./logs -o -path ./ab -o -path ./drivers -o -path ./.git -o -name target \) -prune \
  -o -type f ! -name CHANGELOG.md ! -name RELEASE.md ! -name ab-usb.sh ! -name .build-local.sh ! -name .run-local.sh \
  ! -name '*.img' -print0 | xargs -0 grep -IiH "deso[o]s" 2>/dev/null | grep -v "fixed test data" | cut -d: -f1 | sort -u || true)
if [ -n "$OLD_NAME" ]; then
  echo "FAIL - the old name is still used in: $OLD_NAME"
  exit 1
fi
ABI_HOST=$(grep -ac "^\[ABI HOST TEST\] [0-9]/5 .* PASS" "$LOG_ABI" || true)

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
# Writable test USB stick (USB WRITE TEST): GPT with an ESP and a "DeSo system" partition,
# the only kind of partition DeSo OS ever writes on a USB disk.  A fresh one every run; a
# -blockdev node (not -drive) so that it survives device_del and can be plugged back;
# share-rw: a stick unplugged in the middle of a write may keep its node for a moment.
TEST_USBW="$ROOT/build-test-usbw.img"
rm -f "$TEST_USBW"
python3 "$T/mkgpt.py" "$TEST_USBW" 64 > /dev/null || { echo "ERROR: mkgpt.py"; exit 3; }

# build/ goes to QEMU as a READ-ONLY USB stick (like
# a real USB stick; usbd sees it as a read-only sdX disk).
# It used to be a "fat:rw:" disk – OVMF wrote its NvVars there, and QEMU
# (vvfat) could corrupt build/EFI/BOOT/BOOTX64.EFI in the process.
rm -f "$ROOT/build/NvVars"

mkdir -p "$ROOT/logs"
LOG="$ROOT/logs/test.log"
# QEMU monitor for hot-plugging (USB TEST 6/6): qemu-hotplug.py
# sends it the "[HOTPLUG] …" lines from the log (a hub with a mouse and the test USB stick).
MON="${TMPDIR:-/tmp}/deso-monitor-$$.sock"
rm -f "$MON"
START=$(date +%s)

# -cpu max / host: NX, SMEP, RDTSCP etc. as on a modern processor (needed by the tests).
# -smp $SMP (default 4): several cores (SMP tests).
# fw_cfg opt/deso/autotest = the kernel powers QEMU off by itself after the tests
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
  -blockdev driver=file,filename="$TEST_USBW",node-name=usbwf
  -blockdev driver=raw,file=usbwf,node-name=usbw
  -device usb-storage,bus=xhci.0,port=4,drive=usbw,id=usbw,share-rw=on
  -monitor unix:"$MON",server=on,wait=off
  -drive file="$TEST_DISK",format=raw,if=none,id=vd0
  -device virtio-blk-pci,drive=vd0
  -drive file="$TEST_NVME",format=raw,if=none,id=nv0
  -device nvme,serial=deso-test,drive=nv0
  -device edu,addr=06
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
  -fw_cfg name=opt/deso/autotest,string=1
  -serial stdio -display none -no-reboot)
if [ -n "$LOOP" ]; then
  case "$LOOP" in
    *[!a-z0-9:]*|"") echo "LOOP: suite:rounds, e.g. LOOP=nobkl:400 (got: $LOOP)"; exit 3 ;;
  esac
  QEMU+=(-fw_cfg name=opt/deso/loop,string="$LOOP")
fi

: > "$LOG"
# Each host server creates $STUB_READY/<name> once all its ports are bound (tests/stubnet.py);
# QEMU starts only after all of them have.
STUB_READY=$(mktemp -d)
export STUB_READY
python3 "$T/qemu-hotplug.py" "$LOG" "$MON" &
HOTPLUG_PID=$!
# DNS server for NET TEST (names under .deso; the guest asks 10.0.2.2:53530).
python3 "$T/dns-stub.py" 53530 &
DNS_PID=$!
# HTTP server for NET TEST (TCP; the guest connects to 10.0.2.2:58080).
python3 "$T/http-stub.py" 58080 &
HTTP_PID=$!
# UDP echo server for NET TEST (the guest sends to 10.0.2.2:58090).
python3 "$T/udp-stub.py" 58090 &
UDP_PID=$!
# NTP servers for NTP TEST (ntp.deso = 10.0.2.2, ports 58123-58154).
python3 "$T/ntp-stub.py" 58123 &
NTP_PID=$!
# HTTPS servers for TLS TEST (tls.deso = 10.0.2.2, ports 58443-58470; tests/tls/).
python3 "$T/tls-stub.py" 58443 &
TLS_PID=$!
# rustls test server for TLS TEST (exporter and ALPN against an independent TLS 1.3;
# ports 58500-58502), NTP TEST (NTS, 58510-58574) and NTS TEST (the time service,
# 58600-58644).  Built here on the host (tests/nts-server, its own Cargo.lock; the
# first build downloads its crates from crates.io).
if ! cargo build --release --quiet --manifest-path "$T/nts-server/Cargo.toml"; then
  echo "ERROR: tests/nts-server did not build (needs cargo and, the first time, crates.io)."
  kill "$HOTPLUG_PID" "$DNS_PID" "$HTTP_PID" "$UDP_PID" "$NTP_PID" "$TLS_PID" 2>/dev/null
  rm -rf "$STUB_READY"
  exit 1
fi
"$T/nts-server/target/release/nts-server" "$T/tls" 58500 &
RUSTLS_PID=$!
SERVER_PIDS=("$HOTPLUG_PID" "$DNS_PID" "$HTTP_PID" "$UDP_PID" "$NTP_PID" "$TLS_PID" "$RUSTLS_PID")

# Wait (at most 10 s; a busy port is retried 5 s) until every server is listening.  One
# that cannot get its ports ends the run here, with who holds them, instead of tests
# failing in QEMU minutes later.
STUB_NAMES=(dns http udp ntp tls nts)
STUB_PIDS=("$DNS_PID" "$HTTP_PID" "$UDP_PID" "$NTP_PID" "$TLS_PID" "$RUSTLS_PID")
MISSING=""
for _ in $(seq 100); do
  MISSING=""
  DEAD=""
  for i in "${!STUB_NAMES[@]}"; do
    if [ ! -e "$STUB_READY/${STUB_NAMES[$i]}" ]; then
      MISSING="$MISSING ${STUB_NAMES[$i]}"
      kill -0 "${STUB_PIDS[$i]}" 2>/dev/null || DEAD=1
    fi
  done
  # Done, or a server already gave up (it will never become ready).
  [ -z "$MISSING" ] || [ -n "$DEAD" ] && break
  sleep 0.1
done
if [ -n "$MISSING" ]; then
  echo "ERROR: host test servers not listening:$MISSING (a port is held by another program)."
  echo "Sockets on the test ports (53530, 58080, 58090, 58123-58154, 58443-58644):"
  command -v ss > /dev/null || echo "(ss not found - install iproute2 to see them)"
  ss -tuanp 2>/dev/null | grep -E '127\.0\.0\.1:(53530|58080|58090|581[2-5][0-9]|58[4-6][0-9][0-9])[[:space:]]' || true
  kill "${SERVER_PIDS[@]}" 2>/dev/null
  wait "${SERVER_PIDS[@]}" 2>/dev/null
  rm -rf "$STUB_READY" "$TEST_DISK" "$TEST_NVME" "$TEST_USB" "$TEST_USBW" "$MON"
  exit 3
fi
rm -rf "$STUB_READY"
unset STUB_READY   # tests/soak.sh (the short soak below) makes its own

echo "Running self-tests in QEMU ($ACCEL, $SMP CPU, timeout ${TIMEOUT} s${LOOP:+, loop $LOOP})..."
if [ "$VERBOSE" = 1 ]; then
  timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null 2>&1 | tee "$LOG"
  CODE=${PIPESTATUS[0]}
else
  timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null > "$LOG" 2>&1
  CODE=$?
fi
kill "${SERVER_PIDS[@]}" 2>/dev/null
wait "${SERVER_PIDS[@]}" 2>/dev/null

# The first start's QEMU command, for the third start below.
QEMU_BASE=("${QEMU[@]}")

# Second start on the same test disk (only after a passing first one, not in loop mode).
LOG2="$ROOT/logs/test-restart.log"
: > "$LOG2"
CODE2=33
TIME2=0
if [ "$CODE" = 33 ] && [ -z "$LOOP" ]; then
  echo "Restarting QEMU on the same test disk (RESTART TEST part 2)..."
  START2=$(date +%s)
  QEMU+=(-fw_cfg name=opt/deso/phase,string=restart)
  if [ "$VERBOSE" = 1 ]; then
    timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null 2>&1 | tee "$LOG2"
    CODE2=${PIPESTATUS[0]}
  else
    timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null > "$LOG2" 2>&1
    CODE2=$?
  fi
  TIME2=$(( $(date +%s) - START2 ))
fi

# Third start (only after two passing ones, not in loop mode): QEMU without the virtio and NVMe
# disks – no internal disk, so the writable USB stick the first start left formatted (USB DISK
# TEST 2/2) must become /disk by itself, with its last known good time (USB RESTART TEST).
LOG4="$ROOT/logs/test-usbrestart.log"
: > "$LOG4"
CODE4=33
TIME4=0
if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ -z "$LOOP" ]; then
  echo "Third start: only the USB sticks, no virtio / NVMe (USB RESTART TEST)..."
  START4=$(date +%s)
  QEMU3=()
  skip=0
  for a in "${QEMU_BASE[@]}"; do
    if [ "$skip" = 1 ]; then skip=0; continue; fi
    case "$a" in
      file="$TEST_DISK"*|file="$TEST_NVME"*|virtio-blk-pci*|nvme,*) unset 'QEMU3[${#QEMU3[@]}-1]'; continue ;;
    esac
    QEMU3+=("$a")
  done
  QEMU3+=(-fw_cfg name=opt/deso/phase,string=usbrestart)
  if [ "$VERBOSE" = 1 ]; then
    timeout "$TIMEOUT" "${QEMU3[@]}" < /dev/null 2>&1 | tee "$LOG4"
    CODE4=${PIPESTATUS[0]}
  else
    timeout "$TIMEOUT" "${QEMU3[@]}" < /dev/null > "$LOG4" 2>&1
    CODE4=$?
  fi
  TIME4=$(( $(date +%s) - START4 ))
fi
rm -f "$TEST_DISK" "$TEST_NVME" "$TEST_USB" "$TEST_USBW" "$MON"

# Fourth and fifth start (after three passing ones, not in loop mode): from a stick image made by
# tools/mkusb.py (make-usb.sh --with-disk) – the only disk, the boot disk (ONE STICK TEST).
LOG5="$ROOT/logs/test-onestick.log"
: > "$LOG5"
CODE5=33
TIME5=0
ONE_IMG="$ROOT/build-test-onestick.img"
if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ "$CODE4" = 33 ] && [ -z "$LOOP" ]; then
  echo "Fourth and fifth start: from a make-usb.sh --with-disk image only (ONE STICK TEST)..."
  START5=$(date +%s)
  rm -f "$ONE_IMG"
  esp_sum() { dd if="$ONE_IMG" bs=512 skip=2048 count=262144 status=none | sha256sum | cut -d' ' -f1; }
  if ! python3 "$ROOT/tools/mkusb.py" --image "$ONE_IMG" --size-mib 256 --efi "$ROOT/build/EFI/BOOT/BOOTX64.EFI" >> "$LOG5" 2>&1; then
    echo "[ONE STICK TEST] FAIL: tools/mkusb.py could not make the image" >> "$LOG5"
    CODE5=35
  fi
  ESP_BEFORE=$(esp_sum)
  for phase in onestick1 onestick2; do
    [ "$CODE5" = 33 ] || break
    QEMU5=(qemu-system-x86_64 -machine q35 -m 512M -smp "$SMP" "${ACCEL_ARGS[@]}"
      -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
      -device qemu-xhci,id=xhci
      -drive if=none,id=onestick,format=raw,file="$ONE_IMG"
      -device usb-storage,bus=xhci.0,port=1,drive=onestick,bootindex=0
      -device isa-debug-exit,iobase=0xf4,iosize=0x04
      -fw_cfg name=opt/deso/autotest,string=1
      -fw_cfg name=opt/deso/phase,string=$phase
      -serial stdio -display none -no-reboot)
    if [ "$VERBOSE" = 1 ]; then
      timeout "$TIMEOUT" "${QEMU5[@]}" < /dev/null 2>&1 | tee -a "$LOG5"
      CODE5=${PIPESTATUS[0]}
    else
      timeout "$TIMEOUT" "${QEMU5[@]}" < /dev/null >> "$LOG5" 2>&1
      CODE5=$?
    fi
  done
  if [ "$CODE5" = 33 ] && [ "$(esp_sum)" != "$ESP_BEFORE" ]; then
    echo "[ONE STICK TEST] FAIL: the ESP of the image changed (DeSo OS must never write it)" >> "$LOG5"
    CODE5=35
  fi
  rm -f "$ONE_IMG"
  TIME5=$(( $(date +%s) - START5 ))
fi

# Short soak (only after two passing starts, not in loop mode).
LOG3="$ROOT/logs/test-soak.log"
: > "$LOG3"
# Also the soak's summary: a run without the soak must not show the previous run's [RESULT-SOAK].
: > "$ROOT/logs/test-soak.out"
CODE3=0
TIME3=0
SOAK_OK=""
if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ "$CODE4" = 33 ] && [ "$CODE5" = 33 ] && [ -z "$LOOP" ]; then
  echo "Short soak (2 min, tests/soak.sh)..."
  START3=$(date +%s)
  DURATION=2m SOAK_DISK=ram ACCEL="$ACCEL" SMP="$SMP" SOAK_LOG="$LOG3" "$T/soak.sh" --no-build > "$ROOT/logs/test-soak.out" 2>&1
  CODE3=$?
  TIME3=$(( $(date +%s) - START3 ))
  [ "$CODE3" = 0 ] && SOAK_OK="; short soak: PASS"
fi
TIME=$(( $(date +%s) - START ))

PASSED=$(( ABI_HOST + $(grep -c " PASS" "$LOG" || true) + $(grep -c " PASS" "$LOG2" || true) + $(grep -c " PASS" "$LOG4" || true) + $(grep -c " PASS" "$LOG5" || true) + $(grep -c "^\[SOAK TEST\] .* PASS" "$LOG3" || true) ))
# The serial log ends lines with CR LF – the CR goes, or text printed after it overwrites the line.
SUMMARY=$(grep -a "Self-tests:" "$LOG" | tail -n1 | tr -d '\r' | sed 's/^.*Self-tests: //')
SUMMARY2=$(grep -a "Self-tests:" "$LOG2" | tail -n1 | tr -d '\r' | sed 's/^.*Self-tests: //')
SUMMARY4=$(grep -a "Self-tests:" "$LOG4" | tail -n1 | tr -d '\r' | sed 's/^.*Self-tests: //')
ONE_PASS=$(grep -ac "^\[ONE STICK TEST\] .* PASS" "$LOG5" || true)
echo "Log: logs/test-abi.log + logs/test.log + logs/test-restart.log + logs/test-usbrestart.log + logs/test-onestick.log + logs/test-soak.log (${TIME} s, restart ${TIME2} s, USB restart ${TIME4} s, one stick ${TIME5} s, soak ${TIME3} s, ${PASSED} tests PASS)"
# Service benchmark (kernel vs user space) – the [RESULT-SVC] line from the SVC self-test.
grep -a "^\[RESULT-SVC\]" "$LOG" | tail -n1 || true
# USB controller (xHCI) and usbd – the [RESULT-USB] line from the USB self-test.
grep -a "^\[RESULT-USB\]" "$LOG" | tail -n1 || true
# The syscall rights table – the [RESULT-RIGHTS] line from RIGHTS TEST.
grep -a "^\[RESULT-RIGHTS\]" "$LOG" | tail -n1 || true
# DeSoCrypto – the [RESULT-CRYPTO] line from CRYPTO TEST.
grep -a "^\[RESULT-CRYPTO\]" "$LOG" | tail -n1 || true
# The random number generator – the [RESULT-RNG] line from RNG TEST.
grep -a "^\[RESULT-RNG\]" "$LOG" | tail -n1 || true
# DeSoTLS – the [RESULT-CERTS] line from CERT TEST, [RESULT-TLS] from TLS TEST.
grep -a "^\[RESULT-CERTS\]" "$LOG" | tail -n1 || true
grep -a "^\[RESULT-TLS\]" "$LOG" | tail -n1 || true
# NTP – the [RESULT-NTP] line from NTP TEST.
grep -a "^\[RESULT-NTP\]" "$LOG" | tail -n1 || true
# DeSoFS on /disk after the restart – the [RESULT-FS] line, with the QEMU configuration.
grep -a "^\[RESULT-FS\]" "$LOG2" | tail -n1 | tr -d '\r' | sed "s/\$/ accel=$ACCEL cpus=$SMP mem=512M restart_s=$TIME2/" || true
# Where the DeSoFS time goes per benchmark phase (I/O, SHA-256, writes, both flushes, commits).
grep -a "^\[RESULT-FS-PROF\]" "$LOG2" | tr -d '\r' || true
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

if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ "$CODE4" != 33 ]; then
  case "$CODE4" in
    35) echo "FAIL - USB restart: ${SUMMARY4:-kernel reported an error}"
        grep -a -E "FAIL|PANIC|\[EXC\]" "$LOG4" | head -n 20
        exit 1 ;;
    124) echo "TIMEOUT - the USB restart did not finish within ${TIMEOUT} s. Last lines:"
        tail -n 15 "$LOG4"
        exit 2 ;;
    *) echo "ERROR - USB restart: QEMU exited with code $CODE4. Last lines:"
        tail -n 15 "$LOG4"
        exit 3 ;;
  esac
fi

if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ "$CODE4" = 33 ] && [ "$CODE5" != 33 ]; then
  case "$CODE5" in
    35) echo "FAIL - one stick:"
        grep -a -E "FAIL|PANIC|\[EXC\]|ERROR" "$LOG5" | head -n 20
        exit 1 ;;
    124) echo "TIMEOUT - a start from the stick image did not finish within ${TIMEOUT} s. Last lines:"
        tail -n 15 "$LOG5"
        exit 2 ;;
    *) echo "ERROR - one stick: QEMU exited with code $CODE5 (did UEFI boot the image?). Last lines:"
        tail -n 15 "$LOG5"
        exit 3 ;;
  esac
fi

# The random number generator: the first bytes after the restart differ from the first start's.
RNG1=$(grep -a -m1 "^\[RNG\] boot sample" "$LOG" | tr -d '\r')
RNG2=$(grep -a -m1 "^\[RNG\] boot sample" "$LOG2" | tr -d '\r')
if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ -z "$LOOP" ] && { [ -z "$RNG1" ] || [ -z "$RNG2" ] || [ "$RNG1" = "$RNG2" ]; }; then
  echo "FAIL - restart: the random number generator's first bytes did not change between the two starts (\"$RNG1\" / \"$RNG2\")"
  exit 1
fi

if [ "$CODE" = 33 ] && [ "$CODE2" = 33 ] && [ "$CODE3" != 0 ]; then
  echo "FAIL - short soak: tests/soak.sh ended with code $CODE3 (1 FAIL, 2 HANG, 3 QEMU, 4 timeout). Its summary:"
  tail -n 25 "$ROOT/logs/test-soak.out"
  exit 1
fi

case "$CODE" in
  33)
    if [ -n "$SUMMARY2" ]; then
      echo "PASS - ${SUMMARY}; ABI host: ${ABI_HOST}/5; restart: ${SUMMARY2}; USB restart: ${SUMMARY4}; one stick: ${ONE_PASS}/2 starts PASSED${SOAK_OK}"
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
