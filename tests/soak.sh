#!/usr/bin/env bash
# The long test: all workers at once for hours, checkpoints for leaks and DeSoFS
# (/bin/soak, see user/bin/soak.rs).  QEMU with the same devices as tests/test.sh; the
# boot self-tests are skipped (fw_cfg opt/desoos/phase = "soak <seconds> <seed>").
#
#   tests/soak.sh                      1 hour, KVM
#   DURATION=8h tests/soak.sh          for the night (s / m / h: 90s, 30m, 8h)
#   SEED=12345 tests/soak.sh           the same run again (the seed is always printed)
#   ACCEL=tcg tests/soak.sh            without KVM (slower)
#   SOAK_DISK=ram tests/soak.sh        DeSoFS on a RAM disk made by the soak (`desofs ramdisk`)
#                                      instead of the virtio disk – the way it runs on hardware
#   tests/soak.sh --no-build           without ./build.sh --selftest first
#
# Exit codes: 0 = PASS, 1 = FAIL (the soak reported an error), 2 = HANG (no heartbeat for
# 5 minutes, QEMU still running – stopped, monitor dump in the log), 3 = QEMU ended by
# itself (emulator crash / triple fault), 4 = the whole run took too long.
# The full log: logs/soak.log (SOAK_LOG=… elsewhere); the last 50 lines are shown at the end.
set -uo pipefail

T="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$T")"
cd "$ROOT"

BUILD=1
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 4 ;;
  esac
done

DURATION="${DURATION:-1h}"
case "$DURATION" in
  *h) SECS=$(( ${DURATION%h} * 3600 )) ;;
  *m) SECS=$(( ${DURATION%m} * 60 )) ;;
  *s) SECS=${DURATION%s} ;;
  *[!0-9]*|"") echo "DURATION: e.g. 90s, 30m, 8h (got: $DURATION)"; exit 4 ;;
  *) SECS=$DURATION ;;
esac
[ "$SECS" -ge 60 ] 2>/dev/null || { echo "DURATION: at least 60 s (got: $DURATION)"; exit 4; }
SEED="${SEED:-$(date +%s)}"
SOAK_DISK="${SOAK_DISK:-virtio}"
case "$SOAK_DISK" in
  virtio) PHASE_DISK="" ;;
  ram) PHASE_DISK=" ram" ;;
  *) echo "SOAK_DISK: virtio or ram (got: $SOAK_DISK)"; exit 4 ;;
esac
case "$SEED" in *[!0-9]*|"") echo "SEED: a number (got: $SEED)"; exit 4 ;; esac
SMP="${SMP:-4}"
ACCEL="${ACCEL:-kvm}"
case "$ACCEL" in
  kvm)
    [ -w /dev/kvm ] || { echo "ACCEL=kvm: no access to /dev/kvm (sudo usermod -aG kvm $USER, then log out) - or ACCEL=tcg"; exit 4; }
    ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: tcg or kvm (got: $ACCEL)"; exit 4 ;;
esac
# The whole run: the soak + boot + the final checkpoint; more is a hang somewhere.
TIMEOUT=$(( SECS + SECS / 10 + 900 ))
HANG_S=300

if ! python3 -c 'import socket; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 58082))' 2>/dev/null; then
  echo "ERROR: another test or QEMU is already running (host port 58082 is busy)."
  echo "Wait for it to finish, or stop it: pkill qemu-system-x86"
  exit 4
fi

if [ "$BUILD" = 1 ]; then
  ./build.sh --selftest || { echo "ERROR: build failed"; exit 4; }
fi

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
[ -f "$OVMF_CODE" ] || { echo "OVMF not found (sudo apt install ovmf)"; exit 4; }

# Own disk images (sparse) – tests/test.sh's and your disk.img stay untouched.
SOAK_IMG="$ROOT/build-soak-disk.img"
SOAK_NVME="$ROOT/build-soak-nvme.img"
SOAK_USB="$ROOT/build-soak-usb.img"
rm -f "$SOAK_IMG" "$SOAK_NVME" "$SOAK_USB"
truncate -s 512M "$SOAK_IMG"
truncate -s 64M "$SOAK_NVME"
python3 "$T/mkfat32.py" "$SOAK_USB" "$ROOT/build/user/sh" "$ROOT/build/user/usbd" "$ROOT/build/user/cat" || { echo "ERROR: mkfat32.py"; exit 4; }
rm -f "$ROOT/build/NvVars"

mkdir -p "$ROOT/logs"
LOG="${SOAK_LOG:-$ROOT/logs/soak.log}"
MON="${TMPDIR:-/tmp}/desoos-soak-monitor-$$.sock"
rm -f "$MON"
: > "$LOG"

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
  -blockdev driver=file,filename="$SOAK_USB",node-name=usbtestf,read-only=on
  -blockdev driver=raw,file=usbtestf,node-name=usbtest,read-only=on
  -device usb-storage,bus=xhci.0,port=3.2,drive=usbtest,id=hubdisk
  -monitor unix:"$MON",server=on,wait=off
  -drive file="$SOAK_IMG",format=raw,if=none,id=vd0
  -device virtio-blk-pci,drive=vd0
  -drive file="$SOAK_NVME",format=raw,if=none,id=nv0
  -device nvme,serial=desoos-test,drive=nv0
  -device edu,addr=06
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
  -fw_cfg name=opt/desoos/autotest,string=1
  -fw_cfg name=opt/desoos/phase,string="soak $SECS $SEED$PHASE_DISK"
  -serial stdio -display none -no-reboot)

echo "Soak in QEMU: ${SECS} s, SEED=$SEED ($ACCEL, $SMP CPU, $SOAK_DISK disk) - log: $LOG"
START=$(date +%s)
# Network servers on the host (as in tests/test.sh): DNS, HTTP (/big, 1 MiB), UDP echo.
python3 "$T/dns-stub.py" 53530 &
DNS_PID=$!
python3 "$T/http-stub.py" 58080 &
HTTP_PID=$!
python3 "$T/udp-stub.py" 58090 &
UDP_PID=$!

"${QEMU[@]}" < /dev/null > "$LOG" 2>&1 &
QPID=$!

# Watch: QEMU ended / no new line for HANG_S / the whole time ran out.
RESULT=""
LAST_SIZE=0
LAST_CHANGE=$(date +%s)
while kill -0 "$QPID" 2>/dev/null; do
  sleep 5
  NOW=$(date +%s)
  SIZE=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
  if [ "$SIZE" != "$LAST_SIZE" ]; then
    LAST_SIZE=$SIZE
    LAST_CHANGE=$NOW
  fi
  if [ $(( NOW - LAST_CHANGE )) -ge "$HANG_S" ]; then
    RESULT=hang
    break
  fi
  if [ $(( NOW - START )) -ge "$TIMEOUT" ]; then
    RESULT=timeout
    break
  fi
done

monitor() {
  python3 - "$MON" "$1" <<'EOF' 2>/dev/null
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.settimeout(2)
for cmd in sys.argv[2].split(";"):
    s.sendall((cmd + "\n").encode())
    time.sleep(0.5)
out = b""
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        out += d
except Exception:
    pass
sys.stdout.write(out.decode("latin-1"))
EOF
}

CODE=0
if [ -n "$RESULT" ]; then
  # Stopped by us: the CPU state from the monitor into the log, then QEMU goes.
  {
    echo "=== soak.sh: $RESULT - QEMU monitor dump ==="
    monitor "info status;info cpus;info registers -a"
  } >> "$LOG"
  kill "$QPID" 2>/dev/null
  sleep 1
  kill -9 "$QPID" 2>/dev/null
  wait "$QPID" 2>/dev/null
  CODE=$?
else
  wait "$QPID"
  CODE=$?
fi
kill "$DNS_PID" "$HTTP_PID" "$UDP_PID" 2>/dev/null
wait "$DNS_PID" "$HTTP_PID" "$UDP_PID" 2>/dev/null
rm -f "$SOAK_IMG" "$SOAK_NVME" "$SOAK_USB" "$MON"
TIME=$(( $(date +%s) - START ))

echo "--- last 50 lines of $LOG ---"
tail -n 50 "$LOG" | tr -d '\r'
echo "--- QEMU exit code $CODE, ${TIME} s ---"
VER=$(grep -a -m1 -o "DeSoOS v[0-9.]*" "$LOG" | head -n1 | sed 's/DeSoOS //')
grep -a "^\[RESULT-SOAK\]" "$LOG" | tail -n1 | tr -d '\r' | sed "s/\$/ ver=${VER:-?} accel=$ACCEL cpus=$SMP mem=512M wall_s=$TIME/" || true

case "$RESULT" in
  hang) echo "HANG - no new line for ${HANG_S} s (QEMU was still running; monitor dump in logs/soak.log)"; exit 2 ;;
  timeout) echo "TIMEOUT - the soak did not end within ${TIMEOUT} s"; exit 4 ;;
esac
case "$CODE" in
  33) echo "PASS - soak ${SECS} s, SEED=$SEED"; exit 0 ;;
  35) echo "FAIL - SEED=$SEED (repeat: SEED=$SEED DURATION=$DURATION tests/soak.sh)"
      grep -a -E "\[SOAK\] ERROR|FAIL|PANIC|\[EXC\]" "$LOG" | head -n 20 | tr -d '\r'
      exit 1 ;;
  *) echo "ERROR - QEMU ended by itself with code $CODE (crash / triple fault / reboot?)"; exit 3 ;;
esac
