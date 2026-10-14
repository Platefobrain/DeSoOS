#!/usr/bin/env bash
# M11: automatyczne samotesty w QEMU – wynik jako kod wyjścia.
#
#   ./test.sh              build --selftest + testy (wynik: PASS / FAIL)
#   ./test.sh --no-build   tylko uruchom (np. po własnym ./build.sh --selftest)
#   ./test.sh --verbose    pokaż cały log na bieżąco
#
# Kody wyjścia: 0 = PASS, 1 = FAIL, 2 = timeout (zawieszenie),
#               3 = QEMU skończył się inaczej (np. triple fault / reboot).
# Log zostaje w test.log.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

BUILD=1
VERBOSE=0
TIMEOUT="${TIMEOUT:-180}"
# M17a: liczba rdzeni QEMU.  Więcej wirtualnych CPU niż wątków hosta =
# długie przestoje (host wstrzymuje wirtualny CPU, na którego kolej czeka
# Big Kernel Lock; watchdog to zgłasza) – na słabym hoście: SMP=2 ./test.sh
SMP="${SMP:-4}"
# M17a: akcelerator QEMU.
#   ACCEL=tcg (domyślnie) – emulacja, wielowątkowa (każdy wirtualny CPU
#                           osobnym wątkiem hosta – inaczej Big Kernel Lock
#                           przekazywany "po kolei" daje sekundowe przestoje)
#   ACCEL=kvm             – wirtualizacja sprzętowa (Linux z /dev/kvm):
#                           prawdziwy równoległy sprzęt, natywna szybkość
ACCEL="${ACCEL:-tcg}"
case "$ACCEL" in
  kvm)
    [ -w /dev/kvm ] || { echo "ACCEL=kvm: brak dostępu do /dev/kvm (sudo usermod -aG kvm $USER, potem wyloguj się)"; exit 3; }
    ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: tcg albo kvm (jest: $ACCEL)"; exit 3 ;;
esac
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --verbose|-v) VERBOSE=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Nieznana opcja: $arg"; exit 3 ;;
  esac
done

if [ "$BUILD" = 1 ]; then
  ./build.sh --selftest || { echo "BLAD: build nie powiodl sie"; exit 3; }
fi

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
[ -f "$OVMF_CODE" ] || { echo "Nie znaleziono OVMF (sudo apt install ovmf)"; exit 3; }

# Osobny, pusty dysk testowy – disk.img z Twoimi plikami zostaje nietknięty.
TEST_DISK="$ROOT/build-test-disk.img"
rm -f "$TEST_DISK"
truncate -s 64M "$TEST_DISK"
# M16b: osobny, pusty dysk dla emulowanego NVMe (testy zapisują na nim GPT).
TEST_NVME="$ROOT/build-test-nvme.img"
rm -f "$TEST_NVME"
truncate -s 64M "$TEST_NVME"
# M20.f: testowy pendrive (MBR + FAT32, tylko do odczytu w QEMU): znacznik,
# 4 MiB wzoru i trzy programy z build/user (test porównuje je z /bin).
TEST_USB="$ROOT/build-test-usb.img"
rm -f "$TEST_USB"
command -v python3 >/dev/null 2>&1 || { echo "Brak python3 (potrzebny do obrazu testowego pendrive'a)"; exit 3; }
python3 "$ROOT/mkfat32.py" "$TEST_USB" "$ROOT/build/user/sh" "$ROOT/build/user/usbd" "$ROOT/build/user/cat" || { echo "BLAD: mkfat32.py"; exit 3; }

# M16b: build/ trafia do QEMU jako pendrive USB TYLKO DO ODCZYTU (jak
# prawdziwy pendrive; od M20.f usbd widzi go jako dysk sdX tylko do odczytu).
# Wcześniej był to dysk "fat:rw:" – OVMF zapisywał tam swoje NvVars, a QEMU
# (vvfat) potrafił przy tym uszkodzić build/EFI/BOOT/BOOTX64.EFI.
rm -f "$ROOT/build/NvVars"

LOG="$ROOT/test.log"
# M20.d: monitor QEMU dla podłączania w locie (USB TEST 6/6): qemu-hotplug.py
# wysyła do niego linie „[HOTPLUG] …” z logu (hub z myszą i testowym pendrive'em).
MON="${TMPDIR:-/tmp}/desoos-monitor-$$.sock"
rm -f "$MON"
echo "Uruchamiam samotesty w QEMU ($ACCEL, $SMP CPU, timeout ${TIMEOUT} s)..."
START=$(date +%s)

# -cpu max / host: NX, SMEP, RDTSCP itd. jak na nowym procesorze (testy M13a).
# -smp $SMP (domyślnie 4): M17 – kilka rdzeni (testy SMP).
# fw_cfg opt/desoos/autotest = kernel po testach sam wyłącza QEMU
# przez isa-debug-exit (port 0xf4): PASS -> 33, FAIL -> 35.
QEMU=(qemu-system-x86_64
  -machine q35 -m 512M -smp "$SMP"
  "${ACCEL_ARGS[@]}"
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
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
python3 "$ROOT/qemu-hotplug.py" "$LOG" "$MON" &
HOTPLUG_PID=$!

if [ "$VERBOSE" = 1 ]; then
  timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null 2>&1 | tee "$LOG"
  CODE=${PIPESTATUS[0]}
else
  timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null > "$LOG" 2>&1
  CODE=$?
fi
kill "$HOTPLUG_PID" 2>/dev/null
wait "$HOTPLUG_PID" 2>/dev/null
rm -f "$TEST_DISK" "$TEST_NVME" "$TEST_USB" "$MON"
TIME=$(( $(date +%s) - START ))

PASSED=$(grep -c " PASS" "$LOG" || true)
SUMMARY=$(grep -a "Self-tests:" "$LOG" | tail -n1 | sed 's/^.*Self-tests: //')
echo "Log: test.log (${TIME} s, ${PASSED} testow PASS)"
# M19.h: pomiar usług (jądro vs user space) – linia [RESULT-SVC] z samotestu SVC.
grep -a "^\[RESULT-SVC\]" "$LOG" | tail -n1 || true
# M20: kontroler USB (xHCI) i usbd – linia [RESULT-USB] z samotestu USB.
grep -a "^\[RESULT-USB\]" "$LOG" | tail -n1 || true

case "$CODE" in
  33)
    echo "PASS - ${SUMMARY}"
    exit 0 ;;
  35)
    echo "FAIL - ${SUMMARY:-kernel zglosil blad}"
    grep -a -E "FAIL|PANIC|\[EXC\]" "$LOG" | head -n 20
    exit 1 ;;
  124)
    echo "TIMEOUT - testy nie skonczyly sie w ${TIMEOUT} s (zawieszenie?). Ostatnie linie:"
    tail -n 15 "$LOG"
    exit 2 ;;
  *)
    echo "BLAD - QEMU zakonczyl sie kodem $CODE (triple fault / reboot / brak urzadzenia?). Ostatnie linie:"
    tail -n 15 "$LOG"
    exit 3 ;;
esac
