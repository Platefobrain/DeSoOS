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

# M16b: build/ trafia do QEMU jako pendrive USB TYLKO DO ODCZYTU (jak
# prawdziwy pendrive: DeSoOS nie ma sterownika USB, więc go nie widzi).
# Wcześniej był to dysk "fat:rw:" – OVMF zapisywał tam swoje NvVars, a QEMU
# (vvfat) potrafił przy tym uszkodzić build/EFI/BOOT/BOOTX64.EFI.
rm -f "$ROOT/build/NvVars"

LOG="$ROOT/test.log"
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
  -device qemu-xhci
  -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on
  -device usb-storage,drive=usbboot,bootindex=0
  -drive file="$TEST_DISK",format=raw,if=none,id=vd0
  -device virtio-blk-pci,drive=vd0
  -drive file="$TEST_NVME",format=raw,if=none,id=nv0
  -device nvme,serial=desoos-test,drive=nv0
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
  -fw_cfg name=opt/desoos/autotest,string=1
  -serial stdio -display none -no-reboot)

if [ "$VERBOSE" = 1 ]; then
  timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null 2>&1 | tee "$LOG"
  CODE=${PIPESTATUS[0]}
else
  timeout "$TIMEOUT" "${QEMU[@]}" < /dev/null > "$LOG" 2>&1
  CODE=$?
fi
rm -f "$TEST_DISK" "$TEST_NVME"
TIME=$(( $(date +%s) - START ))

PASSED=$(grep -c " PASS" "$LOG" || true)
SUMMARY=$(grep -a "Self-tests:" "$LOG" | tail -n1 | sed 's/^.*Self-tests: //')
echo "Log: test.log (${TIME} s, ${PASSED} testow PASS)"

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
