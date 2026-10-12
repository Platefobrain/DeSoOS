#!/usr/bin/env bash
# M17a: autostress w QEMU – ten sam test co na Legionie (DESOOS_AUTOSTRESS),
# ale na tym komputerze, przed nagraniem pendrive'a.
#
#   ./stress-qemu.sh              build z autostress + QEMU, wynik na ekranie
#   ./stress-qemu.sh --no-build   tylko uruchom (po własnym ./build.sh --autostress=S)
#
# Zmienne:
#   SECS=60      długość stressu w s (jak na Legionie; domyślnie 60)
#   SMP=N        liczba CPU QEMU (domyślnie: rdzenie tego komputera, najwyżej 16)
#   ACCEL=kvm    kvm (domyślnie, jeśli jest /dev/kvm) albo tcg
#
# Kody wyjścia: 0 = PASS, 1 = FAIL, 2 = timeout / zawieszenie, 3 = błąd.
# Log: stress-qemu.log.  Uwaga: build/ zawiera potem kernel z autostress –
# make-usb.sh i test.sh i tak budują własny.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

SECS="${SECS:-60}"
CORES="$(nproc 2>/dev/null || echo 4)"
SMP="${SMP:-$(( CORES > 16 ? 16 : CORES ))}"
if [ -z "${ACCEL:-}" ]; then
  if [ -w /dev/kvm ]; then ACCEL=kvm; else ACCEL=tcg; fi
fi
case "$ACCEL" in
  kvm)
    [ -w /dev/kvm ] || { echo "ACCEL=kvm: brak dostępu do /dev/kvm (sudo usermod -aG kvm $USER, potem wyloguj się)"; exit 3; }
    ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: tcg albo kvm (jest: $ACCEL)"; exit 3 ;;
esac

BUILD=1
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Nieznana opcja: $arg"; exit 3 ;;
  esac
done

if [ "$BUILD" = 1 ]; then
  ./build.sh --autostress="$SECS" > /dev/null || { echo "BLAD: build nie powiodl sie (uruchom ./build.sh --autostress=$SECS)"; exit 3; }
fi

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
[ -f "$OVMF_CODE" ] || { echo "Nie znaleziono OVMF (sudo apt install ovmf)"; exit 3; }

# Osobne, puste dyski – disk.img / nvme.img z Twoimi plikami zostają nietknięte.
TMP_DISK="$ROOT/build-stress-disk.img"
TMP_NVME="$ROOT/build-stress-nvme.img"
rm -f "$TMP_DISK" "$TMP_NVME" "$ROOT/build/NvVars"
truncate -s 64M "$TMP_DISK"
truncate -s 64M "$TMP_NVME"

LOG="$ROOT/stress-qemu.log"
: > "$LOG"
# Start + 5 s opóźnienia + stress + sprzątanie; zapas na wolne TCG.
LIMIT=$(( SECS + 180 ))  # M18.f: + ipcbench po stressie
echo "Autostress w QEMU: $ACCEL, $SMP CPU, stress $SECS s (limit ${LIMIT} s)..."

qemu-system-x86_64 \
  -machine q35 -m 1G -smp "$SMP" "${ACCEL_ARGS[@]}" \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -device qemu-xhci \
  -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on \
  -device usb-storage,drive=usbboot,bootindex=0 \
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
  # M18.f: [RESULT] to ostatnia linia autostressu (po pomiarze ipcbench).
  if grep -aqE "\[RESULT\].*pass=1" "$LOG"; then RESULT=0; break; fi
  if grep -aqE "\[RESULT\].*pass=0|\[AUTOSTRESS[^]]*\] FAIL" "$LOG"; then RESULT=1; sleep 1; break; fi
  if grep -aqE "PANIC|panicked" "$LOG"; then sleep 1; RESULT=1; break; fi
  if [ $(( $(date +%s) - START )) -gt "$LIMIT" ]; then RESULT=2; break; fi
  sleep 1
done
sleep 0.5
kill "$QPID" 2>/dev/null
wait "$QPID" 2>/dev/null
rm -f "$TMP_DISK" "$TMP_NVME"

# Wynik: raport autostress (bez tabeli CPU – ta jest w logu).
sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' -e 's/^.*\[AUTOSTRESS[^]]*\]/[AUTOSTRESS]/' "$LOG" | grep -a "^\[AUTOSTRESS\]" \
  | grep -avE "^\[AUTOSTRESS\] +[0-9]+ +[0-9]+ " | sed 's/^\[AUTOSTRESS\] //'
sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' "$LOG" | grep -ao "\[RESULT\].*" | tail -n 1
case "$RESULT" in
  0) echo "== PASS ($(( $(date +%s) - START )) s, log: stress-qemu.log)"; exit 0 ;;
  1) echo "== FAIL – ostatnie linie logu:"; grep -aE "FAIL|PANIC|panicked|\[LOCK\]|\[WATCHDOG\]" "$LOG" | tail -n 15; exit 1 ;;
  *) echo "== TIMEOUT / zawieszenie – ostatnie linie logu:"; tail -n 15 "$LOG"; exit 2 ;;
esac
