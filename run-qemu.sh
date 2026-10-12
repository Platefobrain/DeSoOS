#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"

if [ ! -f "$OVMF_CODE" ]; then
  echo "Nie znaleziono OVMF. Zainstaluj: sudo apt install ovmf qemu-system-x86"
  exit 1
fi

# M8: dysk danych dla virtio-blk (plik obrazu, tworzony przy pierwszym
# uruchomieniu).  Poza katalogiem build/, bo build/ QEMU widzi jako dysk FAT.
DISK="$ROOT/disk.img"
DISK_SIZE="64M"
if [ ! -f "$DISK" ]; then
  echo "Tworze obraz dysku $DISK ($DISK_SIZE)"
  truncate -s "$DISK_SIZE" "$DISK"
fi

# M16b: dysk NVMe (emulowany kontroler QEMU – jedyny NVMe, do którego
# DeSoOS zapisuje; prawdziwe SSD są tylko do odczytu).
NVME="$ROOT/nvme.img"
if [ ! -f "$NVME" ]; then
  echo "Tworze obraz dysku NVMe $NVME ($DISK_SIZE)"
  truncate -s "$DISK_SIZE" "$NVME"
fi

# M16b: build/ to pendrive USB tylko do odczytu (jak prawdziwy start
# z pendrive'a).  Wcześniej "fat:rw:" – OVMF zapisywał tam NvVars, a QEMU
# potrafił przy tym uszkodzić BOOTX64.EFI.  Stary plik NvVars usuwamy.
rm -f "$ROOT/build/NvVars"

# M17a: akcelerator QEMU.
#   ACCEL=tcg (domyślnie) – emulacja, wielowątkowa (każdy wirtualny CPU
#                           osobnym wątkiem hosta – inaczej Big Kernel Lock
#                           przekazywany "po kolei" daje sekundowe przestoje)
#   ACCEL=kvm             – wirtualizacja sprzętowa (Linux z /dev/kvm):
#                           prawdziwy równoległy sprzęt, natywna szybkość
ACCEL="${ACCEL:-tcg}"
case "$ACCEL" in
  kvm)
    [ -w /dev/kvm ] || { echo "ACCEL=kvm: brak dostępu do /dev/kvm (sudo usermod -aG kvm $USER, potem wyloguj się)"; exit 1; }
    ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: tcg albo kvm (jest: $ACCEL)"; exit 1 ;;
esac
SMP="${SMP:-4}"

exec qemu-system-x86_64 \
  -machine q35 \
  -smp "$SMP" "${ACCEL_ARGS[@]}" \
  -m 512M \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -device qemu-xhci \
  -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on \
  -device usb-storage,drive=usbboot,bootindex=0 \
  -drive file="$DISK",format=raw,if=none,id=vd0 \
  -device virtio-blk-pci,drive=vd0 \
  -drive file="$NVME",format=raw,if=none,id=nv0 \
  -device nvme,serial=desoos,drive=nv0 \
  -device edu,addr=06 \
  -serial stdio
