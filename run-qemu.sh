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

# M20.e: USB=1 – jak laptop bez PS/2 (Legion): bez kontrolera 8042, klawiatura
# i mysz tylko na USB (usbd -> jądro).  Pisanie w oknie QEMU idzie wtedy przez
# klawiaturę USB.  Domyślnie jak dotąd: PS/2.
# M20.d: HUB=1 – hub USB w porcie 3, a urządzenia z USB=1 i usb.img za nim
# (porty 3.1, 3.2, 3.3) – jak gniazda laptopa podłączone przez wewnętrzny hub.
MACHINE="q35"
USB_ARGS=()
AT=()
if [ "${HUB:-0}" = 1 ]; then
  USB_ARGS=(-device usb-hub,bus=xhci.0,port=3)
  AT=(",bus=xhci.0,port=3.1" ",bus=xhci.0,port=3.2" ",bus=xhci.0,port=3.3")
else
  AT=("" "" "")
fi
if [ "${USB:-0}" = 1 ]; then
  MACHINE="q35,i8042=off"
  USB_ARGS+=(-device "usb-kbd${AT[0]}" -device "usb-mouse${AT[1]}")
fi
# M20.f: usb.img (jeśli jest) = drugi pendrive, TYLKO DO ODCZYTU – jądro
# zamontuje go w /usb0.  Obraz testowy: python3 tests/mkfat32.py usb.img plik1 plik2
if [ -f "$ROOT/usb.img" ]; then
  USB_ARGS+=(-drive if=none,id=usbimg,format=raw,file="$ROOT/usb.img",readonly=on -device "usb-storage,drive=usbimg${AT[2]}")
fi

exec qemu-system-x86_64 \
  -machine "$MACHINE" \
  -smp "$SMP" "${ACCEL_ARGS[@]}" \
  -m 512M \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -device qemu-xhci,id=xhci,p2=8,p3=8 \
  -drive if=none,id=usbboot,format=raw,file=fat:"$ROOT/build",readonly=on \
  -device usb-storage,bus=xhci.0,port=1,drive=usbboot,bootindex=0 \
  "${USB_ARGS[@]}" \
  -drive file="$DISK",format=raw,if=none,id=vd0 \
  -device virtio-blk-pci,drive=vd0 \
  -drive file="$NVME",format=raw,if=none,id=nv0 \
  -device nvme,serial=desoos,drive=nv0 \
  -device edu,addr=06 \
  -serial stdio
