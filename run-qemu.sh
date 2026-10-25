#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
[ -f "$OVMF_CODE" ] || OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"

if [ ! -f "$OVMF_CODE" ]; then
  echo "OVMF not found. Install: sudo apt install ovmf qemu-system-x86"
  exit 1
fi

# Data disk for virtio-blk (an image file, created on first run).
# Outside build/, because QEMU sees build/ as a FAT disk.
DISK="$ROOT/disk.img"
DISK_SIZE="64M"
if [ ! -f "$DISK" ]; then
  echo "Creating disk image $DISK ($DISK_SIZE)"
  truncate -s "$DISK_SIZE" "$DISK"
fi

# NVMe disk (QEMU's emulated controller – the only NVMe that DeSoOS
# writes to; real SSDs are read-only).
NVME="$ROOT/nvme.img"
if [ ! -f "$NVME" ]; then
  echo "Creating NVMe disk image $NVME ($DISK_SIZE)"
  truncate -s "$DISK_SIZE" "$NVME"
fi

# build/ is a read-only USB stick (like a real boot from a USB stick).
# Previously "fat:rw:" – OVMF wrote NvVars there, and QEMU could
# corrupt BOOTX64.EFI in the process.  We remove the stale NvVars file.
rm -f "$ROOT/build/NvVars"

# QEMU accelerator.
#   ACCEL=tcg (default)   – emulation, multi-threaded (each virtual CPU is
#                           a separate host thread – otherwise the Big Kernel Lock
#                           handed over "in turn" causes second-long stalls)
#   ACCEL=kvm             – hardware virtualization (Linux with /dev/kvm):
#                           truly parallel hardware, native speed
ACCEL="${ACCEL:-tcg}"
case "$ACCEL" in
  kvm)
    [ -w /dev/kvm ] || { echo "ACCEL=kvm: no access to /dev/kvm (sudo usermod -aG kvm $USER, then log out)"; exit 1; }
    ACCEL_ARGS=(-accel kvm -cpu host) ;;
  tcg) ACCEL_ARGS=(-accel tcg,thread=multi -cpu max) ;;
  *) echo "ACCEL: tcg or kvm (got: $ACCEL)"; exit 1 ;;
esac
SMP="${SMP:-4}"

# Network: QEMU's user network (DHCP, DNS, NAT to the host's internet).
# HOSTFWD=port (default 18080): the host's 127.0.0.1:port reaches port 8080 of
# DeSoOS – e.g. `httpd 8080 < /index.html` in DeSoOS, `curl http://127.0.0.1:18080/`
# on the host.  HOSTFWD=0 – no forwarding (if the port is taken).
HOSTFWD="${HOSTFWD:-18080}"
NETDEV="user,id=net0"
if [ "$HOSTFWD" != 0 ]; then
  NETDEV="$NETDEV,hostfwd=tcp:127.0.0.1:$HOSTFWD-:8080"
fi

# USB=1 – like a laptop without PS/2: no 8042 controller, keyboard
# and mouse only on USB (usbd -> kernel).  Typing in the QEMU window then goes through
# the USB keyboard.  Default as before: PS/2.
# HUB=1 – a USB hub on port 3, with the USB=1 devices and usb.img behind it
# (ports 3.1, 3.2, 3.3) – like laptop sockets connected through an internal hub.
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
# usb.img (if present) = a second USB stick, READ-ONLY – the kernel
# mounts it at /usb0.  Test image: python3 tests/mkfat32.py usb.img file1 file2
if [ -f "$ROOT/usb.img" ]; then
  USB_ARGS+=(-drive if=none,id=usbimg,format=raw,file="$ROOT/usb.img",readonly=on -device "usb-storage,drive=usbimg${AT[2]}")
fi

exec qemu-system-x86_64 \
  -machine "$MACHINE" \
  -smp "$SMP" "${ACCEL_ARGS[@]}" \
  -m 512M \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -netdev "$NETDEV" -device e1000e,netdev=net0,mac=52:54:00:12:34:56 \
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
