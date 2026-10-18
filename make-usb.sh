#!/usr/bin/env bash
# DeSoOS on a USB flash drive (UEFI) – SAFELY.
#
#   ./make-usb.sh --list                 show USB flash drives attached to the computer
#   ./make-usb.sh /media/${USER:-$(id -un)}/NAME     install DeSoOS onto a mounted FAT32 flash drive
#   ./make-usb.sh --format /dev/sdX      (optional) format the flash drive as FAT32 – ERASES it
#   DESOOS_AUTOSTRESS=60 ./make-usb.sh /media/...   the kernel, 5 s after boot,
#                                        runs a 60 s stress test by itself and shows the result
#
# What installing does: builds the regular kernel (./build.sh, without self-tests)
# and copies ONE file: build/EFI/BOOT/BOOTX64.EFI -> <flash drive>/EFI/BOOT/.
# It formats nothing and does not touch other files on the flash drive.
#
# Safeguards (the script refuses when something does not match):
#   * the target must be a mount point with a vfat (FAT32) file system,
#   * the underlying disk must be attached via USB (lsblk TRAN=usb),
#   * it must not be the disk holding / , /boot or /boot/efi,
#   * an existing, different BOOTX64.EFI (e.g. an Ubuntu installer on the flash drive) is
#     not overwritten without --overwrite,
#   * --format: USB only, not a system disk, nothing on it may be
#     mounted, and the device name must be retyped.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

die() { echo "ERROR: $*" >&2; exit 1; }

# Disk (e.g. sdb) for a device or partition (e.g. /dev/sdb1).
parent_disk() {
  local dev="$1" pk
  pk="$(lsblk -no PKNAME "$dev" 2>/dev/null | head -n1 | tr -d ' ')"
  if [ -n "$pk" ]; then echo "$pk"; else basename "$dev"; fi
}

# System disks: those holding /, /boot, /boot/efi.
system_disks() {
  local m src
  for m in / /boot /boot/efi; do
    src="$(findmnt -n -o SOURCE --target "$m" 2>/dev/null || true)"
    case "$src" in
      /dev/*) parent_disk "$src" ;;
    esac
  done | sort -u
}

is_system_disk() {
  local d="$1"
  system_disks | grep -qx "$d"
}

list_usb() {
  echo "USB flash drives:"
  lsblk -o NAME,SIZE,TRAN,RM,FSTYPE,LABEL,MOUNTPOINTS | awk 'NR==1 || /usb/ {print; usb=1; next} usb && /^[└├│ ]/ {print; next} {usb=0}'
  echo
  echo "System disks (NOT touched): $(system_disks | tr '\n' ' ')"
}

format_usb() {
  local dev="$1" disk tran
  [ -b "$dev" ] || die "$dev is not a block device"
  [ "$(lsblk -no TYPE "$dev" | head -n1)" = "disk" ] || die "$dev is not a whole disk (give e.g. /dev/sdb, not /dev/sdb1)"
  disk="$(basename "$dev")"
  tran="$(lsblk -dno TRAN "$dev" | tr -d ' ')"
  [ "$tran" = "usb" ] || die "$dev is not attached via USB (TRAN='$tran') - refusing"
  is_system_disk "$disk" && die "$dev is a system disk - refusing"
  if lsblk -no MOUNTPOINTS "$dev" | grep -q '[^[:space:]]'; then
    die "something on $dev is mounted - unmount it (e.g. Eject in the file manager) and try again"
  fi
  echo "WARNING: this will ERASE EVERYTHING on:"
  lsblk -o NAME,SIZE,TRAN,MODEL,FSTYPE,LABEL "$dev"
  echo
  read -r -p "Type exactly '$dev' to continue: " answer
  [ "$answer" = "$dev" ] || die "aborted - nothing changed"
  echo "label: gpt
,,U" | sudo sfdisk --quiet "$dev"
  sudo partprobe "$dev" 2>/dev/null || true
  sleep 1
  local part
  part="$(lsblk -lnpo NAME,TYPE "$dev" | awk '$2=="part"{print $1; exit}')"
  [ -n "$part" ] || die "no new partition found on $dev"
  sudo mkfs.vfat -F 32 -n DESOOS "$part" >/dev/null
  echo "Done: $part = FAT32 'DESOOS'. Unplug and replug the flash drive (it will mount itself), then:"
  echo "  ./make-usb.sh /media/${USER:-$(id -un)}/DESOOS"
}

install_to() {
  local mnt="$1" overwrite="$2" src fstype disk tran
  mnt="$(realpath "$mnt")"
  mountpoint -q "$mnt" || die "$mnt is not a mount point (give the directory of the mounted flash drive, e.g. /media/${USER:-$(id -un)}/NAME)"
  src="$(findmnt -n -o SOURCE --target "$mnt")"
  fstype="$(findmnt -n -o FSTYPE --target "$mnt")"
  [ "$fstype" = "vfat" ] || die "$mnt has file system '$fstype' - UEFI needs FAT32 (vfat). See: ./make-usb.sh --format"
  disk="$(parent_disk "$src")"
  tran="$(lsblk -dno TRAN "/dev/$disk" | tr -d ' ')"
  [ "$tran" = "usb" ] || die "$mnt ($src) is not on a USB disk (TRAN='$tran') - refusing"
  is_system_disk "$disk" && die "$src is on a system disk - refusing"

  echo "Flash drive: $src ($(lsblk -dno SIZE,MODEL "/dev/$disk" | xargs)) mounted at $mnt"

  local target="$mnt/EFI/BOOT/BOOTX64.EFI"
  if [ -f "$target" ] && [ "$overwrite" != 1 ]; then
    if ! grep -aq "DeSoOS" "$target"; then
      die "the flash drive already has another bootloader ($target) - e.g. an installer. Use an empty flash drive or add --overwrite"
    fi
  fi

  if [ "${DESOOS_AUTOSTRESS:-0}" != 0 ]; then
    echo "Building the regular kernel + automatic stress test ${DESOOS_AUTOSTRESS} s after boot..."
  else
    echo "Building the regular kernel (no self-tests)..."
  fi
  mkdir -p logs
  ./build.sh > logs/build-usb.log 2>&1 || { tail -n 20 logs/build-usb.log; die "build failed (log: logs/build-usb.log)"; }

  mkdir -p "$mnt/EFI/BOOT"
  cp build/EFI/BOOT/BOOTX64.EFI "$target"
  sync
  cmp -s build/EFI/BOOT/BOOTX64.EFI "$target" || die "the file on the flash drive differs from the built one (faulty flash drive?)"
  echo
  echo "Done: $target ($(stat -c %s "$target") B)."
  echo "Now: eject the flash drive in the file manager (or: udisksctl unmount -b $src), restart the computer,"
  echo "open the boot menu (usually F12, F11, F9 or Esc at the vendor logo) -> choose the flash drive (EFI USB Device)."
  echo "Details and data safety: README.md, section 'Real hardware'."
}

case "${1:-}" in
  --list|-l) list_usb ;;
  --format) [ -n "${2:-}" ] || die "give a device, e.g. ./make-usb.sh --format /dev/sdb (check: ./make-usb.sh --list)"; format_usb "$2" ;;
  -h|--help|"") sed -n '2,20p' "$0" ;;
  *)
    overwrite=0
    [ "${2:-}" = "--overwrite" ] && overwrite=1
    install_to "$1" "$overwrite"
    ;;
esac
