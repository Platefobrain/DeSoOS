#!/usr/bin/env bash
# DeSo OS on a USB flash drive (UEFI) – SAFELY.
#
#   ./make-usb.sh --list                 show USB flash drives attached to the computer
#   ./make-usb.sh /media/${USER:-$(id -un)}/NAME     install DeSo OS onto a mounted FAT32 flash drive
#   ./make-usb.sh --format /dev/sdX      (optional) format the flash drive as FAT32 – ERASES it
#   ./make-usb.sh --with-disk /dev/sdX   a flash drive with a disk – ERASES it: partition 1 = ESP
#                                        (FAT32 "DESO", BOOTX64.EFI, read-only in DeSo OS),
#                                        partition 2 = "DeSo system" (an empty DeSoFS, at most
#                                        64 GiB) = /disk in DeSo OS, where your files and the
#                                        last known good time stay.  Add --dry-run to only check.
#   ./make-usb.sh --with-disk --image FILE SIZE_MIB [--efi BOOTX64.EFI]
#                                        the same layout into an image file (no sudo; the tests
#                                        use it – the same code, tools/mkusb.py)
#   DESO_AUTOSTRESS=60 ./make-usb.sh /media/...   the kernel, 5 s after boot,
#                                        runs a 60 s stress test by itself and shows the result
#   DESO_AUTOSOAK=3600 ./make-usb.sh /media/...   the kernel runs a 1-hour soak test on a
#                                        RAM disk before init and shows the result
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
#   * --with-disk: a whole disk (not a partition, loop or dm), removable, USB, at most 256 GiB,
#     512-byte sectors, not a system disk, nothing on it mounted, no swap on it, no holders
#     (LVM / RAID / dm-crypt), model / size / serial / partitions shown, the device name retyped;
#     everything checked AGAIN right before writing (the same major:minor, serial and size –
#     else nothing is written), and tools/mkusb.py opens it exclusively (O_EXCL) and checks the
#     major:minor and size once more.  Any unclear answer = stop.
# Updating a flash drive made with --with-disk: ./make-usb.sh /media/$USER/DESO – only
# BOOTX64.EFI on the ESP is replaced; the DeSoFS partition (your files) is not touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

die() { echo "ERROR: $*" >&2; exit 1; }

# tests/make-usb-test.sh runs the checks against a fake /sys, /proc and udev database (and fake
# lsblk / findmnt in PATH); the real ones otherwise.
SYS="${DESO_SYS:-/sys}"
PROC="${DESO_PROC:-/proc}"
UDEV="${DESO_UDEV:-/run/udev/data}"
DESO_SYSTEM_GUID="1a0e2e7d-de32-4c13-9442-9fcb2649ca02"

# What a person reads on the stick's label: lsblk's VENDOR and MODEL (the SCSI inquiry strings);
# when both are empty (many cheap sticks), udev's ID_VENDOR / ID_MODEL (the USB descriptor) for
# major:minor $2.  Empty when nothing names it.
device_model() {
  local dev="$1" mm="$2" v m f
  v="$(lsblk -dno VENDOR "$dev" 2>/dev/null | xargs || true)"
  m="$(lsblk -dno MODEL "$dev" 2>/dev/null | xargs || true)"
  if [ -z "$v$m" ] && [ -r "$UDEV/b$mm" ]; then
    f="$UDEV/b$mm"
    v="$(sed -n 's/^E:ID_VENDOR=//p' "$f" | head -n1 | tr '_' ' ' | xargs || true)"
    m="$(sed -n 's/^E:ID_MODEL=//p' "$f" | head -n1 | tr '_' ' ' | xargs || true)"
  fi
  echo "$v $m" | xargs
}

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
  sudo mkfs.vfat -F 32 -n DESO "$part" >/dev/null
  echo "Done: $part = FAT32 'DESO'. Unplug and replug the flash drive (it will mount itself), then:"
  echo "  ./make-usb.sh /media/${USER:-$(id -un)}/DESO"
}

# --with-disk: every check on device $1.  Sets DEV, NAME, MAJMIN, SERIAL, BYTES, MODEL; dies
# on anything unclear.
check_device() {
  local dev name t tran rm ssz bytes mnt p sw swdev hold
  dev="$(readlink -f -- "$1")" || die "cannot resolve $1"
  if [ -z "${DESO_SYS:-}" ]; then
    [ -b "$dev" ] || die "$dev is not a block device"
  fi
  case "$dev" in
    /dev/loop*|/dev/dm-*|/dev/md*|/dev/mapper/*) die "$dev is not a physical disk (loop / dm / md) - refusing" ;;
  esac
  t="$(lsblk -dno TYPE "$dev" 2>/dev/null | tr -d ' ')"
  [ "$t" = "disk" ] || die "$dev is not a whole disk (type '$t') - give e.g. /dev/sdb, not /dev/sdb1"
  name="$(basename "$dev")"
  [ -d "$SYS/block/$name" ] || die "$SYS/block/$name missing - not a disk the kernel lists"
  tran="$(lsblk -dno TRAN "$dev" 2>/dev/null | tr -d ' ')"
  [ "$tran" = "usb" ] || die "$dev is not attached via USB (TRAN='$tran') - refusing"
  rm="$(cat "$SYS/block/$name/removable" 2>/dev/null || true)"
  [ "$rm" = "1" ] || die "$dev is not a removable disk (removable='$rm') - refusing"
  ssz="$(cat "$SYS/block/$name/queue/logical_block_size" 2>/dev/null || true)"
  [ "$ssz" = "512" ] || die "$dev has ${ssz:-unknown}-byte sectors - DeSo OS reads 512-byte sectors only"
  bytes="$(lsblk -dbno SIZE "$dev" 2>/dev/null | tr -d ' ')"
  case "$bytes" in ''|*[!0-9]*) die "size of $dev unknown" ;; esac
  [ "$bytes" -le $((256 << 30)) ] || die "$dev is larger than 256 GiB - not a flash drive? refusing"
  [ "$bytes" -ge $((200 << 20)) ] || die "$dev is smaller than 200 MiB (ESP 128 MiB + DeSo system 64 MiB)"
  is_system_disk "$name" && die "$dev is a system disk - refusing"
  mnt="$(lsblk -nro MOUNTPOINTS "$dev" 2>/dev/null | tr -d '[:space:]')"
  [ -z "$mnt" ] || die "something on $dev is mounted - unmount it (e.g. Eject in the file manager) and try again"
  while read -r swdev _; do
    case "$swdev" in Filename|"") continue ;; esac
    p="$(basename "$(readlink -f -- "$swdev" 2>/dev/null || echo "$swdev")")"
    for sw in $(lsblk -nlo NAME "$dev" 2>/dev/null); do
      [ "$p" = "$sw" ] && die "$dev holds a swap area ($swdev) - turn it off first (swapoff)"
    done
  done < "$PROC/swaps"
  hold="$(ls -A "$SYS/block/$name/holders" 2>/dev/null || true)"
  for p in "$SYS/block/$name/$name"*; do
    [ -d "$p/holders" ] && hold="$hold$(ls -A "$p/holders" 2>/dev/null || true)"
  done
  [ -z "$hold" ] || die "$dev or one of its partitions is held by $hold (LVM / RAID / dm-crypt) - refusing"
  SERIAL="$(lsblk -dno SERIAL "$dev" 2>/dev/null | tr -d ' ')"
  [ -n "$SERIAL" ] || die "$dev reports no serial number - it cannot be told apart from another stick; refusing"
  MAJMIN="$(lsblk -dno MAJ:MIN "$dev" 2>/dev/null | tr -d ' ')"
  case "$MAJMIN" in *:*) ;; *) die "major:minor of $dev unknown" ;; esac
  MODEL="$(device_model "$dev" "$MAJMIN")"
  DEV="$dev"; NAME="$name"; BYTES="$bytes"
}

# Every check again, and still the device asked about: the same major:minor, serial and size.
same_device() {
  check_device "$1"
  [ "$DEV" = "$1" ] && [ "$MAJMIN" = "$2" ] && [ "$SERIAL" = "$3" ] && [ "$BYTES" = "$4" ] || die "$1 changed since the question (now $MAJMIN, serial '$SERIAL', $BYTES B) - nothing written"
}

with_disk_device() {
  local dry="$1" d1 m1 s1 b1
  check_device "$2"
  d1="$DEV"; m1="$MAJMIN"; s1="$SERIAL"; b1="$BYTES"
  echo "WARNING: this will ERASE EVERYTHING on $DEV and make it a DeSo OS flash drive with a disk:"
  echo "  model: ${MODEL:-?}   size: $((BYTES >> 20)) MiB   serial: ${SERIAL:-none}   device: $MAJMIN"
  lsblk -o NAME,SIZE,FSTYPE,LABEL,PARTTYPENAME "$DEV" 2>/dev/null || true
  if lsblk -nro PARTTYPE "$DEV" 2>/dev/null | grep -qi "$DESO_SYSTEM_GUID"; then
    echo
    echo "NOTE: it already has a \"DeSo system\" partition - YOUR DeSo OS DATA (files, the last known"
    echo "good time) WILL BE LOST.  To update DeSo OS only, mount the flash drive and run:"
    echo "  ./make-usb.sh /media/${USER:-$(id -un)}/DESO"
  fi
  echo
  read -r -p "Type exactly '$DEV' to continue: " answer
  [ "$answer" = "$DEV" ] || die "aborted - nothing changed"
  if [ "$dry" = 1 ]; then
    same_device "$d1" "$m1" "$s1" "$b1"
    echo "Dry run: all checks passed - would write $DEV ($MAJMIN, serial '${SERIAL:-none}', $BYTES B); nothing written."
    return
  fi
  echo "Building the regular kernel (no self-tests)..."
  mkdir -p logs
  ./build.sh > logs/build-usb.log 2>&1 || { tail -n 20 logs/build-usb.log; die "build failed (log: logs/build-usb.log)"; }
  # Everything again, right before writing: the same disk, nothing mounted meanwhile.
  same_device "$d1" "$m1" "$s1" "$b1"
  echo "Writing $DEV (sudo)..."
  sudo python3 tools/mkusb.py --device "$DEV" --expect-rdev "$MAJMIN" --expect-bytes "$BYTES" --expect-serial "$SERIAL" --efi build/EFI/BOOT/BOOTX64.EFI || die "writing the flash drive failed - see above (make it again before using it)"
  sudo partprobe "$DEV" 2>/dev/null || true
  echo
  echo "Done: $DEV = ESP 'DESO' (BOOTX64.EFI) + \"DeSo system\" (DeSoFS, /disk in DeSo OS)."
  echo "Now: unplug the flash drive, restart the computer, open the boot menu (usually F12, F11, F9 or Esc)"
  echo "-> choose the flash drive (EFI USB Device).  To update DeSo OS later: ./make-usb.sh /media/${USER:-$(id -un)}/DESO"
}

with_disk_image() {
  local file="$1" mib="$2" efi="$3"
  [ -n "$file" ] && [ -n "$mib" ] || die "give a file and a size: ./make-usb.sh --with-disk --image FILE SIZE_MIB"
  case "$mib" in ''|*[!0-9]*) die "size in MiB, a number (got: $mib)" ;; esac
  [ ! -b "$file" ] || die "$file is a block device - --image writes files only (for a flash drive: --with-disk /dev/sdX)"
  if [ -z "$efi" ]; then
    echo "Building the regular kernel (no self-tests)..."
    mkdir -p logs
    ./build.sh > logs/build-usb.log 2>&1 || { tail -n 20 logs/build-usb.log; die "build failed (log: logs/build-usb.log)"; }
    efi=build/EFI/BOOT/BOOTX64.EFI
  fi
  python3 tools/mkusb.py --image "$file" --size-mib "$mib" --efi "$efi" || die "making the image failed"
  echo "Done: $file (start it in QEMU as a USB disk with bootindex=0, or write it to a flash drive)."
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

  echo "Flash drive: $src ($(lsblk -dno SIZE "/dev/$disk" | xargs) $(device_model "/dev/$disk" "$(lsblk -dno MAJ:MIN "/dev/$disk" | tr -d ' ')")) mounted at $mnt"

  local target="$mnt/EFI/BOOT/BOOTX64.EFI"
  if [ -f "$target" ] && [ "$overwrite" != 1 ]; then
    if ! grep -aq "DeSo OS" "$target"; then
      die "the flash drive already has another bootloader ($target) - e.g. an installer. Use an empty flash drive or add --overwrite"
    fi
  fi

  if [ "${DESO_AUTOSTRESS:-0}" != 0 ]; then
    echo "Building the regular kernel + automatic stress test ${DESO_AUTOSTRESS} s after boot..."
  elif [ "${DESO_AUTOSOAK:-0}" != 0 ]; then
    echo "Building the regular kernel + soak test ${DESO_AUTOSOAK} s on a RAM disk before init..."
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
  --with-disk)
    shift
    case "${1:-}" in
      --image)
        efi=""
        [ "${4:-}" = "--efi" ] && efi="${5:-}"
        [ "${4:-}" != "--efi" ] || [ -n "$efi" ] || die "--efi needs a file"
        with_disk_image "${2:-}" "${3:-}" "$efi" ;;
      --dry-run) [ -n "${2:-}" ] || die "give a device"; with_disk_device 1 "$2" ;;
      "") die "give a device, e.g. ./make-usb.sh --with-disk /dev/sdb (check: ./make-usb.sh --list)" ;;
      *)
        if [ "${2:-}" = "--dry-run" ]; then with_disk_device 1 "$1"; else with_disk_device 0 "$1"; fi ;;
    esac ;;
  -h|--help|"") sed -n '2,40p' "$0" ;;
  *)
    overwrite=0
    [ "${2:-}" = "--overwrite" ] && overwrite=1
    install_to "$1" "$overwrite"
    ;;
esac
