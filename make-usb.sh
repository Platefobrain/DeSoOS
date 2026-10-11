#!/usr/bin/env bash
# M16b: DeSoOS na pendrive (UEFI) – BEZPIECZNIE.
#
#   ./make-usb.sh --list                 pokaż pendrive'y (USB) podłączone do komputera
#   ./make-usb.sh /media/${USER:-$(id -un)}/NAZWA     wgraj DeSoOS na zamontowany pendrive FAT32
#   ./make-usb.sh --format /dev/sdX      (opcjonalnie) sformatuj pendrive na FAT32 – KASUJE go
#   DESOOS_AUTOSTRESS=60 ./make-usb.sh /media/...   (M17a.b) kernel 5 s po starcie
#                                        sam robi stress test 60 s i pokazuje wynik
#
# Co robi przy wgrywaniu: buduje zwykły kernel (./build.sh, bez samotestów)
# i kopiuje JEDEN plik: build/EFI/BOOT/BOOTX64.EFI -> <pendrive>/EFI/BOOT/.
# Niczego nie formatuje, nie rusza innych plików na pendrive.
#
# Zabezpieczenia (skrypt odmawia, gdy coś się nie zgadza):
#   * cel musi być punktem montowania z systemem plików vfat (FAT32),
#   * dysk pod spodem musi być podłączony przez USB (lsblk TRAN=usb),
#   * nie może to być dysk, na którym jest / , /boot ani /boot/efi,
#   * istniejący, inny BOOTX64.EFI (np. instalator Ubuntu na pendrive) nie
#     jest nadpisywany bez --overwrite,
#   * --format: tylko USB, nie systemowy, nic z niego nie może być
#     zamontowane, i trzeba przepisać nazwę urządzenia.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

die() { echo "BLAD: $*" >&2; exit 1; }

# Dysk (np. sdb) dla urządzenia albo partycji (np. /dev/sdb1).
parent_disk() {
  local dev="$1" pk
  pk="$(lsblk -no PKNAME "$dev" 2>/dev/null | head -n1 | tr -d ' ')"
  if [ -n "$pk" ]; then echo "$pk"; else basename "$dev"; fi
}

# Dyski systemowe: te, na których leży /, /boot, /boot/efi.
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
  echo "Pendrive'y (dyski USB):"
  lsblk -o NAME,SIZE,TRAN,RM,FSTYPE,LABEL,MOUNTPOINTS | awk 'NR==1 || /usb/ {print; usb=1; next} usb && /^[└├│ ]/ {print; next} {usb=0}'
  echo
  echo "Dyski systemowe (NIE dotykamy): $(system_disks | tr '\n' ' ')"
}

format_usb() {
  local dev="$1" disk tran
  [ -b "$dev" ] || die "$dev nie jest urządzeniem blokowym"
  [ "$(lsblk -no TYPE "$dev" | head -n1)" = "disk" ] || die "$dev to nie cały dysk (podaj np. /dev/sdb, nie /dev/sdb1)"
  disk="$(basename "$dev")"
  tran="$(lsblk -dno TRAN "$dev" | tr -d ' ')"
  [ "$tran" = "usb" ] || die "$dev nie jest podłączony przez USB (TRAN='$tran') - odmawiam"
  is_system_disk "$disk" && die "$dev to dysk systemowy - odmawiam"
  if lsblk -no MOUNTPOINTS "$dev" | grep -q '[^[:space:]]'; then
    die "coś z $dev jest zamontowane - odmontuj (np. w menedżerze plików: Wysuń) i spróbuj znowu"
  fi
  echo "UWAGA: to SKASUJE WSZYSTKO na:"
  lsblk -o NAME,SIZE,TRAN,MODEL,FSTYPE,LABEL "$dev"
  echo
  read -r -p "Wpisz dokładnie '$dev', żeby kontynuować: " answer
  [ "$answer" = "$dev" ] || die "przerwane - nic nie zmieniono"
  echo "label: gpt
,,U" | sudo sfdisk --quiet "$dev"
  sudo partprobe "$dev" 2>/dev/null || true
  sleep 1
  local part
  part="$(lsblk -lnpo NAME,TYPE "$dev" | awk '$2=="part"{print $1; exit}')"
  [ -n "$part" ] || die "nie widzę nowej partycji na $dev"
  sudo mkfs.vfat -F 32 -n DESOOS "$part" >/dev/null
  echo "Gotowe: $part = FAT32 'DESOOS'. Wyjmij i włóż pendrive (zamontuje się sam), potem:"
  echo "  ./make-usb.sh /media/${USER:-$(id -un)}/DESOOS"
}

install_to() {
  local mnt="$1" overwrite="$2" src fstype disk tran
  mnt="$(realpath "$mnt")"
  mountpoint -q "$mnt" || die "$mnt nie jest punktem montowania (podaj katalog zamontowanego pendrive'a, np. /media/${USER:-$(id -un)}/NAZWA)"
  src="$(findmnt -n -o SOURCE --target "$mnt")"
  fstype="$(findmnt -n -o FSTYPE --target "$mnt")"
  [ "$fstype" = "vfat" ] || die "$mnt ma system plików '$fstype' - UEFI potrzebuje FAT32 (vfat). Zobacz: ./make-usb.sh --format"
  disk="$(parent_disk "$src")"
  tran="$(lsblk -dno TRAN "/dev/$disk" | tr -d ' ')"
  [ "$tran" = "usb" ] || die "$mnt ($src) nie jest na dysku USB (TRAN='$tran') - odmawiam"
  is_system_disk "$disk" && die "$src leży na dysku systemowym - odmawiam"

  echo "Pendrive: $src ($(lsblk -dno SIZE,MODEL "/dev/$disk" | xargs)) zamontowany w $mnt"

  local target="$mnt/EFI/BOOT/BOOTX64.EFI"
  if [ -f "$target" ] && [ "$overwrite" != 1 ]; then
    if ! grep -aq "DeSoOS" "$target"; then
      die "na pendrive jest już inny bootloader ($target) - np. instalator. Użyj pustego pendrive'a albo dodaj --overwrite"
    fi
  fi

  if [ "${DESOOS_AUTOSTRESS:-0}" != 0 ]; then
    echo "Buduję zwykły kernel + automatyczny stress test ${DESOOS_AUTOSTRESS} s po starcie..."
  else
    echo "Buduję zwykły kernel (bez samotestów)..."
  fi
  ./build.sh > build-usb.log 2>&1 || { tail -n 20 build-usb.log; die "build nie powiódł się (log: build-usb.log)"; }

  mkdir -p "$mnt/EFI/BOOT"
  cp build/EFI/BOOT/BOOTX64.EFI "$target"
  sync
  cmp -s build/EFI/BOOT/BOOTX64.EFI "$target" || die "plik na pendrive różni się od zbudowanego (pendrive uszkodzony?)"
  echo
  echo "Gotowe: $target ($(stat -c %s "$target") B)."
  echo "Teraz: Wysuń pendrive w menedżerze plików (albo: udisksctl unmount -b $src), uruchom komputer"
  echo "ponownie, F12 przy logo Lenovo -> wybierz pendrive (EFI USB Device)."
  echo "Szczegóły i bezpieczeństwo danych: README.md, sekcja 'Prawdziwy komputer'."
}

case "${1:-}" in
  --list|-l) list_usb ;;
  --format) [ -n "${2:-}" ] || die "podaj urządzenie, np. ./make-usb.sh --format /dev/sdb (sprawdź: ./make-usb.sh --list)"; format_usb "$2" ;;
  -h|--help|"") sed -n '2,20p' "$0" ;;
  *)
    overwrite=0
    [ "${2:-}" = "--overwrite" ] && overwrite=1
    install_to "$1" "$overwrite"
    ;;
esac
