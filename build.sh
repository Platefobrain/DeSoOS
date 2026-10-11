#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# ./build.sh                 -> zwykly kernel (bez samotestow)
# ./build.sh --selftest      -> kernel z samotestami (wyniki na serialu)
# ./build.sh --autostress=60 -> M17a.b: 5 s po starcie sam robi stress test
#                               (60 s) i wypisuje wynik, `cpus` i `mem` na
#                               ekranie - np. laptop bez dzialajacej klawiatury.
#                               To samo: DESOOS_AUTOSTRESS=60 ./make-usb.sh ...
SELFTEST_CFG=()
MODE="normal"
for arg in "$@"; do
  case "$arg" in
    --selftest) SELFTEST_CFG=(--cfg selftest); MODE="selftest" ;;
    --autostress) DESOOS_AUTOSTRESS=60 ;;
    --autostress=*) DESOOS_AUTOSTRESS="${arg#--autostress=}" ;;
    -h|--help) sed -n '7,12p' "$0"; exit 0 ;;
    *) echo "Nieznana opcja: $arg (uzyj --selftest albo --autostress=S)"; exit 1 ;;
  esac
done
export DESOOS_AUTOSTRESS="${DESOOS_AUTOSTRESS:-0}"
case "$DESOOS_AUTOSTRESS" in
  ''|*[!0-9]*) echo "--autostress: podaj liczbe sekund (jest: $DESOOS_AUTOSTRESS)"; exit 1 ;;
esac
# M17b.h2: DESOOS_STRESS_POOL=P – stress z P procesami na CPU (pełne obciążenie);
# brak / 0 = tryb porównawczy (3 na CPU, najwyżej 48 – jak dotąd).
export DESOOS_STRESS_POOL="${DESOOS_STRESS_POOL:-0}"
case "$DESOOS_STRESS_POOL" in
  ''|*[!0-9]*) echo "DESOOS_STRESS_POOL: podaj liczbe procesow na CPU (jest: $DESOOS_STRESS_POOL)"; exit 1 ;;
esac
if [ "$DESOOS_AUTOSTRESS" != 0 ]; then
  if [ "$DESOOS_STRESS_POOL" != 0 ]; then
    echo "Build: $MODE + stress ${DESOOS_AUTOSTRESS} s po starcie, PELNE obciazenie (${DESOOS_STRESS_POOL} procesow na CPU)"
  else
    echo "Build: $MODE + automatyczny stress test ${DESOOS_AUTOSTRESS} s po starcie (tryb porownawczy)"
  fi
else
  echo "Build: $MODE"
fi

# Wersja z Cargo.toml -> kernel (komenda 'ver', baner shella).
DESOOS_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
export DESOOS_VERSION

command -v rustc >/dev/null 2>&1 || { echo "Brak rustc. Zainstaluj Rust."; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "Brak cargo. Zainstaluj Rust."; exit 1; }
command -v objcopy >/dev/null 2>&1 || { echo "Brak objcopy. Zainstaluj binutils."; exit 1; }

# Target doinstalowany tylko, gdy go brak (bez sieci build dalej dziala).
SYSROOT="$(rustc --print sysroot)"
for t in x86_64-unknown-none x86_64-unknown-uefi; do
  [ -d "$SYSROOT/lib/rustlib/$t/lib" ] || rustup target add "$t"
done

mkdir -p build/EFI/BOOT

# M15: programy uzytkownika (user/bin/*.rs, ring 3) -> build/user/<nazwa>.
# Statyczne ELF-y (ET_EXEC) pod 0x400000 (user/user.ld), bez symboli.
# build/user/initrd.rs (lista nazwa + bajty) wlacza je do obrazu kernela;
# przy starcie laduja w /bin (kernel/initrd.rs).
mkdir -p build/user
rm -f build/user/*
INITRD=build/user/initrd.rs.tmp
echo "// wygenerowane przez build.sh - programy wbudowane w kernel (/bin)" > "$INITRD"
echo "pub static FILES: &[(&str, &[u8])] = &[" >> "$INITRD"
for src in user/bin/*.rs; do
  name=$(basename "$src" .rs)
  rustc \
    --edition=2024 \
    --target x86_64-unknown-none \
    -C panic=abort \
    -C relocation-model=static \
    -C opt-level=2 \
    -C link-arg=-Tuser/user.ld \
    -o "build/user/$name.full" \
    "$src"
  if ! readelf -h "build/user/$name.full" | grep -q "EXEC"; then
    echo "BLAD: build/user/$name.full nie jest statycznym ELF (ET_EXEC) - kernel go nie uruchomi."
    exit 1
  fi
  objcopy --strip-all "build/user/$name.full" "build/user/$name"
  echo "    (\"$name\", include_bytes!(\"$ROOT/build/user/$name\"))," >> "$INITRD"
  echo "user/bin/$name.rs -> build/user/$name ($(stat -c %s "build/user/$name") B)"
done
echo "];" >> "$INITRD"
mv "$INITRD" build/user/initrd.rs

rustc \
  --edition=2024 \
  --target x86_64-unknown-none \
  -C panic=abort \
  -C relocation-model=static \
  -C code-model=kernel \
  -C opt-level=2 \
  -C overflow-checks=on \
  -C link-arg=-Tkernel/linker.ld \
  --check-cfg 'cfg(selftest)' \
  "${SELFTEST_CFG[@]}" \
  -o build/kernel.elf \
  kernel/kernel.rs

# M10: DSB laduje ELF (segmenty PT_LOAD) pod 0xffffffff80000000 - nie ma juz
# plaskiego kernel.bin, limitu 512 KiB ani stalego stosu (DSB go alokuje).
# kernel.elf zostaje z symbolami (gdb, addr2line), do DSB idzie kopia bez nich.
command -v readelf >/dev/null 2>&1 || { echo "Brak readelf. Zainstaluj binutils."; exit 1; }
if ! readelf -h build/kernel.elf | grep -q "EXEC"; then
  echo "BLAD: build/kernel.elf nie jest statycznym plikiem wykonywalnym (ET_EXEC) - DSB go nie zaladuje."
  exit 1
fi
ENTRY=$(readelf -h build/kernel.elf | awk '/Entry point/ {print $4}')
if [ "$ENTRY" != "0xffffffff80000000" ]; then
  echo "BLAD: punkt wejscia kernela to $ENTRY, oczekiwano 0xffffffff80000000 (kernel/linker.ld)."
  exit 1
fi
objcopy --strip-all build/kernel.elf build/kernel.boot.elf
rm -f build/kernel.bin
KERNEL_START=$((16#$(nm build/kernel.elf | awk '$3 == "__kernel_start" {print $1}')))
KERNEL_END=$((16#$(nm build/kernel.elf | awk '$3 == "__kernel_end" {print $1}')))
echo "kernel.elf: wejscie $ENTRY, obraz w pamieci $(( (KERNEL_END - KERNEL_START) / 1024 )) KiB (z .bss)"

cargo build --release --target x86_64-unknown-uefi

cp target/x86_64-unknown-uefi/release/dsb.efi build/desoos.efi
cp build/desoos.efi build/EFI/BOOT/BOOTX64.EFI

echo
echo "Gotowe ($MODE):"
ls -lh build/kernel.elf build/kernel.boot.elf build/desoos.efi build/EFI/BOOT/BOOTX64.EFI
