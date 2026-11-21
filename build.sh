#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# ./build.sh                 -> regular kernel (no self-tests)
# ./build.sh --selftest      -> kernel with self-tests (results on serial)
# ./build.sh --autostress=60 -> 5 s after boot runs a stress test on its own
#                               (60 s) and prints the result, `cpus` and `mem` on
#                               the screen - e.g. a laptop without a working keyboard.
#                               Same thing: DESO_AUTOSTRESS=60 ./make-usb.sh ...
# ./build.sh --autosoak=3600  -> before init runs the soak test (3600 s) on a RAM disk
#                               (real hardware; the computer's disks are not touched),
#                               the result on the screen, then the system starts as usual.
#                               Same thing: DESO_AUTOSOAK=3600 ./make-usb.sh ...
SELFTEST_CFG=()
MODE="normal"
for arg in "$@"; do
  case "$arg" in
    --selftest) SELFTEST_CFG=(--cfg selftest); MODE="selftest" ;;
    --autostress) DESO_AUTOSTRESS=60 ;;
    --autostress=*) DESO_AUTOSTRESS="${arg#--autostress=}" ;;
    --autosoak=*) DESO_AUTOSOAK="${arg#--autosoak=}" ;;
    -h|--help) sed -n '7,16p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg (use --selftest, --autostress=S or --autosoak=S)"; exit 1 ;;
  esac
done
export DESO_AUTOSTRESS="${DESO_AUTOSTRESS:-0}"
case "$DESO_AUTOSTRESS" in
  ''|*[!0-9]*) echo "--autostress: give a number of seconds (got: $DESO_AUTOSTRESS)"; exit 1 ;;
esac
export DESO_AUTOSOAK="${DESO_AUTOSOAK:-0}"
case "$DESO_AUTOSOAK" in
  ''|*[!0-9]*) echo "--autosoak: give a number of seconds (got: $DESO_AUTOSOAK)"; exit 1 ;;
esac
if [ "$DESO_AUTOSOAK" != 0 ] && [ "$DESO_AUTOSOAK" -lt 60 ]; then
  echo "--autosoak: at least 60 seconds (got: $DESO_AUTOSOAK)"; exit 1
fi
if [ "$DESO_AUTOSOAK" != 0 ] && [ "$DESO_AUTOSTRESS" != 0 ]; then
  echo "--autosoak and --autostress together: choose one"; exit 1
fi
# The random number generator's trust policy (kernel/random.rs): 0 = the source is still
# mixed into the pool, but its entropy is not counted.  DESO_TRUST_CPU – RDSEED;
# DESO_TRUST_BOOTLOADER – the firmware's RNG (RAW algorithm).  Default 1 (counted).
export DESO_TRUST_CPU="${DESO_TRUST_CPU:-1}"
export DESO_TRUST_BOOTLOADER="${DESO_TRUST_BOOTLOADER:-1}"
case "$DESO_TRUST_CPU$DESO_TRUST_BOOTLOADER" in
  00|01|10|11) ;;
  *) echo "DESO_TRUST_CPU / DESO_TRUST_BOOTLOADER: 0 or 1 (got: $DESO_TRUST_CPU / $DESO_TRUST_BOOTLOADER)"; exit 1 ;;
esac
if [ "$DESO_TRUST_CPU$DESO_TRUST_BOOTLOADER" != 11 ]; then
  echo "Random numbers: RDSEED counted: $DESO_TRUST_CPU, firmware RNG counted: $DESO_TRUST_BOOTLOADER"
fi
# DESO_BUILD_TAG=NAME – the build's own name, shown by `ver` (up to 8 letters / digits;
# tests/make-usb-test.sh tells two builds apart with it).  Unset – no name.
if [ -n "${DESO_BUILD_TAG:-}" ]; then
  case "$DESO_BUILD_TAG" in
    *[!A-Za-z0-9]*) echo "DESO_BUILD_TAG: letters and digits only (got: $DESO_BUILD_TAG)"; exit 1 ;;
  esac
  [ "${#DESO_BUILD_TAG}" -le 8 ] || { echo "DESO_BUILD_TAG: at most 8 characters (got: $DESO_BUILD_TAG)"; exit 1; }
  export DESO_BUILD_TAG
  echo "Build tag: $DESO_BUILD_TAG"
fi
# DESO_STRESS_POOL=P – stress with P processes per CPU (full load);
# unset / 0 = comparison mode (3 per CPU, at most 48 – the default).
export DESO_STRESS_POOL="${DESO_STRESS_POOL:-0}"
case "$DESO_STRESS_POOL" in
  ''|*[!0-9]*) echo "DESO_STRESS_POOL: give a number of processes per CPU (got: $DESO_STRESS_POOL)"; exit 1 ;;
esac
if [ "$DESO_AUTOSTRESS" != 0 ]; then
  if [ "$DESO_STRESS_POOL" != 0 ]; then
    echo "Build: $MODE + stress ${DESO_AUTOSTRESS} s after boot, FULL load (${DESO_STRESS_POOL} processes per CPU)"
  else
    echo "Build: $MODE + automatic stress test ${DESO_AUTOSTRESS} s after boot (comparison mode)"
  fi
elif [ "$DESO_AUTOSOAK" != 0 ]; then
  echo "Build: $MODE + soak test ${DESO_AUTOSOAK} s on a RAM disk before init"
else
  echo "Build: $MODE"
fi

# Spin the idle CPU before `hlt` (faster wake-up).
# DESO_IDLE_POLL_US=N – upper bound of the window in µs (0 = hlt immediately), default 200;
# DESO_IDLE_POLL_ADAPT=1 – the window adapts per CPU on its own (default), 0 – fixed N.
export DESO_IDLE_POLL_US="${DESO_IDLE_POLL_US:-200}"
export DESO_IDLE_POLL_ADAPT="${DESO_IDLE_POLL_ADAPT:-1}"
case "$DESO_IDLE_POLL_US$DESO_IDLE_POLL_ADAPT" in
  ''|*[!0-9]*) echo "DESO_IDLE_POLL_US / DESO_IDLE_POLL_ADAPT: give numbers"; exit 1 ;;
esac
if [ "$DESO_IDLE_POLL_US" != 200 ] || [ "$DESO_IDLE_POLL_ADAPT" != 1 ]; then
  echo "Idle: spin before hlt up to ${DESO_IDLE_POLL_US} us, $([ "$DESO_IDLE_POLL_ADAPT" = 1 ] && echo adaptive || echo fixed)"
fi

# Version from Cargo.toml -> kernel (the 'ver' command, shell banner).
DESO_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
export DESO_VERSION

command -v rustc >/dev/null 2>&1 || { echo "rustc not found. Install Rust."; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "cargo not found. Install Rust."; exit 1; }
command -v objcopy >/dev/null 2>&1 || { echo "objcopy not found. Install binutils."; exit 1; }

# Install the target only if it is missing (without network the build still works).
SYSROOT="$(rustc --print sysroot)"
for t in x86_64-unknown-none x86_64-unknown-uefi; do
  [ -d "$SYSROOT/lib/rustlib/$t/lib" ] || rustup target add "$t"
done

mkdir -p build/EFI/BOOT

# User programs (user/bin/*.rs, ring 3) -> build/user/<name>.
# Static ELFs (ET_EXEC) at 0x400000 (user/user.ld), without symbols.
# build/user/initrd.rs (list of name + bytes) includes them in the kernel image;
# at boot they are loaded into /bin (kernel/initrd.rs).
mkdir -p build/user
rm -f build/user/*
INITRD=build/user/initrd.rs.tmp
echo "// generated by build.sh - programs built into the kernel (/bin)" > "$INITRD"
echo "pub static FILES: &[(&str, &[u8])] = &[" >> "$INITRD"
for src in user/bin/*.rs; do
  name=$(basename "$src" .rs)
  # Test-only library code (e.g. DeSoCrypto's assume_length) exists only in the
  # program that tests it – not in ordinary programs.
  EXTRA_CFG=()
  [ "$name" = cryptotest ] && EXTRA_CFG=(--cfg desocrypto_test)
  # DeSoTLS's test hooks (RFC 8448's own ClientHello, its 1024-bit key) – only in tlstest.
  [ "$name" = tlstest ] && EXTRA_CFG=(--cfg desotls_test)
  # The time service's test list (tests/nts-server, the test CAs) – only in the self-test
  # image; the normal timekeeper has the built-in list alone and takes no argument.
  [ "$name" = timekeeper ] && [ "$MODE" = "selftest" ] && EXTRA_CFG=(--cfg selftest)
  # usbd's test flags (the third write lock off, a failed WRITE / FLUSH, a late FLUSH
  # reply) – only in the self-test image; the normal usbd refuses them.
  [ "$name" = usbd ] && [ "$MODE" = "selftest" ] && EXTRA_CFG=(--cfg selftest)
  rustc \
    --edition=2024 \
    --target x86_64-unknown-none \
    -C panic=abort \
    -C relocation-model=static \
    -C opt-level=2 \
    -C link-arg=-Tuser/user.ld \
    --check-cfg 'cfg(selftest, desocrypto_test, desotls_test, desocrypto_no_simd)' \
    "${EXTRA_CFG[@]}" \
    -o "build/user/$name.full" \
    "$src"
  if ! readelf -h "build/user/$name.full" | grep -q "EXEC"; then
    echo "ERROR: build/user/$name.full is not a static ELF (ET_EXEC) - the kernel will not run it."
    exit 1
  fi
  objcopy --strip-all "build/user/$name.full" "build/user/$name"
  echo "    (\"$name\", include_bytes!(\"$ROOT/build/user/$name\"))," >> "$INITRD"
  echo "user/bin/$name.rs -> build/user/$name ($(stat -c %s "build/user/$name") B)"
done
echo "];" >> "$INITRD"
# Service manifests (user/etc/services/*.svc) -> /etc/services at boot: what init
# gives each service (device, grants, file access).
echo "pub static ETC_SERVICES: &[(&str, &[u8])] = &[" >> "$INITRD"
for svc in user/etc/services/*.svc; do
  [ -e "$svc" ] || continue
  echo "    (\"$(basename "$svc")\", include_bytes!(\"$ROOT/$svc\"))," >> "$INITRD"
done
echo "];" >> "$INITRD"
# The trusted CA store (user/etc/certs/roots – user/etc/certs/gen-roots.py from Mozilla's root
# store) -> /etc/certs/roots at boot, sealed (no process can change it).
[ -f user/etc/certs/roots ] || { echo "user/etc/certs/roots missing (user/etc/certs/gen-roots.py)."; exit 1; }
echo "pub static ETC_CERTS_ROOTS: &[u8] = include_bytes!(\"$ROOT/user/etc/certs/roots\");" >> "$INITRD"
# DeSoFS reference image (tests/mkdesofs.py – an independent implementation of the
# format) for DESOFS TEST; only in the self-test build.
if [ "$MODE" = "selftest" ]; then
  command -v python3 >/dev/null 2>&1 || { echo "python3 not found (needed for the self-test build: tests/mkdesofs.py)."; exit 1; }
  python3 tests/mkdesofs.py build/user/desofs-ref.img
  python3 tests/mkdesofs.py --format 64 build/user/desofs-fmt.img
  echo "#[allow(dead_code)]" >> "$INITRD"
  echo "pub static DESOFS_REF: &[u8] = include_bytes!(\"$ROOT/build/user/desofs-ref.img\");" >> "$INITRD"
  echo "#[allow(dead_code)]" >> "$INITRD"
  echo "pub static DESOFS_FMT: &[u8] = include_bytes!(\"$ROOT/build/user/desofs-fmt.img\");" >> "$INITRD"
else
  echo "#[allow(dead_code)]" >> "$INITRD"
  echo "pub static DESOFS_REF: &[u8] = &[];" >> "$INITRD"
  echo "#[allow(dead_code)]" >> "$INITRD"
  echo "pub static DESOFS_FMT: &[u8] = &[];" >> "$INITRD"
fi
mv "$INITRD" build/user/initrd.rs

# The build date – the lower bound of a plausible clock (kernel/drivers/rtc.rs: the RTC may
# not be earlier than this minus 24 h).  SOURCE_DATE_EPOCH when someone sets it on purpose (as
# Linux distributions do for reproducible builds), otherwise the time of this build (as Android:
# the most recent date possible – the strongest floor).  No git: the date never depends on a
# repository or on where the sources came from.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  case "$SOURCE_DATE_EPOCH" in *[!0-9]*) echo "SOURCE_DATE_EPOCH is not a number of seconds."; exit 1 ;; esac
  DESO_BUILD_EPOCH="$SOURCE_DATE_EPOCH"; DESO_BUILD_EPOCH_SOURCE="SOURCE_DATE_EPOCH"
else
  DESO_BUILD_EPOCH="$(date +%s)"; DESO_BUILD_EPOCH_SOURCE="build time"
fi
export DESO_BUILD_EPOCH DESO_BUILD_EPOCH_SOURCE
echo "Build date: $(date -u -d "@$DESO_BUILD_EPOCH" '+%Y-%m-%d %H:%M:%S UTC') (from $DESO_BUILD_EPOCH_SOURCE)"

# The kernel: --cfg desocrypto_no_simd – no AES-NI / PCLMULQDQ code in it at all (its own
# code runs with CR0.TS = 1 and never saves XMM for itself; kernel/arch/x86_64/fpu.rs).
rustc \
  --edition=2024 \
  --target x86_64-unknown-none \
  -C panic=abort \
  -C relocation-model=static \
  -C code-model=kernel \
  -C opt-level=2 \
  -C overflow-checks=on \
  -C link-arg=-Tkernel/linker.ld \
  --check-cfg 'cfg(selftest, desocrypto_test, desotls_test, desocrypto_no_simd)' \
  --cfg desocrypto_no_simd \
  "${SELFTEST_CFG[@]}" \
  -o build/kernel.elf \
  kernel/kernel.rs

# DSB loads the ELF (PT_LOAD segments) at 0xffffffff80000000 - there is no longer
# a flat kernel.bin, a 512 KiB limit or a fixed stack (DSB allocates it).
# kernel.elf keeps its symbols (gdb, addr2line), DSB gets a stripped copy.
command -v readelf >/dev/null 2>&1 || { echo "readelf not found. Install binutils."; exit 1; }
if ! readelf -h build/kernel.elf | grep -q "EXEC"; then
  echo "ERROR: build/kernel.elf is not a static executable (ET_EXEC) - DSB will not load it."
  exit 1
fi
ENTRY=$(readelf -h build/kernel.elf | awk '/Entry point/ {print $4}')
if [ "$ENTRY" != "0xffffffff80000000" ]; then
  echo "ERROR: kernel entry point is $ENTRY, expected 0xffffffff80000000 (kernel/linker.ld)."
  exit 1
fi
objcopy --strip-all build/kernel.elf build/kernel.boot.elf
rm -f build/kernel.bin
KERNEL_START=$((16#$(nm build/kernel.elf | awk '$3 == "__kernel_start" {print $1}')))
KERNEL_END=$((16#$(nm build/kernel.elf | awk '$3 == "__kernel_end" {print $1}')))
echo "kernel.elf: entry $ENTRY, in-memory image $(( (KERNEL_END - KERNEL_START) / 1024 )) KiB (incl. .bss)"

cargo build --release --target x86_64-unknown-uefi

cp target/x86_64-unknown-uefi/release/dsb.efi build/deso.efi
cp build/deso.efi build/EFI/BOOT/BOOTX64.EFI

echo
echo "Done ($MODE):"
ls -lh build/kernel.elf build/kernel.boot.elf build/deso.efi build/EFI/BOOT/BOOTX64.EFI
