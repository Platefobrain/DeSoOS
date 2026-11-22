#!/usr/bin/env bash
# deso-build.sh – build a program for DeSo OS with this SDK, outside the DeSo OS repository
# (docs/abi/SDK.md).  This directory is the whole SDK: copy it anywhere.
#
#   deso-build.sh new DIR                     a new program: DIR/main.rs from template/
#   deso-build.sh build FILE.rs [-o DIR] [-n NAME]
#                                             FILE.rs -> DIR/NAME (default: build/ next to FILE.rs;
#                                             NAME: the file's name, or its directory's for main.rs)
#
# The result is a static ELF (no interpreter) for DeSo OS ABI 1.0 with the ABI note (copy it to /disk/bin on DeSo OS);
# NAME.full next to it keeps the symbols.  Needs rustc (edition 2024 – 1.85 or newer) with the
# x86_64-unknown-none target, and objcopy / readelf (binutils).  No cargo, no network, nothing
# outside this directory and the program's own: the library is compiled from libdeso/ with the
# same rustc as the program, so any rustc that builds it fits – the kernel's ABI is the system
# calls, not Rust's own ABI.  The paths of this directory and of the program do not end up in the
# file (--remap-path-prefix).
set -euo pipefail

SDK="$(cd "$(dirname "$0")" && pwd)"
TARGET=x86_64-unknown-none

die() { echo "deso-build: $*" >&2; exit 1; }

usage() {
  echo "usage: deso-build.sh new DIR"
  echo "       deso-build.sh build FILE.rs [-o DIR] [-n NAME]"
  exit 2
}

valid_name() { [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]]; }

need_tools() {
  command -v rustc >/dev/null 2>&1 || die "rustc not found (https://rustup.rs)"
  local v
  v="$(rustc --version | sed -n 's/^rustc \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
  [ -n "$v" ] || die "cannot read the rustc version: $(rustc --version)"
  set -- $v
  if [ "$1" -lt 1 ] || { [ "$1" -eq 1 ] && [ "$2" -lt 85 ]; }; then
    die "rustc $1.$2 is too old - edition 2024 needs 1.85 or newer (rustup update)"
  fi
  [ -d "$(rustc --print sysroot)/lib/rustlib/$TARGET/lib" ] || die "the $TARGET target is missing (rustup target add $TARGET)"
  command -v objcopy >/dev/null 2>&1 || die "objcopy not found (binutils)"
  command -v readelf >/dev/null 2>&1 || die "readelf not found (binutils)"
}

cmd_new() {
  [ $# = 1 ] || usage
  local dir="$1" name
  name="$(basename "$dir")"
  valid_name "$name" || die "'$name': a program name is 1-32 characters a-z 0-9 _ - (starting with a letter or digit)"
  [ -e "$dir" ] && die "$dir exists - pick a new directory"
  mkdir -p "$dir"
  cp "$SDK/template/main.rs" "$dir/main.rs"
  echo "deso-build: $dir/main.rs - build it with: $0 build $dir/main.rs"
}

# The ABI the library is built for: the bytes the note must carry (u16 major, u16 minor, u32 flags).
abi_version() {
  local f="$SDK/libdeso/src/abi.rs" maj min
  maj="$(sed -n 's/^pub const ABI_MAJOR: u16 = \([0-9]*\);/\1/p' "$f")"
  min="$(sed -n 's/^pub const ABI_MINOR: u16 = \([0-9]*\);/\1/p' "$f")"
  [ -n "$maj" ] && [ -n "$min" ] || die "$f: no ABI_MAJOR / ABI_MINOR"
  echo "$maj $min"
}

cmd_build() {
  [ $# -ge 1 ] || usage
  local src="$1" out="" name=""
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      -o) [ $# -ge 2 ] || usage; out="$2"; shift 2 ;;
      -n) [ $# -ge 2 ] || usage; name="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -f "$src" ] || die "$src: no such file"
  case "$src" in *.rs) ;; *) die "$src: not a .rs file" ;; esac
  need_tools
  local srcdir
  srcdir="$(cd "$(dirname "$src")" && pwd)"
  src="$srcdir/$(basename "$src")"
  if [ -z "$name" ]; then
    name="$(basename "$src" .rs)"
    [ "$name" = main ] && name="$(basename "$srcdir")"
  fi
  valid_name "$name" || die "'$name': a program name is 1-32 characters a-z 0-9 _ - (give one with -n)"
  [ -n "$out" ] || out="$srcdir/build"
  mkdir -p "$out/.libdeso"
  out="$(cd "$out" && pwd)"
  local remap=(--remap-path-prefix "$SDK=/deso-sdk" --remap-path-prefix "$srcdir=.")
  # The library: one code-generation unit, so the ABI note travels with _start.
  rustc --edition=2024 --target "$TARGET" --crate-type rlib --crate-name libdeso \
    -C panic=abort -C relocation-model=static -C opt-level=2 -C codegen-units=1 \
    --check-cfg 'cfg(feature, values("unstable"))' "${remap[@]}" \
    -o "$out/.libdeso/liblibdeso.rlib" "$SDK/libdeso/src/lib.rs" || die "libdeso does not build with $(rustc --version)"
  rustc --edition=2024 --target "$TARGET" \
    -C panic=abort -C relocation-model=static -C opt-level=2 \
    -C "link-arg=-T$SDK/libdeso/link.ld" \
    --extern "libdeso=$out/.libdeso/liblibdeso.rlib" "${remap[@]}" \
    -o "$out/$name.full" "$src" || die "$src does not build"
  readelf -h "$out/$name.full" | grep -q "EXEC" || die "$name: not a static ELF (ET_EXEC) - DeSo OS would not run it"
  # No interpreter: DeSo OS has no dynamic loader (docs/abi/STARTUP.md) - a PT_INTERP header
  # (a link with -dynamic-linker, or a shared library) is refused, not shipped.
  if readelf -lW "$out/$name.full" | grep -q "INTERP"; then
    die "$name: has an interpreter (PT_INTERP) - DeSo OS programs are static, without a dynamic loader"
  fi
  local v want
  v="$(abi_version)"
  set -- $v
  want="$(printf '%02x %02x %02x %02x 00 00 00 00' $(( $1 & 255 )) $(( $1 >> 8 )) $(( $2 & 255 )) $(( $2 >> 8 )))"
  readelf -nW "$out/$name.full" | grep -A1 "^ *DeSo .*0x00000008" | grep -q "description data: $want" \
    || die "$name: no DeSo OS ABI $1.$2 note (libdeso/link.ld)"
  objcopy --strip-all "$out/$name.full" "$out/$name"
  echo "deso-build: $out/$name ($(stat -c %s "$out/$name") B, DeSo OS ABI $1.$2) - copy it to /disk/bin on DeSo OS"
}

case "${1:-}" in
  new) shift; cmd_new "$@" ;;
  build) shift; cmd_build "$@" ;;
  *) usage ;;
esac
