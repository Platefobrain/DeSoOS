#!/usr/bin/env bash
# PKG HOST TEST, Rust half (5/6, 6/6): user/lib/pkgfmt.rs and user/lib/pkgsolve.rs compiled for this computer (tests/pkg/pkgfmt-host.rs)
# judges the vectors tools/desopkg.py makes – before QEMU, in seconds.  The same code runs in
# QEMU as /bin/pkgtest (PKG FORMAT TEST).  System names: build/user/ when it exists (the last
# build's /bin), otherwise the fallback list – tools/desopkg.py uses the same rule.
#
#   tests/pkg/pkgfmt-host.sh        (tests/test.sh runs it after tools/desopkg.py --test)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
command -v rustc >/dev/null 2>&1 || { echo "[PKG HOST TEST] FAIL rustc not found"; exit 1; }
OUT="$ROOT/build/pkgfmt-host"
mkdir -p "$OUT"
rustc --edition=2024 -C overflow-checks=on -C opt-level=1 \
  --check-cfg 'cfg(selftest, desocrypto_test, desotls_test, desocrypto_no_simd)' \
  -o "$OUT/pkgfmt-host" tests/pkg/pkgfmt-host.rs
BIN=()
[ -d build/user ] && BIN=(build/user)
python3 tools/desopkg.py vectors -o "$OUT/vectors.bin" --fuzz 3000 ${BIN[@]+--bin "${BIN[@]}"} >/dev/null
"$OUT/pkgfmt-host" "$OUT/vectors.bin" "${BIN[@]}"
# The dependency solver (user/lib/pkgsolve.rs) on the host – a table of every rule.
rustc --edition=2024 -C overflow-checks=on -C opt-level=1 \
  --check-cfg 'cfg(selftest, desocrypto_test, desotls_test, desocrypto_no_simd)' \
  -o "$OUT/pkgsolve-host" tests/pkg/pkgsolve-host.rs
"$OUT/pkgsolve-host"
