# desopkg file formats (format 1)

DeSo OS v0.82 installs programs from the internet with `/bin/desopkg` (plan: V082-PLAN ver 4.6).
This document is the exact specification of every file desopkg reads or writes. Two independent
implementations follow it and are tested against each other:

| | Where | Used by |
|---|---|---|
| Rust | `user/lib/pkgfmt.rs` (+ `common/elf.rs`, `user/lib/cmdnames.rs`) | `/bin/desopkg` (stage B), `/bin/pkgtest`, `tests/pkg/pkgfmt-host.rs` |
| Python | `tools/desopkg.py` | packing, indexing and signing on the host, test vectors |

Every refusal has a **reason id** (table at the end). Both implementations check in the order
this document gives and stop at the first failure, so a broken file gets the same id from both.

## 1. One rule for every text file

Manifest, index, signature, key store, repository configuration and generation files are read
**byte for byte**:

1. Empty file → `truncated`.
2. Valid UTF-8, else `not_utf8`.
3. No CR byte anywhere (`cr`) – lines end with `\n` only.
4. No control bytes: below 0x20 other than `\n`, or 0x7f (`control`). Tabs are control bytes.
5. The last byte is `\n` (`no_final_newline`).
6. Every line at most 1024 bytes, without its `\n` (`line_too_long`).

Lines are `key=value`; the key is everything before the first `=`, the value everything after
it, unchanged – a space at the end is part of the value (and an error in fields with a limited
character set). Keys come in a fixed order. A line that is not the key expected at that point –
unknown, repeated, out of order, missing, an empty line – is `unexpected_key`; running out of
lines is `truncated`; any line after the last one (`end`, or `hash=` in a generation) is
`trailing_bytes`. Fields that may repeat (`depends`, `conflicts`, `file`, `key`, `program`,
package blocks) say so with their limits; one more than the limit is `too_many`.

Hashes and signatures are always computed over the raw bytes, never over parsed text.

**Small grammars**

| | |
|---|---|
| name (package, program, repo, channel) | `[a-z][a-z0-9-]{0,31}` |
| key id | `[a-z0-9][a-z0-9.-]{0,63}` |
| decimal | `0` or `[1-9][0-9]*`, at most the field's maximum, fits in 64 bits |
| version | `A.B.C`, each a decimal 0–65535; compared as numbers (`1.10.0` > `1.2.0`) |
| ABI | `M.m`, each a decimal 0–65535 |
| hex | lower-case `[0-9a-f]`, exactly the given length |
| date | `YYYY-MM-DDTHH:MM:SSZ` exactly: UTC, capital `T` and `Z`, years 1970–9999, a real calendar day, hours 00–23, seconds 00–59 (no leap second, no other zone) |
| dependency | `name` (any version) or `name>=A.B.C` |

**Relations** (`depends=`, then `conflicts=`, 0–16 each, in manifest, index and generation): a
dependency has valid syntax, is not the package itself and does not repeat a name
(`bad_depends`); a conflict is a valid name, not the package itself, not repeated and not also a
dependency (`bad_conflicts`).

## 2. System names

A **system name** is a name on one of the four lists in `user/lib/cmdnames.rs` (shell built-ins,
`sysctl` commands, information commands, emergency-shell commands) or the name of a file in
`/bin`. The shell never looks for a system name beyond those lists and `/bin`, so a package or
program with such a name could be installed but never run by its name: it is refused with
`reserved_name`. Comparison is plain byte equality (names are already lower-case ASCII; `Sh` is
`bad_name`, not reserved). `/bin` is asked live: on DeSo OS `stat("/bin/<name>")` (exactly the
shell's rule); on the host, the files without a `.` in `build/user/` (what `build.sh` puts into
`/bin`).

## 3. Package (`.pkg`)

```
DESOPKG 1 <M> <D>\n      header: manifest and data lengths
<M bytes: manifest>
<D bytes: file data, one file after another in manifest order>
```

Checks, in order:

1. File larger than 32 + 64 KiB + 32 MiB → `too_big`.
2. Header: a `\n` within the first 32 bytes; exactly four space-separated fields `DESOPKG`, `1`,
   M (decimal 1–65536), D (decimal 0–33554432) → else `bad_header`.
3. header + M + D == file size → else `size_mismatch`.
4. The manifest (below).
5. Manifest `data` == D → else `data_mismatch`.
6. For every file, in order: SHA-256 of its bytes == manifest (`file_sha_mismatch`); for a
   program, every rule the kernel loader checks (`common/elf.rs` `check_program`: ELF header,
   ABI note, segments in the user range, no overlap, W^X, image ≤ 64 MiB, entry in code)
   (`bad_elf`), and the program's ABI == manifest `abi` (`abi_mismatch`).

A package has no signature of its own: the signed index pins its size and SHA-256.

### Manifest

```
format=1
name=witaj
version=1.2.0
arch=x86_64
abi=1.0
data=19105
summary=A greeting for DeSo OS
depends=fonts>=1.0.0                              (0–16)
conflicts=oldwitaj                                (0–16)
file=bin/witaj|206|<sha256>|program               (1–256, in data order)
file=share/witaj/hello.txt|17|<sha256>|data
end
```

| Line | Rule | Reason |
|---|---|---|
| (whole) | at most 64 KiB | `too_big` |
| `format` | `1` | `bad_format` |
| `name` | name grammar; not a system name | `bad_name`, `reserved_name` |
| `version` | version | `bad_version` |
| `arch` | `x86_64` | `bad_arch` |
| `abi` | ABI; major == system's (1), minor ≤ system's (0) | `bad_abi` |
| `data` | decimal ≤ 32 MiB | `bad_data` |
| `summary` | 1–256 bytes | `bad_summary` |
| `depends`, `conflicts` | relations (§1) | |
| `file` | exactly 4 `\|`-separated fields | `bad_file` |
| – path | ≤ 128 bytes; components `[a-z0-9._-]{1,64}`, not `.`/`..`; `bin/<x>` (exactly two components) or `share/…` (at least two) | `bad_path` |
| – size | decimal ≤ 32 MiB | `bad_size` |
| – sha256 | 64 hex | `bad_sha256` |
| – kind | `program` for `bin/`, `data` for `share/` | `bad_kind` |
| – program | name grammar; not a system name; ≤ 8 MiB | `bad_program_name`, `reserved_name`, `program_too_big` |
| – against earlier files | not the same path; not a file that is also a directory of another (`share/a` and `share/a/b`) | `dup_path`, `path_clash` |
| (no `file` line) | | `unexpected_key` |
| after `end` | sum of all sizes == `data` | `data_mismatch` |

The longest path on the disk: `/disk/pkg/<32>/<version 17>-<16>/` + 128 bytes = 206 < 255.

## 4. Index and signature

On the server: `<url>/<channel>/<arch>/index`, `index.sig`, `packages/<name>-<version>.pkg`.

```
format=1
repo=decodesoft
channel=stable
arch=x86_64
serial=42
issued=2026-12-01T10:00:00Z
expires=2026-12-31T10:00:00Z
package=witaj                 (0–4096 blocks)
version=1.2.0
abi=1.0
size=19300
sha256=<64 hex>
depends=fonts>=1.0.0          (0–16)
conflicts=oldwitaj            (0–16)
summary=A greeting for DeSo OS
endpackage
end
```

| Line | Rule | Reason |
|---|---|---|
| (whole) | at most 1 MiB | `too_big` |
| `format` | `1` | `bad_format` |
| `repo`, `channel` | name grammar | `bad_repo`, `bad_channel` |
| `arch` | `x86_64` | `bad_arch` |
| `serial` | decimal 1 … 2⁶⁴−1 | `bad_serial` |
| `issued`, `expires` | date | `bad_date` |
| (after `expires`) | `issued` < `expires`, at most 30 days apart | `bad_times` |
| block count | at most 4096 | `too_many` |
| `package` | name grammar | `bad_name` |
| `version` | version; (name, version) not seen before | `bad_version`, `dup_package` |
| `abi` | ABI (any – a package for a newer ABI is skipped at install) | `bad_abi` |
| `size` | decimal 1 … the largest possible package | `bad_size` |
| `sha256` | 64 hex | `bad_sha256` |
| `summary` | 1–256 bytes | `bad_summary` |

An index may hold several versions of one package (`install name=version`).

**Against the clock** (step 5 of `refresh`): `expires` > now (`expired`); `issued` ≤ now + 1 day
(`issued_in_future`). **Against `/etc/desopkg/repo`**: `repo`, `channel`, `arch` equal
(`repo_mismatch`).

**A downloaded package against its entry**: exactly `size` bytes (`pkg_size_mismatch`; the
download is stopped as soon as it passes `size`); SHA-256 of the whole file (`pkg_sha_mismatch`);
the package itself (§3); manifest `name`, `version`, `abi`, `summary`, `depends` and `conflicts`
(as written, in order) == the entry (`index_mismatch`).

### `index.sig`

```
SIGNATURE 1
alg=p256
keyid=decodesoft-2026-01
signature=<hex DER>
end
```

| Line | Rule | Reason |
|---|---|---|
| (whole) | at most 1 KiB | `too_big` |
| `alg` | `p256` | `bad_alg` |
| `keyid` | key id grammar | `bad_keyid` |
| `signature` | non-empty, even-length hex; strict DER `SEQUENCE { INTEGER r, INTEGER s }`: short-form lengths, minimal positive integers, nothing after, total 8–72 bytes; 1 ≤ r, s < n | `sig_encoding` |
| | low-S: s ≤ ⌊n/2⌋ | `high_s` |

Signed message: `DESO-INDEX-SIGNATURE-V1\n` + `alg=<alg>\n` + `keyid=<keyid>\n` + the raw index
bytes; ECDSA P-256 with SHA-256. The key id must be in `/etc/desopkg/keys` (`unknown_key`);
the signature must verify (`bad_signature`). The signature is checked **before** the index is
read. `alg` exists so Ed25519 can be added without a new format.

### `/etc/desopkg/keys`

```
DESOPKG-KEYS 1
key=decodesoft-2026-01|p256|<130 hex: 04 ‖ X ‖ Y>     (0–16)
end
```

Each key: three fields, key id grammar, `p256`, key id not repeated, an uncompressed point on
the curve – else `bad_key`. The self-test image trusts only `deso-test-1`
(`tests/pkg/test-key.pem`, a test key); a normal image the keys in `user/etc/desopkg/keys`.

### `/etc/desopkg/repo`

```
format=1
url=https://decodesoft.pl/deso/
repo=decodesoft
channel=stable
arch=x86_64
end
```

`url`: `https://`, a host of `[a-z0-9.-]`, then a path of `[a-z0-9._/-]` ending with `/` (no
port, no user, no `//`) – else `bad_url`. Both `/etc/desopkg` files are sealed at boot.

### Accepted index: `/disk/pkg/index/<serial>`

```
DESO-ACCEPTED-INDEX 1 <index size> <signature size>\n
<index bytes><index.sig bytes>
```

Header within the first 64 bytes, four fields, index size 1 … 1 MiB, signature size 1 … 1 KiB
(`bad_header`); header + both == file size (`size_mismatch` – e.g. an unfinished write). Then the
signature, then the index. An expired accepted index still counts as accepted (desopkg runs
`refresh`). The two newest valid ones are kept; the newest one that passes is in force.

## 5. Generation: `/disk/pkg/gen/<n>`

```
format=1
generation=3
op=install
package=witaj                       (0–64 blocks)
version=1.2.0
dir=1.2.0-5f2a9c01d4e7b3a8
reason=explicit
manifest=<SHA-256 of the package file in that directory>
depends=fonts>=1.0.0                (0–16)
conflicts=oldwitaj                  (0–16)
program=witaj                       (0–256; 256 in the whole generation)
endpackage
end
hash=<64 hex>
```

| Line | Rule | Reason |
|---|---|---|
| (whole) | at most 256 KiB | `too_big` |
| `generation` | decimal 1 … 2⁶⁴−1; == `<n>` of the file name | `bad_generation`, `generation_mismatch` |
| `op` | `install`, `update`, `remove`, `reinstall` | `bad_op` |
| block count | at most 64 | `too_many` |
| `package` | name grammar; not a system name; not repeated | `bad_name`, `reserved_name`, `dup_package` |
| `dir` | `<version of this block>-<16 hex>` | `bad_dir` |
| `reason` | `explicit` or `dependency` | `bad_reason` |
| `manifest` | 64 hex | `bad_manifest` |
| `program` | name grammar; not a system name; not used by any package of the generation; ≤ 256 in all | `bad_program_name`, `reserved_name`, `dup_program`, `too_many` |
| `hash` | 64 hex == SHA-256 of the file from its first byte to the `\n` just before `hash=` | `bad_hash` |

Then each package against `/disk/pkg/<package>/<dir>/package`: missing (`missing_package`);
SHA-256 of that file == `manifest` (`manifest_mismatch`); the manifest valid (§3); `name`,
`version`, the program list (in manifest order), `depends` and `conflicts` equal
(`entry_mismatch`).

**The current generation is the highest `n` whose file passes all of this** – like the DeSoFS
superblock. A file that is unfinished or damaged fails and the previous one stays in force.

## 6. Test vectors (`DESOPKG-VECTORS 1`)

`tools/desopkg.py vectors` writes the files of §3–§5 – good ones and every rule broken on its
own (CRLF, an extra `\n`, a space at the end of a value, a byte after `end` or `hash`, one byte
of a manifest or of a signed index changed, high-S, non-DER, another key, …) – each with the
verdict it is meant to get, checked by the tool itself first. Then random mutations (fixed seed)
with the tool's own verdict. `user/lib/pkgvec.rs` reads them:

```
DESOPKG-VECTORS 1 <count>\n
REC <kind> <expect> <parts> <description>\n      (count times)
<label> <length>\n<bytes>\n                       (parts times)
```

Kinds: `manifest`, `pkg`, `pkgidx` (parts `index`, `pkg`, `entry` = `"<name> <version>"`;
`not_in_index`), `index`, `repo`, `time` (`now` in Unix seconds), `sig`, `accepted`, `keys`,
`repocfg`, `gen` (`gen`, `n`, `manifest:<package>`…), `vercmp` (`lt`/`eq`/`gt`), `reserved`
(every system name refused as a package name and as a program; the name list equal on both
sides, else `names_differ`).

Run on the host by `tests/test.sh` (PKG HOST TEST: `tools/desopkg.py --test`,
`tests/pkg/pkgfmt-host.sh`) and in QEMU by PKG FORMAT TEST (`/bin/pkgtest`).

## 7. Reasons

| Group | Ids |
|---|---|
| text | `truncated` `not_utf8` `cr` `control` `no_final_newline` `line_too_long` `unexpected_key` `trailing_bytes` `too_many` `too_big` |
| names, versions | `bad_format` `bad_name` `reserved_name` `bad_version` `bad_arch` `bad_abi` `bad_depends` `bad_conflicts` |
| manifest | `bad_data` `bad_summary` `bad_file` `bad_path` `bad_size` `bad_sha256` `bad_kind` `bad_program_name` `program_too_big` `dup_path` `path_clash` `data_mismatch` |
| package | `bad_header` `size_mismatch` `file_sha_mismatch` `bad_elf` `abi_mismatch` |
| index | `bad_repo` `bad_channel` `bad_serial` `bad_date` `bad_times` `dup_package` `expired` `issued_in_future` `repo_mismatch` `pkg_size_mismatch` `pkg_sha_mismatch` `index_mismatch` `not_in_index` |
| signature, keys, repo | `bad_alg` `bad_keyid` `sig_encoding` `high_s` `unknown_key` `bad_signature` `bad_key` `bad_url` |
| generation | `bad_generation` `generation_mismatch` `bad_op` `bad_dir` `bad_reason` `bad_manifest` `dup_program` `bad_hash` `missing_package` `manifest_mismatch` `entry_mismatch` |

## 8. What this does not protect against

The signature protects the index and the packages on the server and on the way; `serial` and
`expires` (with the time from NTS) protect against an old index from the server. A local program
with access to `/disk` (DeSoFS has no permissions) can change package files, generations and the
accepted indexes – including putting back an older, genuinely signed index, which takes the
serial back with it. When the newest accepted index is damaged on the disk, the previous valid
one is used and the next `refresh` accepts any serial above it again: a deliberate trade-off – a
working system instead of a refusal after media damage, not full rollback protection.
