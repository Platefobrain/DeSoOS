#!/usr/bin/env python3
"""desopkg host tool (docs/pkg/FORMAT.md) – Python 3 + openssl.

An independent implementation of the package formats: it makes packages, indexes and their
signatures, checks them, and makes the PKG FORMAT TEST vectors that user/lib/pkgfmt.rs (Rust,
in QEMU and on the host) must judge exactly the same way – the same verdict and the same reason
id.

  desopkg.py pack DIR -o NAME-VERSION.pkg     a package from DIR/desopkg.meta, DIR/bin, DIR/share
  desopkg.py index REPODIR --serial N --key K.pem [--keyid ID] [--days 30]
                                              REPODIR/index + index.sig from REPODIR/packages/*.pkg
  desopkg.py keys K.pem --keyid ID [-o FILE]  the /etc/desopkg/keys file for a key
  desopkg.py check FILE [--keys KEYS] [--sig SIG] [--gen N]
                                              an independent check (kind from its first line)
  desopkg.py vectors -o FILE [--bin DIR] [--fuzz N]
                                              the PKG FORMAT TEST vectors (every hand-written one
                                              judged here first: a verdict that is not the
                                              intended one stops the tool) + N random mutations
                                              (default 400, fixed seed) with this tool's verdict
  desopkg.py --test [--bin DIR]               every rule on its own (mutations), the reserved
                                              names, the time and key edge cases: "[PKG HOST TEST]"

DIR/desopkg.meta – the package's description, `key=value` lines in this order:
  name=…  version=A.B.C  summary=…  [depends=… (0–16)]  [conflicts=… (0–16)]
Files: DIR/bin/<program> (programs: built for DeSo OS ABI 1.0) and DIR/share/… (data), in
sorted path order.

The private key never goes into the repository or the image – only `keys` output (the public
point).  Signatures are normalised to low-S.  System names: user/lib/cmdnames.rs (the four lists)
plus the programs of /bin – taken from build/user/ (what build.sh puts into the image), or with
--bin DIR; without either, the few programs every image has (sh, ls, cat, init).
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ------------------------------------------------------------
# Limits (FORMAT.md §3, §4, §5) – the same numbers as user/lib/pkgfmt.rs
# ------------------------------------------------------------
MAX_LINE = 1024
MAX_MANIFEST = 64 * 1024
MAX_DATA = 32 * 1024 * 1024
MAX_PKG = 32 + MAX_MANIFEST + MAX_DATA
MAX_PROGRAM = 8 * 1024 * 1024
MAX_FILES = 256
MAX_DEPENDS = 16
MAX_CONFLICTS = 16
MAX_PATH = 128
MAX_COMPONENT = 64
MAX_SUMMARY = 256
MAX_INDEX = 1024 * 1024
MAX_INDEX_PACKAGES = 4096
MAX_SIG = 1024
MAX_KEYS = 16
MAX_GENERATION = 256 * 1024
MAX_GEN_PACKAGES = 64
MAX_GEN_PROGRAMS = 256
MAX_INDEX_DAYS = 30
DAY = 86400
U64_MAX = 2**64 - 1
SYSTEM_ABI = (1, 0)
ARCH = "x86_64"
SIG_DOMAIN = b"DESO-INDEX-SIGNATURE-V1\n"
OPS = ("install", "update", "remove", "reinstall")

# P-256
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


class Refused(Exception):
    """A refusal with its reason id (docs/pkg/FORMAT.md, "Reasons")."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def fail(reason):
    raise Refused(reason)


# ------------------------------------------------------------
# Small grammars
# ------------------------------------------------------------
NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
KEYID_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
COMPONENT_RE = re.compile(r"[a-z0-9._-]{1,64}")


def valid_name(s):
    return NAME_RE.fullmatch(s) is not None


def valid_keyid(s):
    return KEYID_RE.fullmatch(s) is not None


def decimal(s, maximum):
    if not re.fullmatch(r"[0-9]{1,20}", s) or (s[0] == "0" and len(s) > 1):
        return None
    v = int(s)
    if v > U64_MAX or v > maximum:
        return None
    return v


def hex_bytes(s, n):
    if not re.fullmatch(r"[0-9a-f]*", s) or len(s) != 2 * n:
        return None
    return bytes.fromhex(s)


def parse_version(s):
    parts = s.split(".")
    if len(parts) != 3:
        return None
    vals = [decimal(p, 65535) for p in parts]
    if any(v is None for v in vals):
        return None
    return tuple(vals)


def ver_str(v):
    return "%d.%d.%d" % v


def parse_abi(s):
    a, sep, b = s.partition(".")
    if not sep:
        return None
    x, y = decimal(a, 65535), decimal(b, 65535)
    if x is None or y is None:
        return None
    return (x, y)


def parse_date(s):
    b = s.encode()
    if len(b) != 20 or b[4:5] != b"-" or b[7:8] != b"-" or b[10:11] != b"T" or b[13:14] != b":" or b[16:17] != b":" or b[19:20] != b"Z":
        return None

    def num(lo, hi):
        part = b[lo:hi]
        if not all(0x30 <= c <= 0x39 for c in part):
            return None
        return int(part)

    vals = [num(0, 4), num(5, 7), num(8, 10), num(11, 13), num(14, 16), num(17, 19)]
    if any(v is None for v in vals):
        return None
    y, mo, d, h, mi, se = vals
    if not (1970 <= y <= 9999) or not (1 <= mo <= 12) or d < 1 or h > 23 or mi > 59 or se > 59:
        return None
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    mdays = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if d > mdays[mo - 1]:
        return None
    import datetime

    days = (datetime.date(y, mo, d) - datetime.date(1970, 1, 1)).days
    return days * DAY + h * 3600 + mi * 60 + se


def fmt_date(t):
    import datetime

    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(b):
    return hashlib.sha256(b).digest()


# ------------------------------------------------------------
# The text rule (FORMAT.md §1)
# ------------------------------------------------------------
def text_lines(b):
    if len(b) == 0:
        fail("truncated")
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        fail("not_utf8")
    if b"\r" in b:
        fail("cr")
    if any((c < 0x20 and c != 0x0A) or c == 0x7F for c in b):
        fail("control")
    if b[-1] != 0x0A:
        fail("no_final_newline")
    lines = s[:-1].split("\n")
    if any(len(l.encode()) > MAX_LINE for l in lines):
        fail("line_too_long")
    return lines


class Cursor:
    def __init__(self, b):
        self.b = b
        self.lines = text_lines(b)
        self.pos = 0

    def next_is(self, key):
        if self.pos >= len(self.lines):
            return False
        l = self.lines[self.pos]
        return len(l) > len(key) and l.startswith(key) and l[len(key)] == "="

    def kv(self, key):
        if self.pos >= len(self.lines):
            fail("truncated")
        if not self.next_is(key):
            fail("unexpected_key")
        l = self.lines[self.pos]
        self.pos += 1
        return l[len(key) + 1 :]

    def lit(self, text):
        if self.pos >= len(self.lines):
            fail("truncated")
        if self.lines[self.pos] != text:
            fail("unexpected_key")
        self.pos += 1

    def many(self, key, maximum, each):
        n = 0
        while self.next_is(key):
            n += 1
            if n > maximum:
                fail("too_many")
            each(self.kv(key))
        return n

    def done(self):
        if self.pos < len(self.lines):
            fail("trailing_bytes")

    def offset(self):
        """Byte offset of the next line."""
        return sum(len(l.encode()) + 1 for l in self.lines[: self.pos])


# ------------------------------------------------------------
# depends / conflicts
# ------------------------------------------------------------
def parse_dep(s):
    n, sep, v = s.partition(">=")
    if sep:
        if not valid_name(n):
            return None
        ver = parse_version(v)
        if ver is None:
            return None
        return (n, ver)
    if not valid_name(s):
        return None
    return (s, None)


def read_relations(c, me):
    raw, deps = [], []

    def dep(v):
        d = parse_dep(v)
        if d is None or d[0] == me or any(x[0] == d[0] for x in deps):
            fail("bad_depends")
        deps.append(d)
        raw.append(v)

    c.many("depends", MAX_DEPENDS, dep)
    conflicts = []

    def conf(v):
        if not valid_name(v) or v == me or v in conflicts or any(x[0] == v for x in deps):
            fail("bad_conflicts")
        conflicts.append(v)

    c.many("conflicts", MAX_CONFLICTS, conf)
    return raw, deps, conflicts


# ------------------------------------------------------------
# Manifest and package (FORMAT.md §3)
# ------------------------------------------------------------
def path_ok(p):
    if len(p) == 0 or len(p.encode()) > MAX_PATH:
        return False
    comps = p.split("/")
    for c in comps:
        if c in (".", "..") or COMPONENT_RE.fullmatch(c) is None:
            return False
    if comps[0] == "bin":
        return len(comps) == 2
    if comps[0] == "share":
        return len(comps) >= 2
    return False


def parse_manifest(b, system_name):
    if len(b) > MAX_MANIFEST:
        fail("too_big")
    c = Cursor(b)
    if c.kv("format") != "1":
        fail("bad_format")
    name = c.kv("name")
    if not valid_name(name):
        fail("bad_name")
    if system_name(name):
        fail("reserved_name")
    version = parse_version(c.kv("version"))
    if version is None:
        fail("bad_version")
    if c.kv("arch") != ARCH:
        fail("bad_arch")
    abi = parse_abi(c.kv("abi"))
    if abi is None or abi[0] != SYSTEM_ABI[0] or abi[1] > SYSTEM_ABI[1]:
        fail("bad_abi")
    data = decimal(c.kv("data"), MAX_DATA)
    if data is None:
        fail("bad_data")
    summary = c.kv("summary")
    if len(summary) == 0 or len(summary.encode()) > MAX_SUMMARY:
        fail("bad_summary")
    depends_raw, depends, conflicts = read_relations(c, name)
    files = []
    total = [0]

    def file(v):
        parts = v.split("|")
        if len(parts) != 4:
            fail("bad_file")
        path = parts[0]
        if not path_ok(path):
            fail("bad_path")
        size = decimal(parts[1], MAX_DATA)
        if size is None:
            fail("bad_size")
        digest = hex_bytes(parts[2], 32)
        if digest is None:
            fail("bad_sha256")
        is_bin = path.startswith("bin/")
        if parts[3] == "program" and is_bin:
            kind = "program"
        elif parts[3] == "data" and not is_bin:
            kind = "data"
        else:
            fail("bad_kind")
        if kind == "program":
            prog = path[4:]
            if not valid_name(prog):
                fail("bad_program_name")
            if system_name(prog):
                fail("reserved_name")
            if size > MAX_PROGRAM:
                fail("program_too_big")
        for f in files:
            if f["path"] == path:
                fail("dup_path")
            a, bb = f["path"], path
            if (len(a) > len(bb) and a.startswith(bb) and a[len(bb)] == "/") or (len(bb) > len(a) and bb.startswith(a) and bb[len(a)] == "/"):
                fail("path_clash")
        files.append({"path": path, "size": size, "sha256": digest, "kind": kind, "offset": total[0]})
        total[0] += size

    n = c.many("file", MAX_FILES, file)
    if n == 0:
        fail("unexpected_key" if c.pos < len(c.lines) else "truncated")
    c.lit("end")
    c.done()
    if total[0] != data:
        fail("data_mismatch")
    return {
        "name": name,
        "version": version,
        "abi": abi,
        "data": data,
        "summary": summary,
        "depends_raw": depends_raw,
        "conflicts": conflicts,
        "files": files,
    }


def programs_of(m):
    return [f["path"][4:] for f in m["files"] if f["kind"] == "program"]


def parse_pkg_header(b):
    nl = b[:32].find(b"\n")
    if nl < 0:
        fail("bad_header")
    try:
        line = b[:nl].decode("utf-8")
    except UnicodeDecodeError:
        fail("bad_header")
    t = line.split(" ")
    if len(t) < 2 or t[0] != "DESOPKG" or t[1] != "1":
        fail("bad_header")
    m = decimal(t[2], MAX_MANIFEST) if len(t) > 2 else None
    if m is None or m == 0:
        fail("bad_header")
    d = decimal(t[3], MAX_DATA) if len(t) > 3 else None
    if d is None or len(t) > 4:
        fail("bad_header")
    return nl + 1, m, d


def parse_pkg(b, system_name):
    if len(b) > MAX_PKG:
        fail("too_big")
    h, m, d = parse_pkg_header(b)
    if h + m + d != len(b):
        fail("size_mismatch")
    mb = b[h : h + m]
    data = b[h + m :]
    man = parse_manifest(mb, system_name)
    if man["data"] != d:
        fail("data_mismatch")
    for f in man["files"]:
        part = data[f["offset"] : f["offset"] + f["size"]]
        if sha256(part) != f["sha256"]:
            fail("file_sha_mismatch")
        if f["kind"] == "program":
            try:
                abi = check_program(part, SYSTEM_ABI)
            except ElfRefused:
                fail("bad_elf")
            if abi != man["abi"]:
                fail("abi_mismatch")
    return man, mb, data


# ------------------------------------------------------------
# ELF programs – the rules of common/elf.rs (parse_with, abi_of_with, check_program)
# ------------------------------------------------------------
class ElfRefused(Exception):
    pass


PROGRAM_MIN = 0x10_0000
PROGRAM_MAX = 0x0000_1000_0000_0000 - (1 << 30) - (1 << 30)
PROGRAM_MAX_IMAGE = 64 * 1024 * 1024


def _u(b, o, n):
    if o < 0 or o + n > len(b):
        raise ElfRefused("outside")
    return int.from_bytes(b[o : o + n], "little")


def check_program(b, system):
    """The ABI (major, minor) of a program the kernel would start, else ElfRefused."""
    L = len(b)
    if L < 64 or b[0:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        raise ElfRefused("header")
    if _u(b, 18, 2) != 0x3E or _u(b, 16, 2) != 2:
        raise ElfRefused("machine/type")
    entry = _u(b, 24, 8)
    phoff = _u(b, 32, 8)
    phentsize = _u(b, 54, 2)
    phnum = _u(b, 56, 2)
    if phentsize < 56 or phnum > 256 or phoff + phnum * phentsize > L:
        raise ElfRefused("phdrs")
    segs = []
    for i in range(phnum):
        ph = phoff + i * phentsize
        if _u(b, ph, 4) != 1:
            continue
        flags, off, vaddr, filesz, memsz = _u(b, ph + 4, 4), _u(b, ph + 8, 8), _u(b, ph + 16, 8), _u(b, ph + 32, 8), _u(b, ph + 40, 8)
        if memsz == 0:
            continue
        if filesz > memsz or off + filesz > L or vaddr + memsz > U64_MAX or len(segs) == 16:
            raise ElfRefused("segment")
        segs.append((vaddr, memsz, flags))
    if not segs:
        raise ElfRefused("no segments")
    # ABI note
    ph_end = phoff + phnum * phentsize
    areas = []
    found = None
    for i in range(phnum):
        ph = phoff + i * phentsize
        if _u(b, ph, 4) != 4:
            continue
        off, size = _u(b, ph + 8, 8), _u(b, ph + 32, 8)
        end = off + size
        if end > U64_MAX or len(areas) == 4 or end > L or size > 4096 or off % 4 != 0:
            raise ElfRefused("note header")

        def overlaps(lo, hi):
            return size != 0 and off < hi and lo < end

        if overlaps(0, 64) or overlaps(phoff, ph_end) or any(overlaps(lo, hi) for lo, hi in areas):
            raise ElfRefused("note overlap")
        areas.append((off, end))
        pos = off
        while pos < end:
            if end - pos < 12:
                raise ElfRefused("note short")
            namesz, descsz, kind = _u(b, pos, 4), _u(b, pos + 4, 4), _u(b, pos + 8, 4)
            name = pos + 12
            desc = name + ((namesz + 3) & ~3)
            nxt = desc + ((descsz + 3) & ~3)
            if nxt > end:
                raise ElfRefused("note length")
            deso = namesz >= 4 and b[name : name + 4] == b"DeSo"
            if deso:
                if not (namesz == 5 and desc - name == 8 and b[name + 4 : name + 8] == b"\0\0\0\0"):
                    raise ElfRefused("note name")
            if deso and kind == 1:
                if descsz != 8:
                    raise ElfRefused("note desc")
                if found is not None:
                    raise ElfRefused("twice")
                found = (_u(b, desc, 2), _u(b, desc + 2, 2), _u(b, desc + 4, 4))
            pos = nxt
    abi = (1, 0)
    if found is not None:
        major, minor, flags = found
        if flags != 0 or major != system[0] or minor > system[1]:
            raise ElfRefused("abi")
        abi = (major, minor)
    for i, (va, ms, _) in enumerate(segs):
        for vb, mt, _ in segs[i + 1 :]:
            if va < vb + mt and vb < va + ms:
                raise ElfRefused("overlap")
    for va, ms, fl in segs:
        if va < PROGRAM_MIN or va + ms > PROGRAM_MAX:
            raise ElfRefused("range")
        if fl & 2 and fl & 1:
            raise ElfRefused("w^x")
    lo = min(s[0] for s in segs)
    hi = max(s[0] + s[1] for s in segs)
    if hi - lo > PROGRAM_MAX_IMAGE:
        raise ElfRefused("too big")
    if not any(fl & 1 and va <= entry < va + ms for va, ms, fl in segs):
        raise ElfRefused("entry")
    return abi


def elf_program(major=1, minor=0, flags=0, seg_flags=5, with_note=True):
    """A minimal DeSo OS program: ELF header, PT_LOAD (`seg_flags`, default R+X) over the whole
    file at 0x400000, PT_NOTE with the ABI note (major.minor, flags), two bytes of code (jmp $)."""
    phnum = 2 if with_note else 1
    note_off = 64 + 56 * phnum
    note = b""
    if with_note:
        note = (5).to_bytes(4, "little") + (8).to_bytes(4, "little") + (1).to_bytes(4, "little") + b"DeSo\0\0\0\0"
        note += major.to_bytes(2, "little") + minor.to_bytes(2, "little") + flags.to_bytes(4, "little")
    code_off = note_off + len(note)
    total = code_off + 2
    base = 0x400000
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4], eh[5], eh[6] = 2, 1, 1
    eh[16:18] = (2).to_bytes(2, "little")
    eh[18:20] = (0x3E).to_bytes(2, "little")
    eh[20:24] = (1).to_bytes(4, "little")
    eh[24:32] = (base + code_off).to_bytes(8, "little")
    eh[32:40] = (64).to_bytes(8, "little")
    eh[52:54] = (64).to_bytes(2, "little")
    eh[54:56] = (56).to_bytes(2, "little")
    eh[56:58] = phnum.to_bytes(2, "little")

    def ph(t, fl, off, va, fs, ms, align):
        return b"".join(
            [t.to_bytes(4, "little"), fl.to_bytes(4, "little"), off.to_bytes(8, "little"), va.to_bytes(8, "little"), va.to_bytes(8, "little"), fs.to_bytes(8, "little"), ms.to_bytes(8, "little"), align.to_bytes(8, "little")]
        )

    out = bytes(eh) + ph(1, seg_flags, 0, base, total, total, 0x1000)
    if with_note:
        out += ph(4, 4, note_off, base + note_off, len(note), len(note), 4)
    out += note + b"\xeb\xfe"
    assert len(out) == total
    return out


# ------------------------------------------------------------
# Index (FORMAT.md §4)
# ------------------------------------------------------------
def parse_index(b):
    if len(b) > MAX_INDEX:
        fail("too_big")
    c = Cursor(b)
    if c.kv("format") != "1":
        fail("bad_format")
    repo = c.kv("repo")
    if not valid_name(repo):
        fail("bad_repo")
    channel = c.kv("channel")
    if not valid_name(channel):
        fail("bad_channel")
    arch = c.kv("arch")
    if arch != ARCH:
        fail("bad_arch")
    serial = decimal(c.kv("serial"), U64_MAX)
    if serial is None or serial == 0:
        fail("bad_serial")
    issued = parse_date(c.kv("issued"))
    if issued is None:
        fail("bad_date")
    expires = parse_date(c.kv("expires"))
    if expires is None:
        fail("bad_date")
    if issued >= expires or expires - issued > MAX_INDEX_DAYS * DAY:
        fail("bad_times")
    packages = []
    while c.next_is("package"):
        if len(packages) == MAX_INDEX_PACKAGES:
            fail("too_many")
        name = c.kv("package")
        if not valid_name(name):
            fail("bad_name")
        version = parse_version(c.kv("version"))
        if version is None:
            fail("bad_version")
        if any(p["name"] == name and p["version"] == version for p in packages):
            fail("dup_package")
        abi = parse_abi(c.kv("abi"))
        if abi is None:
            fail("bad_abi")
        size = decimal(c.kv("size"), MAX_PKG)
        if size is None or size == 0:
            fail("bad_size")
        digest = hex_bytes(c.kv("sha256"), 32)
        if digest is None:
            fail("bad_sha256")
        depends_raw, _, conflicts = read_relations(c, name)
        summary = c.kv("summary")
        if len(summary) == 0 or len(summary.encode()) > MAX_SUMMARY:
            fail("bad_summary")
        c.lit("endpackage")
        packages.append(
            {"name": name, "version": version, "abi": abi, "size": size, "sha256": digest, "depends_raw": depends_raw, "conflicts": conflicts, "summary": summary}
        )
    c.lit("end")
    c.done()
    return {"repo": repo, "channel": channel, "arch": arch, "serial": serial, "issued": issued, "expires": expires, "packages": packages}


def check_index_time(idx, now):
    if idx["expires"] <= now:
        fail("expired")
    if idx["issued"] > min(now + DAY, U64_MAX):
        fail("issued_in_future")


def check_index_repo(idx, cfg):
    if idx["repo"] != cfg["repo"] or idx["channel"] != cfg["channel"] or idx["arch"] != cfg["arch"]:
        fail("repo_mismatch")


def find_entry(idx, name, version):
    for p in idx["packages"]:
        if p["name"] == name and p["version"] == version:
            return p
    return None


def check_pkg_against_index(b, e, system_name):
    if len(b) != e["size"]:
        fail("pkg_size_mismatch")
    if sha256(b) != e["sha256"]:
        fail("pkg_sha_mismatch")
    m, _, _ = parse_pkg(b, system_name)
    if (
        m["name"] != e["name"]
        or m["version"] != e["version"]
        or m["abi"] != e["abi"]
        or m["summary"] != e["summary"]
        or m["depends_raw"] != e["depends_raw"]
        or m["conflicts"] != e["conflicts"]
    ):
        fail("index_mismatch")
    return m


# ------------------------------------------------------------
# Signature, keys, repository configuration
# ------------------------------------------------------------
def der_int(b, i):
    if i >= len(b) or b[i] != 0x02 or i + 1 >= len(b):
        return None
    n = b[i + 1]
    if n == 0 or n >= 0x80 or i + 2 + n > len(b):
        return None
    v = b[i + 2 : i + 2 + n]
    if v[0] & 0x80:
        return None
    if v[0] == 0 and n > 1 and not (v[1] & 0x80):
        return None
    if v[0] == 0 and n > 1:
        v = v[1:]
    return v, i + 2 + n


def check_der_p256(der):
    if len(der) < 8 or len(der) > 72 or der[0] != 0x30 or der[1] != len(der) - 2 or der[1] >= 0x80:
        fail("sig_encoding")
    a = der_int(der, 2)
    if a is None:
        fail("sig_encoding")
    r, i = a
    a = der_int(der, i)
    if a is None:
        fail("sig_encoding")
    s, j = a
    if j != len(der) or len(r) > 32 or len(s) > 32:
        fail("sig_encoding")
    r, s = int.from_bytes(r, "big"), int.from_bytes(s, "big")
    if r == 0 or s == 0 or r >= P256_N or s >= P256_N:
        fail("sig_encoding")
    if s > P256_N // 2:
        fail("high_s")


def parse_signature(b):
    if len(b) > MAX_SIG:
        fail("too_big")
    c = Cursor(b)
    c.lit("SIGNATURE 1")
    alg = c.kv("alg")
    if alg != "p256":
        fail("bad_alg")
    keyid = c.kv("keyid")
    if not valid_keyid(keyid):
        fail("bad_keyid")
    h = c.kv("signature")
    if len(h) == 0 or len(h) % 2 != 0:
        fail("sig_encoding")
    der = hex_bytes(h, len(h) // 2)
    if der is None:
        fail("sig_encoding")
    check_der_p256(der)
    c.lit("end")
    c.done()
    return {"alg": alg, "keyid": keyid, "der": der}


def signed_message(alg, keyid, index):
    return SIG_DOMAIN + b"alg=" + alg.encode() + b"\nkeyid=" + keyid.encode() + b"\n" + index


def point_ok(p):
    if len(p) != 65 or p[0] != 4:
        return False
    x, y = int.from_bytes(p[1:33], "big"), int.from_bytes(p[33:], "big")
    if x >= P256_P or y >= P256_P:
        return False
    return (y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0


def parse_keys(b):
    c = Cursor(b)
    c.lit("DESOPKG-KEYS 1")
    keys = []

    def key(v):
        parts = v.split("|")
        if len(parts) != 3 or not valid_keyid(parts[0]) or parts[1] != "p256" or any(k["keyid"] == parts[0] for k in keys):
            fail("bad_key")
        point = hex_bytes(parts[2], 65)
        if point is None or not point_ok(point):
            fail("bad_key")
        keys.append({"keyid": parts[0], "point": point})

    c.many("key", MAX_KEYS, key)
    c.lit("end")
    c.done()
    return keys


def openssl_verify(point, msg, der):
    with tempfile.TemporaryDirectory() as d:
        pub = os.path.join(d, "pub.der")
        with open(pub, "wb") as f:
            f.write(SPKI_P256_PREFIX + point)
        m = os.path.join(d, "msg")
        with open(m, "wb") as f:
            f.write(msg)
        s = os.path.join(d, "sig")
        with open(s, "wb") as f:
            f.write(der)
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pub, "-keyform", "DER", "-signature", s, m], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return r.returncode == 0 and b"Verified OK" in r.stdout


def verify_index(index, sig, keys):
    s = parse_signature(sig)
    key = next((k for k in keys if k["keyid"] == s["keyid"]), None)
    if key is None:
        fail("unknown_key")
    if not openssl_verify(key["point"], signed_message(s["alg"], s["keyid"], index), s["der"]):
        fail("bad_signature")


def url_ok(u):
    if not u.startswith("https://"):
        return False
    rest = u[8:]
    hostport, sep, path = rest.partition("/")
    if not sep:
        return False
    host, colon, port = hostport.partition(":")
    if colon:
        p = decimal(port, 65535)
        if p is None or p == 0:
            return False
    return (
        len(host) > 0
        and re.fullmatch(r"[a-z0-9.-]+", host) is not None
        and (path == "" or path.endswith("/"))
        and re.fullmatch(r"[a-z0-9._/-]*", path) is not None
        and "//" not in path
    )


def parse_repo_config(b):
    c = Cursor(b)
    if c.kv("format") != "1":
        fail("bad_format")
    url = c.kv("url")
    if not url_ok(url):
        fail("bad_url")
    repo = c.kv("repo")
    if not valid_name(repo):
        fail("bad_repo")
    channel = c.kv("channel")
    if not valid_name(channel):
        fail("bad_channel")
    arch = c.kv("arch")
    if arch != ARCH:
        fail("bad_arch")
    c.lit("end")
    c.done()
    return {"url": url, "repo": repo, "channel": channel, "arch": arch}


# ------------------------------------------------------------
# Accepted index
# ------------------------------------------------------------
def parse_accepted(b):
    nl = b[:64].find(b"\n")
    if nl < 0:
        fail("bad_header")
    try:
        line = b[:nl].decode("utf-8")
    except UnicodeDecodeError:
        fail("bad_header")
    t = line.split(" ")
    if len(t) < 2 or t[0] != "DESO-ACCEPTED-INDEX" or t[1] != "1":
        fail("bad_header")
    ni = decimal(t[2], MAX_INDEX) if len(t) > 2 else None
    if ni is None or ni == 0:
        fail("bad_header")
    ns = decimal(t[3], MAX_SIG) if len(t) > 3 else None
    if ns is None or ns == 0 or len(t) > 4:
        fail("bad_header")
    if nl + 1 + ni + ns != len(b):
        fail("size_mismatch")
    return b[nl + 1 : nl + 1 + ni], b[nl + 1 + ni :]


def make_accepted(index, sig):
    return b"DESO-ACCEPTED-INDEX 1 %d %d\n" % (len(index), len(sig)) + index + sig


def check_accepted(b, keys):
    index, sig = parse_accepted(b)
    verify_index(index, sig, keys)
    return parse_index(index)


# ------------------------------------------------------------
# Generation (FORMAT.md §5)
# ------------------------------------------------------------
def dir_ok(d, version):
    v, sep, ident = d.rpartition("-")
    if not sep:
        return False
    return parse_version(v) == version and v == ver_str(version) and hex_bytes(ident, 8) is not None


def parse_generation(b, number, system_name):
    if len(b) > MAX_GENERATION:
        fail("too_big")
    c = Cursor(b)
    if c.kv("format") != "1":
        fail("bad_format")
    g = decimal(c.kv("generation"), U64_MAX)
    if g is None or g == 0:
        fail("bad_generation")
    if g != number:
        fail("generation_mismatch")
    op = c.kv("op")
    if op not in OPS:
        fail("bad_op")
    packages = []
    all_programs = []
    while c.next_is("package"):
        if len(packages) == MAX_GEN_PACKAGES:
            fail("too_many")
        name = c.kv("package")
        if not valid_name(name):
            fail("bad_name")
        if system_name(name):
            fail("reserved_name")
        if any(p["name"] == name for p in packages):
            fail("dup_package")
        version = parse_version(c.kv("version"))
        if version is None:
            fail("bad_version")
        d = c.kv("dir")
        if not dir_ok(d, version):
            fail("bad_dir")
        reason = c.kv("reason")
        if reason not in ("explicit", "dependency"):
            fail("bad_reason")
        manifest = hex_bytes(c.kv("manifest"), 32)
        if manifest is None:
            fail("bad_manifest")
        depends_raw, _, conflicts = read_relations(c, name)
        programs = []

        def prog(p):
            if not valid_name(p):
                fail("bad_program_name")
            if system_name(p):
                fail("reserved_name")
            if p in all_programs:
                fail("dup_program")
            if len(all_programs) == MAX_GEN_PROGRAMS:
                fail("too_many")
            all_programs.append(p)
            programs.append(p)

        c.many("program", MAX_GEN_PROGRAMS, prog)
        c.lit("endpackage")
        packages.append(
            {"name": name, "version": version, "dir": d, "reason": reason, "manifest": manifest, "depends_raw": depends_raw, "conflicts": conflicts, "programs": programs}
        )
    c.lit("end")
    hashed = c.offset()
    h = hex_bytes(c.kv("hash"), 32)
    if h is None:
        fail("bad_hash")
    c.done()
    if sha256(b[:hashed]) != h:
        fail("bad_hash")
    return {"number": g, "op": op, "packages": packages}


def check_generation_package(e, mb, system_name):
    if sha256(mb) != e["manifest"]:
        fail("manifest_mismatch")
    m = parse_manifest(mb, system_name)
    if (
        m["name"] != e["name"]
        or m["version"] != e["version"]
        or programs_of(m) != e["programs"]
        or m["depends_raw"] != e["depends_raw"]
        or m["conflicts"] != e["conflicts"]
    ):
        fail("entry_mismatch")
    return m


def make_generation(number, op, packages):
    s = "format=1\ngeneration=%d\nop=%s\n" % (number, op)
    for p in packages:
        s += "package=%s\nversion=%s\ndir=%s\nreason=%s\nmanifest=%s\n" % (p["name"], ver_str(p["version"]), p["dir"], p["reason"], p["manifest"].hex())
        for d in p["depends_raw"]:
            s += "depends=%s\n" % d
        for d in p["conflicts"]:
            s += "conflicts=%s\n" % d
        for d in p["programs"]:
            s += "program=%s\n" % d
        s += "endpackage\n"
    s += "end\n"
    b = s.encode()
    return b + b"hash=" + sha256(b).hex().encode() + b"\n"


# ------------------------------------------------------------
# System names (user/lib/cmdnames.rs + /bin)
# ------------------------------------------------------------
def cmd_lists(path=None):
    """The four lists of user/lib/cmdnames.rs."""
    src = open(path or os.path.join(ROOT, "user", "lib", "cmdnames.rs"), encoding="utf-8").read()
    lists = {}
    for m in re.finditer(r"pub const (\w+): &\[[^\]]*\] = &\[(.*?)\n?\];", src, re.S):
        body = m.group(2)
        if m.group(1) == "BUILTINS":
            names = re.findall(r'^\s*\("([^"]*)"', body, re.M)
        else:
            names = re.findall(r'"([^"]*)"', body)
        lists[m.group(1)] = names
    for want in ("BUILTINS", "SYSCTL_BUILTINS", "INFO_COMMANDS", "KERNEL_ONLY"):
        if not lists.get(want):
            sys.exit("user/lib/cmdnames.rs: list %s not found" % want)
    return lists


def bin_programs(bin_dir=None):
    """The programs of /bin: the files without '.' in build/user (or bin_dir); None – unknown."""
    d = bin_dir or os.path.join(ROOT, "build", "user")
    if not os.path.isdir(d):
        return None
    return sorted(n for n in os.listdir(d) if "." not in n and os.path.isfile(os.path.join(d, n)))


FALLBACK_BIN = ["sh", "ls", "cat", "init"]


def system_names(bin_dir=None):
    lists = cmd_lists()
    listed = set()
    for v in lists.values():
        listed.update(v)
    progs = bin_programs(bin_dir)
    if progs is None:
        progs = list(FALLBACK_BIN)
    return listed, set(progs)


def system_name_fn(bin_dir=None):
    listed, progs = system_names(bin_dir)
    return lambda n: n in listed or n in progs


# ------------------------------------------------------------
# Making things
# ------------------------------------------------------------
def make_manifest(name, version, summary, files, depends=(), conflicts=(), abi="1.0", data=None):
    """files: list of (path, bytes, kind)."""
    s = "format=1\nname=%s\nversion=%s\narch=%s\nabi=%s\n" % (name, version, ARCH, abi)
    s += "data=%d\nsummary=%s\n" % (sum(len(b) for _, b, _ in files) if data is None else data, summary)
    for d in depends:
        s += "depends=%s\n" % d
    for d in conflicts:
        s += "conflicts=%s\n" % d
    for p, b, k in files:
        s += "file=%s|%d|%s|%s\n" % (p, len(b), sha256(b).hex(), k)
    s += "end\n"
    return s.encode()


def make_pkg(manifest, data, header_d=None):
    d = len(data) if header_d is None else header_d
    return b"DESOPKG 1 %d %d\n" % (len(manifest), d) + manifest + data


def pkg_from(name, version, summary, files, depends=(), conflicts=()):
    m = make_manifest(name, version, summary, files, depends, conflicts)
    return make_pkg(m, b"".join(b for _, b, _ in files)), m


def index_entry_text(name, version, abi, size, digest, depends, conflicts, summary):
    s = "package=%s\nversion=%s\nabi=%s\nsize=%d\nsha256=%s\n" % (name, version, abi, size, digest.hex())
    for d in depends:
        s += "depends=%s\n" % d
    for d in conflicts:
        s += "conflicts=%s\n" % d
    s += "summary=%s\nendpackage\n" % summary
    return s


def make_index(serial, issued, expires, entries, repo="decodesoft", channel="stable", arch=ARCH):
    s = "format=1\nrepo=%s\nchannel=%s\narch=%s\nserial=%d\nissued=%s\nexpires=%s\n" % (repo, channel, arch, serial, issued, expires)
    s += "".join(entries) + "end\n"
    return s.encode()


def entry_for_pkg(pkg, system_name, **override):
    m, _, _ = parse_pkg(pkg, system_name)
    f = dict(
        name=m["name"],
        version=ver_str(m["version"]),
        abi="%d.%d" % m["abi"],
        size=len(pkg),
        digest=sha256(pkg),
        depends=m["depends_raw"],
        conflicts=m["conflicts"],
        summary=m["summary"],
    )
    f.update(override)
    return index_entry_text(f["name"], f["version"], f["abi"], f["size"], f["digest"], f["depends"], f["conflicts"], f["summary"])


def der_encode(r, s):
    def integer(v):
        b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\x02" + bytes([len(b)]) + b

    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def der_decode_loose(der):
    i = 2
    out = []
    for _ in range(2):
        n = der[i + 1]
        out.append(int.from_bytes(der[i + 2 : i + 2 + n], "big"))
        i += 2 + n
    return out


def openssl_sign(key_pem, msg):
    with tempfile.TemporaryDirectory() as d:
        m = os.path.join(d, "msg")
        with open(m, "wb") as f:
            f.write(msg)
        out = os.path.join(d, "sig")
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_pem, "-out", out, m], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        der = open(out, "rb").read()
    r, s = der_decode_loose(der)
    if s > P256_N // 2:
        s = P256_N - s
    return der_encode(r, s)


def key_point(key_pem):
    r = subprocess.run(["openssl", "ec", "-in", key_pem, "-pubout", "-outform", "DER"], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    der = r.stdout
    if not der.startswith(SPKI_P256_PREFIX) or len(der) != len(SPKI_P256_PREFIX) + 65:
        sys.exit("%s: not a P-256 key" % key_pem)
    return der[len(SPKI_P256_PREFIX) :]


def sig_file(keyid, der, alg="p256"):
    return ("SIGNATURE 1\nalg=%s\nkeyid=%s\nsignature=%s\nend\n" % (alg, keyid, der.hex())).encode()


def sign_index(index, key_pem, keyid):
    return sig_file(keyid, openssl_sign(key_pem, signed_message("p256", keyid, index)))


def keys_file(pairs):
    s = "DESOPKG-KEYS 1\n"
    for keyid, point in pairs:
        s += "key=%s|p256|%s\n" % (keyid, point.hex())
    return (s + "end\n").encode()


# ------------------------------------------------------------
# Commands
# ------------------------------------------------------------
def cmd_pack(args):
    if len(args) != 3 or args[1] != "-o":
        sys.exit("usage: desopkg.py pack DIR -o FILE.pkg")
    d, out = args[0], args[2]
    meta = open(os.path.join(d, "desopkg.meta"), "rb").read()
    c = Cursor(meta)
    name, version, summary = c.kv("name"), c.kv("version"), c.kv("summary")
    deps, confs = [], []
    c.many("depends", MAX_DEPENDS, deps.append)
    c.many("conflicts", MAX_CONFLICTS, confs.append)
    c.done()
    files = []
    for top, kind in (("bin", "program"), ("share", "data")):
        base = os.path.join(d, top)
        if not os.path.isdir(base):
            continue
        for dirpath, _, names in os.walk(base):
            for n in names:
                full = os.path.join(dirpath, n)
                rel = os.path.relpath(full, d).replace(os.sep, "/")
                files.append((rel, open(full, "rb").read(), kind))
    files.sort(key=lambda f: f[0])
    pkg, _ = pkg_from(name, version, summary, files, deps, confs)
    sn = system_name_fn()
    try:
        parse_pkg(pkg, sn)
    except Refused as e:
        sys.exit("pack: the package would be refused: %s" % e.reason)
    with open(out, "wb") as f:
        f.write(pkg)
    print("%s: %s %s, %d files, %d bytes, sha256 %s" % (out, name, version, len(files), len(pkg), sha256(pkg).hex()))


def opt(args, name, default=None):
    if name in args:
        i = args.index(name)
        v = args[i + 1]
        del args[i : i + 2]
        return v
    return default


def cmd_index(args):
    args = list(args)
    serial = opt(args, "--serial")
    key = opt(args, "--key")
    keyid = opt(args, "--keyid", "decodesoft-2026-01")
    days = int(opt(args, "--days", "30"))
    repo = opt(args, "--repo", "decodesoft")
    channel = opt(args, "--channel", "stable")
    issued_s = opt(args, "--issued")
    if len(args) != 1 or serial is None or key is None:
        sys.exit("usage: desopkg.py index REPODIR --serial N --key K.pem [--keyid ID] [--days 30] [--repo R] [--channel C]")
    repodir = args[0]
    import time

    issued = parse_date(issued_s) if issued_s else int(time.time())
    if issued is None or not 1 <= days <= MAX_INDEX_DAYS:
        sys.exit("index: bad --issued or --days")
    sn = system_name_fn()
    entries = []
    pk = os.path.join(repodir, "packages")
    for n in sorted(os.listdir(pk)):
        if not n.endswith(".pkg"):
            continue
        b = open(os.path.join(pk, n), "rb").read()
        try:
            m, _, _ = parse_pkg(b, sn)
        except Refused as e:
            sys.exit("index: %s refused: %s" % (n, e.reason))
        if n != "%s-%s.pkg" % (m["name"], ver_str(m["version"])):
            sys.exit("index: %s should be named %s-%s.pkg" % (n, m["name"], ver_str(m["version"])))
        entries.append(entry_for_pkg(b, sn))
    index = make_index(int(serial), fmt_date(issued), fmt_date(issued + days * DAY), entries, repo, channel)
    parse_index(index)
    sig = sign_index(index, key, keyid)
    verify_index(index, sig, [{"keyid": keyid, "point": key_point(key)}])
    open(os.path.join(repodir, "index"), "wb").write(index)
    open(os.path.join(repodir, "index.sig"), "wb").write(sig)
    print("%s/index: serial %s, %d packages, valid until %s; index.sig: %s" % (repodir, serial, len(entries), fmt_date(issued + days * DAY), keyid))


def cmd_keys(args):
    args = list(args)
    keyid = opt(args, "--keyid")
    out = opt(args, "-o")
    if len(args) != 1 or not keyid or not valid_keyid(keyid):
        sys.exit("usage: desopkg.py keys K.pem --keyid ID [-o FILE]")
    b = keys_file([(keyid, key_point(args[0]))])
    parse_keys(b)
    if out:
        open(out, "wb").write(b)
    else:
        sys.stdout.write(b.decode())


def cmd_check(args):
    args = list(args)
    keys = opt(args, "--keys")
    sig = opt(args, "--sig")
    gen = opt(args, "--gen")
    if len(args) != 1:
        sys.exit("usage: desopkg.py check FILE [--keys KEYS] [--sig SIG] [--gen N]")
    b = open(args[0], "rb").read()
    sn = system_name_fn()
    try:
        if b.startswith(b"DESOPKG 1 "):
            m, _, _ = parse_pkg(b, sn)
            what = "package %s %s, %d files" % (m["name"], ver_str(m["version"]), len(m["files"]))
        elif b.startswith(b"DESO-ACCEPTED-INDEX "):
            if not keys:
                sys.exit("check: an accepted index needs --keys")
            idx = check_accepted(b, parse_keys(open(keys, "rb").read()))
            what = "accepted index, serial %d, signature OK" % idx["serial"]
        elif b.startswith(b"SIGNATURE 1\n"):
            parse_signature(b)
            what = "signature (grammar only)"
        elif b.startswith(b"DESOPKG-KEYS 1\n"):
            what = "%d keys" % len(parse_keys(b))
        elif b"\ngeneration=" in b[:64]:
            n = int(gen) if gen else int(os.path.basename(args[0]))
            g = parse_generation(b, n, sn)
            what = "generation %d, %d packages (metadata only)" % (g["number"], len(g["packages"]))
        elif b.startswith(b"format=1\nurl="):
            parse_repo_config(b)
            what = "repository configuration"
        else:
            idx = parse_index(b)
            what = "index, serial %d, %d packages" % (idx["serial"], len(idx["packages"]))
            if sig:
                if not keys:
                    sys.exit("check: --sig needs --keys")
                verify_index(b, open(sig, "rb").read(), parse_keys(open(keys, "rb").read()))
                what += ", signature OK"
    except Refused as e:
        print("%s: REFUSED: %s" % (args[0], e.reason))
        sys.exit(2)
    print("%s: OK – %s" % (args[0], what))


# ------------------------------------------------------------
# Vectors and mutations
# ------------------------------------------------------------
TEST_KEY = os.path.join(ROOT, "tests", "pkg", "test-key.pem")
OTHER_KEY = os.path.join(ROOT, "tests", "pkg", "other-key.pem")
TEST_KEYID = "deso-test-1"


def judge(kind, parts, sn, names=None):
    """The same as user/lib/pkgvec.rs `judge`."""
    p = dict(parts)
    try:
        if kind == "manifest":
            parse_manifest(p["manifest"], sn)
        elif kind == "pkg":
            parse_pkg(p["pkg"], sn)
        elif kind == "pkgidx":
            idx = parse_index(p["index"])
            name, ver = p["entry"].decode().split(" ")
            e = find_entry(idx, name, parse_version(ver))
            if e is None:
                return "not_in_index"
            check_pkg_against_index(p["pkg"], e, sn)
        elif kind == "index":
            parse_index(p["index"])
        elif kind == "repo":
            idx = parse_index(p["index"])
            check_index_repo(idx, parse_repo_config(p["repo"]))
        elif kind == "time":
            check_index_time(parse_index(p["index"]), int(p["now"]))
        elif kind == "sig":
            verify_index(p["index"], p["sig"], parse_keys(p["keys"]))
        elif kind == "accepted":
            check_accepted(p["file"], parse_keys(p["keys"]))
        elif kind == "keys":
            parse_keys(p["keys"])
        elif kind == "repocfg":
            parse_repo_config(p["repo"])
        elif kind == "gen":
            g = parse_generation(p["gen"], int(p["n"]), sn)
            for e in g["packages"]:
                mb = p.get("manifest:" + e["name"])
                if mb is None:
                    return "missing_package"
                check_generation_package(e, mb, sn)
        elif kind == "vercmp":
            a, b = parse_version(p["a"].decode()), parse_version(p["b"].decode())
            return "lt" if a < b else "eq" if a == b else "gt"
        elif kind == "reserved":
            return judge_reserved(p["names"], sn, names)
        else:
            raise ValueError(kind)
    except Refused as e:
        return e.reason
    return "ok"


def reserved_manifests(name):
    """(manifest with name=X, manifest with the program bin/X) – both must be refused."""
    prog = make_manifest(name, "1.0.0", "t", [("share/x", b"", "data")])
    as_prog = make_manifest("pkgtest-probe", "1.0.0", "t", [("bin/" + name, b"", "program")])
    return prog, as_prog


def judge_reserved(names_part, sn, names):
    """Every system name refused as a package name and as a program (`reserved_name`), the
    name list equal to this side's own, a capitalised name refused by the grammar."""
    listed = sorted(set(names_part.decode().split("\n")) - {""})
    if names is not None and listed != sorted(names):
        return "names_differ"
    for n in listed:
        for m in reserved_manifests(n):
            try:
                parse_manifest(m, sn)
                return "accepted:" + n
            except Refused as e:
                want = "reserved_name" if valid_name(n) else ("bad_name", "bad_path", "bad_program_name")
                if e.reason != want and e.reason not in want:
                    return "wrong:%s:%s" % (n, e.reason)
    try:
        parse_manifest(reserved_manifests("Sh")[0], sn)
        return "accepted:Sh"
    except Refused as e:
        if e.reason != "bad_name":
            return "wrong:Sh:" + e.reason
    return "ok"


class Vectors:
    def __init__(self, sn, names):
        self.recs = []
        self.sn = sn
        self.names = names

    def add(self, kind, expect, desc, parts):
        parts = [(l, b if isinstance(b, bytes) else b.encode()) for l, b in parts]
        got = judge(kind, parts, self.sn, self.names)
        if got != expect:
            raise SystemExit("vector %d %s (%s): intended %s, the Python check says %s" % (len(self.recs), kind, desc, expect, got))
        self.recs.append((kind, expect, desc, parts))

    def blob(self):
        out = [b"DESOPKG-VECTORS 1 %d\n" % len(self.recs)]
        for kind, expect, desc, parts in self.recs:
            assert "\n" not in desc
            out.append(("REC %s %s %d %s\n" % (kind, expect, len(parts), desc)).encode())
            for label, b in parts:
                out.append(b"%s %d\n" % (label.encode(), len(b)))
                out.append(b + b"\n")
        return b"".join(out)


def build_vectors(bin_dir=None, fuzz=400):
    sn = system_name_fn(bin_dir)
    listed, progs = system_names(bin_dir)
    names = sorted(listed | progs)
    V = Vectors(sn, names)
    prog = elf_program()
    hello = b"Witaj w DeSo OS!\n"
    files = [("bin/witaj", prog, "program"), ("share/witaj/hello.txt", hello, "data")]
    deps, confs = ["fonts>=1.0.0"], ["oldwitaj"]
    man = make_manifest("witaj", "1.2.0", "A greeting for DeSo OS", files, deps, confs)
    data = prog + hello

    # --- manifest: every rule on its own -------------------------------------------------
    def M(expect, desc, m):
        V.add("manifest", expect, desc, [("manifest", m)])

    def sub(old, new, count=1, base=None):
        b = base if base is not None else man
        assert old.encode() in b, old
        return b.replace(old.encode(), new.encode(), count)

    M("ok", "good manifest", man)
    M("cr", "CRLF instead of LF", man.replace(b"\n", b"\r\n"))
    M("trailing_bytes", "an extra newline at the end", man + b"\n")
    M("trailing_bytes", "a byte after end", man + b"x\n")
    M("no_final_newline", "no newline after end", man[:-1])
    M("truncated", "empty file", b"")
    M("truncated", "no end line", man[: man.rindex(b"end\n")])
    M("not_utf8", "invalid UTF-8 in the summary", man.replace(b"A greeting", b"A gr\xff\xfeeting"))
    M("control", "a tab in the summary", sub("A greeting", "A\tgreeting"))
    M("control", "a NUL byte", sub("A greeting", "A\0greeting"))
    M("control", "a DEL byte", sub("A greeting", "A\x7fgreeting"))
    M("line_too_long", "a 1025-byte line", sub("summary=A greeting for DeSo OS", "summary=" + "x" * 1017))
    M("bad_summary", "summary of 257 bytes", sub("summary=A greeting for DeSo OS", "summary=" + "x" * 257))
    M("ok", "summary of 256 bytes", sub("summary=A greeting for DeSo OS", "summary=" + "x" * 256))
    M("ok", "summary with a space at the end (part of the value)", sub("for DeSo OS\n", "for DeSo OS \n"))
    M("ok", "summary in UTF-8 (Polish letters)", sub("A greeting for DeSo OS", "Powitanie – zażółć gęślą jaźń"))
    M("bad_summary", "empty summary", sub("summary=A greeting for DeSo OS", "summary="))
    M("unexpected_key", "an unknown key", sub("name=witaj\n", "name=witaj\ncolor=red\n"))
    M("unexpected_key", "name twice", sub("name=witaj\n", "name=witaj\nname=witaj\n"))
    M("unexpected_key", "version before name", sub("name=witaj\nversion=1.2.0\n", "version=1.2.0\nname=witaj\n"))
    M("unexpected_key", "arch missing", sub("arch=x86_64\n", ""))
    M("unexpected_key", "a key in capitals", sub("name=witaj", "NAME=witaj"))
    M("unexpected_key", "a space before =", sub("name=witaj", "name =witaj"))
    M("unexpected_key", "an empty line", sub("arch=x86_64\n", "\narch=x86_64\n"))
    M("bad_format", "format=2", sub("format=1", "format=2"))
    M("bad_name", "a space at the end of name", sub("name=witaj\n", "name=witaj \n"))
    M("bad_name", "name with a capital letter", sub("name=witaj", "name=Witaj"))
    M("bad_name", "name starting with a digit", sub("name=witaj", "name=1witaj"))
    M("bad_name", "name of 33 bytes", sub("name=witaj", "name=" + "a" * 33))
    M("ok", "name of 32 bytes", sub("name=witaj", "name=" + "a" * 32))
    M("bad_name", "name with an underscore", sub("name=witaj", "name=wit_aj"))
    M("bad_name", "empty name", sub("name=witaj", "name="))
    for n in ("cd", "help", "sync", "desofs", "ver", "dcp", "run", "k", "sh", "ls"):
        M("reserved_name", "reserved name " + n, sub("name=witaj", "name=" + n))
    M("bad_name", "Sh – not reserved, refused by the grammar", sub("name=witaj", "name=Sh"))
    M("bad_version", "version with a leading zero", sub("version=1.2.0", "version=01.2.0"))
    M("bad_version", "version part 65536", sub("version=1.2.0", "version=1.65536.0"))
    M("ok", "version part 65535", sub("version=1.2.0", "version=65535.0.0"))
    M("bad_version", "version A.B", sub("version=1.2.0", "version=1.2"))
    M("bad_version", "version A.B.C.D", sub("version=1.2.0", "version=1.2.0.0"))
    M("bad_version", "a space at the end of version", sub("version=1.2.0\n", "version=1.2.0 \n"))
    M("bad_version", "version with a sign", sub("version=1.2.0", "version=+1.2.0"))
    M("bad_arch", "arch=aarch64", sub("arch=x86_64", "arch=aarch64"))
    M("bad_abi", "abi=1.1 (newer than the system)", sub("abi=1.0", "abi=1.1"))
    M("bad_abi", "abi=2.0", sub("abi=1.0", "abi=2.0"))
    M("bad_abi", "abi=1.00", sub("abi=1.0", "abi=1.00"))
    M("bad_abi", "abi=1", sub("abi=1.0", "abi=1"))
    M("bad_data", "data with a leading zero", sub("data=%d" % len(data), "data=0%d" % len(data)))
    M("bad_data", "data above 32 MiB", sub("data=%d" % len(data), "data=%d" % (MAX_DATA + 1)))
    M("data_mismatch", "data one more than the files", sub("data=%d" % len(data), "data=%d" % (len(data) + 1)))
    M("bad_depends", "depends with >", sub("fonts>=1.0.0", "fonts>1.0.0"))
    M("bad_depends", "depends with a bad version", sub("fonts>=1.0.0", "fonts>=1.0"))
    M("bad_depends", "depends on itself", sub("fonts>=1.0.0", "witaj"))
    M("bad_depends", "the same dependency twice", sub("depends=fonts>=1.0.0\n", "depends=fonts>=1.0.0\ndepends=fonts\n"))
    M("ok", "depends without a version", sub("fonts>=1.0.0", "fonts"))
    M("too_many", "17 dependencies", sub("depends=fonts>=1.0.0\n", "".join("depends=d%d\n" % i for i in range(17))))
    M("ok", "16 dependencies", sub("depends=fonts>=1.0.0\n", "".join("depends=d%d\n" % i for i in range(16))))
    M("bad_conflicts", "conflict that is also a dependency", sub("conflicts=oldwitaj", "conflicts=fonts"))
    M("bad_conflicts", "the same conflict twice", sub("conflicts=oldwitaj\n", "conflicts=oldwitaj\nconflicts=oldwitaj\n"))
    M("bad_conflicts", "conflict with itself", sub("conflicts=oldwitaj", "conflicts=witaj"))
    M("unexpected_key", "conflicts before depends", sub("depends=fonts>=1.0.0\nconflicts=oldwitaj\n", "conflicts=oldwitaj\ndepends=fonts>=1.0.0\n"))
    nofiles = make_manifest("witaj", "1.2.0", "s", [], data=0)
    M("unexpected_key", "no file lines", nofiles)

    def F(old_line_part, new_line_part):
        return sub(old_line_part, new_line_part)

    pfile = "file=bin/witaj|%d|%s|program" % (len(prog), sha256(prog).hex())
    dfile = "file=share/witaj/hello.txt|%d|%s|data" % (len(hello), sha256(hello).hex())
    M("bad_file", "file with 3 fields", F(pfile, "file=bin/witaj|%d|%s" % (len(prog), sha256(prog).hex())))
    M("bad_file", "file with 5 fields", F(pfile, pfile + "|x"))
    for p, why in (
        ("share/../etc", ".."),
        ("share/./x", "."),
        ("etc/passwd", "outside bin/ and share/"),
        ("bin/a/b", "bin/ with a subdirectory"),
        ("share", "share alone"),
        ("bin", "bin alone"),
        ("share/Hello.txt", "a capital letter"),
        ("share//x", "an empty component"),
        ("/share/x", "absolute"),
        ("share/" + "a" * 65, "a 65-byte component"),
        ("share/" + "abcdefgh/" * 13 + "abcdef", "a 129-byte path"),
        ("share/x y", "a space"),
    ):
        M("bad_path", "path " + why, F(dfile, "file=%s|%d|%s|data" % (p, len(hello), sha256(hello).hex())))
    long_ok = "share/" + "abcdefgh/" * 13 + "abcde"
    assert len(long_ok) == 128, len(long_ok)
    M("ok", "a 128-byte path", F(dfile, "file=%s|%d|%s|data" % (long_ok, len(hello), sha256(hello).hex())))
    M("bad_size", "size with a leading zero", F(dfile, "file=share/witaj/hello.txt|0%d|%s|data" % (len(hello), sha256(hello).hex())))
    M("bad_size", "negative size", F(dfile, "file=share/witaj/hello.txt|-1|%s|data" % sha256(hello).hex()))
    M("bad_sha256", "sha256 in capitals", F(dfile, "file=share/witaj/hello.txt|%d|%s|data" % (len(hello), sha256(hello).hex().upper())))
    M("bad_sha256", "sha256 of 63 digits", F(dfile, "file=share/witaj/hello.txt|%d|%s|data" % (len(hello), sha256(hello).hex()[:63])))
    M("bad_kind", "share/ file marked program", F(dfile, dfile.replace("|data", "|program")))
    M("bad_kind", "bin/ file marked data", F(pfile, pfile.replace("|program", "|data")))
    M("bad_kind", "unknown kind", F(dfile, dfile.replace("|data", "|config")))
    M("bad_program_name", "program starting with a digit", F(pfile, pfile.replace("bin/witaj", "bin/1witaj")))
    M("bad_program_name", "program with a dot", F(pfile, pfile.replace("bin/witaj", "bin/witaj.elf")))
    M("bad_program_name", "program with an underscore", F(pfile, pfile.replace("bin/witaj", "bin/wit_aj")))
    for n in ("ls", "sh", "cd", "ver", "spawn"):
        M("reserved_name", "program named " + n, F(pfile, pfile.replace("bin/witaj", "bin/" + n)))
    big = "file=bin/witaj|%d|%s|program" % (MAX_PROGRAM + 1, sha256(prog).hex())
    M("program_too_big", "program above 8 MiB", F(pfile, big))
    M("dup_path", "the same path twice", F(dfile, dfile + "\n" + dfile))
    clash = "file=share/witaj/hello.txt/more|0|%s|data" % sha256(b"").hex()
    M("path_clash", "a path both a file and a directory", F(dfile, dfile + "\n" + clash))
    clash2 = "file=share/witaj|0|%s|data" % sha256(b"").hex()
    M("path_clash", "a directory given as a file first", F(dfile, clash2 + "\n" + dfile))
    many = [("share/f%d" % i, b"", "data") for i in range(MAX_FILES + 1)]
    M("too_many", "257 files", make_manifest("witaj", "1.2.0", "s", many))
    M("ok", "256 files", make_manifest("witaj", "1.2.0", "s", many[:MAX_FILES]))
    M("ok", "data-only package", make_manifest("fonts", "1.0.0", "Fonts", [("share/fonts/a.ttf", b"\0\1", "data")]))

    # --- pkg: header, sizes, data, ELF -------------------------------------------------------
    pkg = make_pkg(man, data)

    def P(expect, desc, b):
        V.add("pkg", expect, desc, [("pkg", b)])

    hdr_end = pkg.index(b"\n") + 1
    body = pkg[hdr_end:]
    P("ok", "good package", pkg)
    P("bad_header", "DESOPKG 2", b"DESOPKG 2 %d %d\n" % (len(man), len(data)) + body)
    P("bad_header", "M with a leading zero", b"DESOPKG 1 0%d %d\n" % (len(man), len(data)) + body)
    P("bad_header", "M = 0", b"DESOPKG 1 0 %d\n" % len(data) + body)
    P("bad_header", "M above 64 KiB", b"DESOPKG 1 %d %d\n" % (MAX_MANIFEST + 1, len(data)) + body)
    P("bad_header", "a fifth field", b"DESOPKG 1 %d %d 0\n" % (len(man), len(data)) + body)
    P("bad_header", "two spaces", b"DESOPKG 1  %d %d\n" % (len(man), len(data)) + body)
    P("bad_header", "no newline in the first 32 bytes", b"DESOPKG 1 %d %d " % (len(man), len(data)) + b"x" * 30 + body)
    P("bad_header", "not a package", b"\x7fELF" + body)
    P("size_mismatch", "one byte missing", pkg[:-1])
    P("size_mismatch", "one byte too many", pkg + b"\0")
    P("data_mismatch", "header D one more than the manifest's data", make_pkg(man, data + b"\0"))
    flipped = bytearray(pkg)
    flipped[-1] ^= 1
    P("file_sha_mismatch", "one data byte changed", bytes(flipped))
    m_mut = man.replace(b"A greeting", b"A Greeting")
    P("ok", "one manifest byte changed – fine alone, the index catches it", make_pkg(m_mut, data))
    P("unexpected_key", "manifest grammar error inside a package", make_pkg(man.replace(b"arch=", b"Arch="), data))

    def with_prog(p, desc, expect):
        fs = [("bin/witaj", p, "program"), ("share/witaj/hello.txt", hello, "data")]
        m = make_manifest("witaj", "1.2.0", "A greeting for DeSo OS", fs, deps, confs)
        P(expect, desc, make_pkg(m, p + hello))

    with_prog(b"#!/bin/sh\necho hi\n", "program that is not an ELF", "bad_elf")
    with_prog(elf_program(1, 1), "program with ABI note 1.1", "bad_elf")
    with_prog(elf_program(2, 0), "program with ABI note 2.0", "bad_elf")
    with_prog(elf_program(1, 0, 1), "program with ABI note flags", "bad_elf")
    with_prog(elf_program(seg_flags=7), "program with a W+X segment", "bad_elf")
    with_prog(elf_program(with_note=False), "program without an ABI note (= 1.0)", "ok")
    e = bytearray(prog)
    e[18] = 3
    with_prog(bytes(e), "program for i386", "bad_elf")
    e = bytearray(prog)
    e[16] = 3
    with_prog(bytes(e), "program ET_DYN", "bad_elf")
    e = bytearray(prog)
    e[64 + 16 : 64 + 24] = (0x1000).to_bytes(8, "little")
    with_prog(bytes(e), "program segment in the null page", "bad_elf")
    e = bytearray(prog)
    e[24:32] = (0x500000).to_bytes(8, "little")
    with_prog(bytes(e), "program entry outside the code", "bad_elf")
    real = os.path.join(bin_dir or os.path.join(ROOT, "build", "user"), "hello")
    if os.path.isfile(real):
        rb = open(real, "rb").read()
        if rb.startswith(b"\x7fELF") and len(rb) <= MAX_PROGRAM:
            fs = [("bin/witaj", rb, "program")]
            P("ok", "a real /bin program (build/user/hello) as a package program", make_pkg(make_manifest("witaj", "1.2.0", "s", fs), rb))

    # --- index -------------------------------------------------------------------------------
    ent = entry_for_pkg(pkg, sn)
    issued, expires = "2026-12-01T10:00:00Z", "2026-12-31T10:00:00Z"
    idx = make_index(42, issued, expires, [ent])

    def I(expect, desc, b):
        V.add("index", expect, desc, [("index", b)])

    def isub(old, new, base=None):
        b = base if base is not None else idx
        assert old.encode() in b, old
        return b.replace(old.encode(), new.encode(), 1)

    I("ok", "good index", idx)
    I("ok", "index without packages", make_index(1, issued, expires, []))
    I("cr", "CRLF", idx.replace(b"\n", b"\r\n"))
    I("trailing_bytes", "extra newline", idx + b"\n")
    I("bad_format", "format=2", isub("format=1", "format=2"))
    I("bad_repo", "repo with a capital", isub("repo=decodesoft", "repo=DecodeSoft"))
    I("bad_channel", "channel with a space at the end", isub("channel=stable\n", "channel=stable \n"))
    I("bad_arch", "arch", isub("arch=x86_64", "arch=riscv64"))
    I("bad_serial", "serial 0", isub("serial=42", "serial=0"))
    I("bad_serial", "serial with a leading zero", isub("serial=42", "serial=042"))
    I("bad_serial", "serial 2^64", isub("serial=42", "serial=%d" % 2**64))
    I("ok", "serial 2^64-1", isub("serial=42", "serial=%d" % U64_MAX))
    for d, why in (
        ("2026-02-30T10:00:00Z", "30 February"),
        ("2026-12-01t10:00:00Z", "lower-case t"),
        ("2026-12-01T10:00:00z", "lower-case z"),
        ("2026-12-01T10:00:00+01:00", "a time zone"),
        ("2026-12-01T10:00:60Z", "second 60"),
        ("2026-12-01T24:00:00Z", "hour 24"),
        ("2026-12-01 10:00:00Z", "a space instead of T"),
        ("2026-12-1T10:00:00Z", "one-digit day"),
        ("1969-12-31T23:59:59Z", "before 1970"),
    ):
        I("bad_date", "issued: " + why, isub("issued=" + issued, "issued=" + d))
    I("ok", "29 February of a leap year", make_index(42, "2028-02-29T00:00:00Z", "2028-03-01T00:00:00Z", [ent]))
    I("bad_date", "29 February of 2100", make_index(42, "2100-02-29T00:00:00Z", "2100-03-01T00:00:00Z", [ent]))
    I("bad_times", "issued == expires", make_index(42, issued, issued, [ent]))
    I("bad_times", "expires before issued", make_index(42, expires, issued, [ent]))
    I("bad_times", "valid 30 days + 1 s", make_index(42, issued, "2026-12-31T10:00:01Z", [ent]))
    I("ok", "valid exactly 30 days", make_index(42, issued, "2026-12-31T10:00:00Z", [ent]))
    I("dup_package", "the same name and version twice", make_index(42, issued, expires, [ent, ent]))
    ent2 = entry_for_pkg(pkg, sn, version="1.1.0")
    I("ok", "two versions of one package", make_index(42, issued, expires, [ent, ent2]))
    I("bad_size", "size 0", isub("size=%d" % len(pkg), "size=0"))
    I("bad_size", "size above the largest package", isub("size=%d" % len(pkg), "size=%d" % (MAX_PKG + 1)))
    I("ok", "size exactly the largest package", isub("size=%d" % len(pkg), "size=%d" % MAX_PKG))
    I("bad_sha256", "sha256 too short", isub("sha256=" + sha256(pkg).hex(), "sha256=" + sha256(pkg).hex()[:-2]))
    I("bad_name", "package name with a capital", isub("package=witaj", "package=Witaj"))
    I("bad_abi", "abi=x", isub("abi=1.0", "abi=x"))
    I("unexpected_key", "endpackage missing", isub("endpackage\n", ""))
    I("unexpected_key", "summary before depends", isub("depends=fonts>=1.0.0\nconflicts=oldwitaj\nsummary=A greeting for DeSo OS\n", "summary=A greeting for DeSo OS\ndepends=fonts>=1.0.0\nconflicts=oldwitaj\n"))
    I("bad_summary", "empty summary", isub("summary=A greeting for DeSo OS", "summary="))
    I("unexpected_key", "expires missing", isub("expires=" + expires + "\n", ""))

    # --- repo / time ---------------------------------------------------------------------------
    repo = b"format=1\nurl=https://decodesoft.pl/deso/\nrepo=decodesoft\nchannel=stable\narch=x86_64\nend\n"
    V.add("repo", "ok", "index matches /etc/desopkg/repo", [("index", idx), ("repo", repo)])
    V.add("repo", "repo_mismatch", "index of another channel", [("index", make_index(42, issued, expires, [ent], channel="testing")), ("repo", repo)])
    V.add("repo", "repo_mismatch", "index of another repository", [("index", make_index(42, issued, expires, [ent], repo="other")), ("repo", repo)])
    t_iss, t_exp = parse_date(issued), parse_date(expires)
    for now, expect, desc in (
        (t_iss, "ok", "now == issued"),
        (t_exp - 1, "ok", "one second before expires"),
        (t_exp, "expired", "now == expires"),
        (t_exp + DAY, "expired", "a day after expires"),
        (t_iss - DAY, "ok", "issued exactly one day ahead"),
        (t_iss - DAY - 1, "issued_in_future", "issued one day and a second ahead"),
    ):
        V.add("time", expect, desc, [("index", idx), ("now", str(now))])

    def RC(expect, desc, b):
        V.add("repocfg", expect, desc, [("repo", b)])

    RC("ok", "good /etc/desopkg/repo", repo)
    RC("bad_url", "http://", repo.replace(b"https://", b"http://"))
    RC("bad_url", "no / at the end", repo.replace(b"/deso/", b"/deso"))
    RC("ok", "a port", repo.replace(b"decodesoft.pl/", b"decodesoft.pl:8443/"))
    RC("ok", "port 65535", repo.replace(b"decodesoft.pl/", b"decodesoft.pl:65535/"))
    RC("bad_url", "port 0", repo.replace(b"decodesoft.pl/", b"decodesoft.pl:0/"))
    RC("bad_url", "port 65536", repo.replace(b"decodesoft.pl/", b"decodesoft.pl:65536/"))
    RC("bad_url", "port with a leading zero", repo.replace(b"decodesoft.pl/", b"decodesoft.pl:08443/"))
    RC("bad_url", "empty port", repo.replace(b"decodesoft.pl/", b"decodesoft.pl:/"))
    RC("bad_url", "two ports", repo.replace(b"decodesoft.pl/", b"decodesoft.pl:1:2/"))
    RC("bad_url", "port without a host", repo.replace(b"decodesoft.pl/", b":8443/"))
    RC("ok", "the self-test repository", repo.replace(b"https://decodesoft.pl/deso/", b"https://tls.deso:58480/deso/"))
    RC("bad_url", "user info", repo.replace(b"https://", b"https://a@"))
    RC("ok", "host only", repo.replace(b"https://decodesoft.pl/deso/", b"https://decodesoft.pl/"))
    RC("bad_channel", "channel in capitals", repo.replace(b"channel=stable", b"channel=STABLE"))
    RC("unexpected_key", "repo missing", repo.replace(b"repo=decodesoft\n", b""))

    # --- signature and keys --------------------------------------------------------------------
    point = key_point(TEST_KEY)
    other = key_point(OTHER_KEY)
    keys = keys_file([(TEST_KEYID, point)])
    keys2 = keys_file([(TEST_KEYID, point), ("other-1", other)])
    der = openssl_sign(TEST_KEY, signed_message("p256", TEST_KEYID, idx))
    sig = sig_file(TEST_KEYID, der)

    def S(expect, desc, index=idx, s=sig, k=keys):
        V.add("sig", expect, desc, [("index", index), ("sig", s), ("keys", k)])

    S("ok", "good signature")
    S("ok", "good signature, two keys in the store", k=keys2)
    tampered = bytearray(idx)
    tampered[idx.index(b"serial=42") + 7] = ord("3")
    S("bad_signature", "one index byte changed after signing", index=bytes(tampered))
    S("bad_signature", "index with one more byte", index=idx + b"\n")
    r, s_ = der_decode_loose(der)
    S("high_s", "high-S form of the same signature", s=sig_file(TEST_KEYID, der_encode(r, P256_N - s_)))
    def der_raw(rb, sb):
        body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
        return b"\x30" + bytes([len(body)]) + body

    rb = der_encode(r, s_)[4 : 4 + der_encode(r, s_)[3]]
    sb = s_.to_bytes((s_.bit_length() + 7) // 8, "big")
    S("ok", "the same signature through der_raw (check of the helper)", s=sig_file(TEST_KEYID, der_raw(rb, sb)))
    S("sig_encoding", "an unneeded leading zero in s", s=sig_file(TEST_KEYID, der_raw(rb, b"\0" + sb)))
    S("sig_encoding", "a negative s", s=sig_file(TEST_KEYID, der_raw(rb, b"\x81")))
    S("sig_encoding", "an empty INTEGER", s=sig_file(TEST_KEYID, der_raw(rb, b"")))
    S("sig_encoding", "INTEGER tag 0x03", s=sig_file(TEST_KEYID, der_raw(rb, sb).replace(b"\x02" + bytes([len(sb)]) + sb, b"\x03" + bytes([len(sb)]) + sb)))
    S("sig_encoding", "a byte after the DER sequence", s=sig_file(TEST_KEYID, der[:1] + bytes([der[1]]) + der[2:] + b"\0"))
    S("sig_encoding", "DER length one too long", s=sig_file(TEST_KEYID, der[:1] + bytes([der[1] + 1]) + der[2:] + b"\0"))
    S("sig_encoding", "r = 0", s=sig_file(TEST_KEYID, der_encode(0, s_)))
    S("sig_encoding", "r = n", s=sig_file(TEST_KEYID, der_encode(P256_N, s_)))
    S("sig_encoding", "signature in capitals", s=sig.replace(der.hex().encode(), der.hex().upper().encode()))
    S("sig_encoding", "odd number of hex digits", s=sig.replace(der.hex().encode(), der.hex()[:-1].encode()))
    S("sig_encoding", "empty signature", s=sig.replace(der.hex().encode(), b""))
    other_der = openssl_sign(OTHER_KEY, signed_message("p256", TEST_KEYID, idx))
    S("bad_signature", "signed by another key under the test key's id", s=sig_file(TEST_KEYID, other_der))
    S("ok", "signed by the other key under its own id", s=sig_file("other-1", openssl_sign(OTHER_KEY, signed_message("p256", "other-1", idx))), k=keys2)
    S("unknown_key", "key id not in the store", s=sig_file("deso-test-9", der))
    S("bad_signature", "signature made for another key id", s=sig_file("other-1", der), k=keys2)
    S("bad_alg", "alg=ed25519", s=sig.replace(b"alg=p256", b"alg=ed25519"))
    S("bad_keyid", "key id with a capital", s=sig.replace(b"keyid=" + TEST_KEYID.encode(), b"keyid=Deso-test-1"))
    S("cr", "signature file with CRLF", s=sig.replace(b"\n", b"\r\n"))
    S("trailing_bytes", "a byte after end in the signature file", s=sig + b"x\n")
    S("unexpected_key", "SIGNATURE 2", s=sig.replace(b"SIGNATURE 1", b"SIGNATURE 2"))
    S("bad_signature", "signature over the index without the domain line", s=sig_file(TEST_KEYID, openssl_sign(TEST_KEY, idx)))

    def K(expect, desc, b):
        V.add("keys", expect, desc, [("keys", b)])

    K("ok", "good key store", keys)
    K("ok", "empty key store", keys_file([]))
    bad_pt = bytearray(point)
    bad_pt[64] ^= 1
    K("bad_key", "a point not on the curve", keys_file([(TEST_KEYID, bytes(bad_pt))]))
    K("bad_key", "a compressed point", keys.replace(point.hex().encode(), (b"\x02" + point[1:33]).hex().encode()))
    K("bad_key", "the same key id twice", keys_file([(TEST_KEYID, point), (TEST_KEYID, other)]))
    K("bad_key", "alg p384", keys.replace(b"|p256|", b"|p384|"))
    K("too_many", "17 keys", keys_file([("k%d" % i, point) for i in range(17)]))
    K("ok", "16 keys", keys_file([("k%d" % i, point) for i in range(16)]))
    K("unexpected_key", "no header line", keys.replace(b"DESOPKG-KEYS 1\n", b""))

    # --- accepted index on the disk ------------------------------------------------------------
    acc = make_accepted(idx, sig)

    def A(expect, desc, b, k=keys):
        V.add("accepted", expect, desc, [("file", b), ("keys", k)])

    A("ok", "good accepted index", acc)
    A("size_mismatch", "one byte missing (unfinished write)", acc[:-1])
    A("size_mismatch", "one byte too many", acc + b"\n")
    A("bad_header", "index size with a leading zero", b"DESO-ACCEPTED-INDEX 1 0%d %d\n" % (len(idx), len(sig)) + idx + sig)
    A("bad_header", "signature size above 1 KiB", b"DESO-ACCEPTED-INDEX 1 %d %d\n" % (len(idx), MAX_SIG + 1) + idx + sig)
    A("bad_header", "version 2", acc.replace(b"DESO-ACCEPTED-INDEX 1", b"DESO-ACCEPTED-INDEX 2", 1))
    A("bad_header", "empty file", b"")
    A("bad_signature", "index byte changed on the disk", make_accepted(bytes(tampered), sig))
    crlf_idx = idx.replace(b"\n", b"\r\n")
    A("cr", "a properly signed index with CRLF – the signature is checked first, then the grammar", make_accepted(crlf_idx, sign_index(crlf_idx, TEST_KEY, TEST_KEYID)))
    A("unknown_key", "accepted index checked against a store without its key", acc, keys_file([("other-1", other)]))

    # --- packages against the index ------------------------------------------------------------
    def PI(expect, desc, p=pkg, index=idx, entry="witaj 1.2.0"):
        V.add("pkgidx", expect, desc, [("index", index), ("pkg", p), ("entry", entry)])

    PI("ok", "the package of the index entry")
    PI("pkg_size_mismatch", "one byte missing", p=pkg[:-1])
    PI("pkg_size_mismatch", "one byte more", p=pkg + b"\0")
    PI("pkg_sha_mismatch", "one manifest byte changed (same size)", p=make_pkg(m_mut, data))
    PI("pkg_sha_mismatch", "one data byte changed", p=bytes(flipped))
    PI("not_in_index", "a version the index does not have", entry="witaj 9.9.9")
    for field, val, desc in (
        ("summary", "Another summary", "summary differs from the index"),
        ("depends", ["fonts>=1.1.0"], "depends differs from the index"),
        ("depends", ["fonts"], "depends without the version in the index"),
        ("conflicts", [], "conflicts missing in the index"),
    ):
        PI("index_mismatch", desc, index=make_index(42, issued, expires, [entry_for_pkg(pkg, sn, **{field: val})]))
    bad_pkg = make_pkg(man.replace(b"arch=x86_64", b"arch=x86-64"), data)
    PI("bad_arch", "the index pins a package whose manifest is bad", p=bad_pkg, index=make_index(42, issued, expires, [entry_for_pkg(pkg, sn, size=len(bad_pkg), digest=sha256(bad_pkg))]))

    # --- generations ---------------------------------------------------------------------------
    fonts_files = [("share/fonts/a.ttf", b"\0\1\2", "data")]
    fonts_man = make_manifest("fonts", "1.0.0", "Fonts", fonts_files)
    gw = {"name": "witaj", "version": (1, 2, 0), "dir": "1.2.0-5f2a9c01d4e7b3a8", "reason": "explicit", "manifest": sha256(man), "depends_raw": deps, "conflicts": confs, "programs": ["witaj"]}
    gf = {"name": "fonts", "version": (1, 0, 0), "dir": "1.0.0-0123456789abcdef", "reason": "dependency", "manifest": sha256(fonts_man), "depends_raw": [], "conflicts": [], "programs": []}
    gen = make_generation(3, "install", [gw, gf])
    mans = [("manifest:witaj", man), ("manifest:fonts", fonts_man)]

    def G(expect, desc, b=None, n="3", ms=None):
        b = gen if b is None else b
        V.add("gen", expect, desc, [("gen", b), ("n", n)] + (mans if ms is None else ms))

    def gmod(**kw):
        p = dict(gw)
        p.update(kw)
        return make_generation(3, "install", [p, gf])

    G("ok", "good generation")
    G("ok", "generation without packages", make_generation(5, "remove", []), "5", [])
    G("ok", "generation 2^64-1", make_generation(U64_MAX, "update", [gw, gf]), str(U64_MAX))
    G("generation_mismatch", "number in the file differs from its name", gen, "4")
    G("bad_generation", "generation 0", make_generation(0, "install", []), "0", [])
    G("bad_generation", "generation with a leading zero", gen.replace(b"generation=3", b"generation=03"))
    G("bad_op", "op=rollback", make_generation(3, "rollback", [gw, gf]))
    G("bad_dir", "dir of another version", gmod(dir="1.1.0-5f2a9c01d4e7b3a8"))
    G("bad_dir", "dir id of 15 hex digits", gmod(dir="1.2.0-5f2a9c01d4e7b3a"))
    G("bad_dir", "dir id in capitals", gmod(dir="1.2.0-5F2A9C01D4E7B3A8"))
    G("bad_dir", "dir without an id", gmod(dir="1.2.0"))
    G("bad_reason", "reason=manual", gmod(reason="manual"))
    G("bad_manifest", "manifest hash too short", gen.replace(sha256(man).hex().encode(), sha256(man).hex()[:-1].encode()))
    G("bad_hash", "hash field changed", gen[:-3] + (b"0" if gen[-3:-2] != b"0" else b"1") + gen[-2:])
    G("bad_hash", "a content byte changed, hash kept", gen.replace(b"op=install", b"op=update"))
    G("bad_hash", "hash in capitals", gen[: gen.rindex(b"hash=") + 5] + gen[gen.rindex(b"hash=") + 5 :].upper())
    G("trailing_bytes", "a byte after the hash", gen + b"x\n")
    G("trailing_bytes", "an extra newline after the hash", gen + b"\n")
    G("no_final_newline", "no newline after the hash", gen[:-1])
    G("cr", "CRLF", gen.replace(b"\n", b"\r\n"))
    G("truncated", "file cut before the hash (unfinished write)", gen[: gen.rindex(b"hash=")])
    G("truncated", "file cut at a line in the middle", gen[: gen.index(b"\n", len(gen) // 2) + 1])
    G("unexpected_key", "file cut inside a line in the middle", gen[: gen.index(b"\n", len(gen) // 2) - 3] + b"\n")
    G("dup_program", "two packages with the same program", make_generation(3, "install", [gw, dict(gf, programs=["witaj"])]))
    G("reserved_name", "program named ls", gmod(programs=["ls"]))
    G("reserved_name", "package named sh", make_generation(3, "install", [dict(gw, name="sh")]))
    G("dup_package", "the same package twice", make_generation(3, "install", [gw, gw]))
    G("missing_package", "a package without its package file", gen, ms=[("manifest:witaj", man)])
    G("manifest_mismatch", "package file changed on the disk", gen, ms=[("manifest:witaj", m_mut), ("manifest:fonts", fonts_man)])
    G("entry_mismatch", "program list differs from the manifest", gmod(programs=[]))
    m11 = make_manifest("witaj", "1.1.0", "A greeting for DeSo OS", files, deps, confs)
    G("entry_mismatch", "version differs from the manifest", gmod(version=(1, 1, 0), dir="1.1.0-5f2a9c01d4e7b3a8"))
    G("entry_mismatch", "package file of another version", gmod(manifest=sha256(m11)), ms=[("manifest:witaj", m11), ("manifest:fonts", fonts_man)])
    G("entry_mismatch", "depends differ from the manifest", gmod(depends_raw=["fonts"]))
    G("bad_name", "package name in capitals", make_generation(3, "install", [dict(gw, name="Witaj")]))
    many_pk = [dict(gf, name="p%d" % i, programs=[]) for i in range(MAX_GEN_PACKAGES + 1)]
    G("too_many", "65 packages", make_generation(3, "install", many_pk), ms=[])

    # --- versions, reserved names --------------------------------------------------------------
    for a, b, expect in (("1.2.0", "1.10.0", "lt"), ("2.0.0", "1.65535.65535", "gt"), ("1.2.3", "1.2.3", "eq"), ("0.0.0", "0.0.1", "lt"), ("10.0.0", "9.99.99", "gt")):
        V.add("vercmp", expect, "%s vs %s" % (a, b), [("a", a), ("b", b)])
    V.add("reserved", "ok", "every system name refused as a package and a program; the lists agree", [("names", "\n".join(names) + "\n")])
    add_fuzz(V, FUZZ_SEED, fuzz)
    return V


FUZZ_SEED = 82
FUZZ_BYTES = b"\n\r =|.-0123456789az>\x00\xff/"


def add_fuzz(V, seed, count):
    """`count` random mutations (1–3 byte changes: replace, insert, delete, bit flip) of the
    vectors above.  The expected verdict is this tool's own – the Rust side must say the same,
    whatever it is: the two implementations must not drift apart anywhere, not only on the
    hand-written cases.  A fixed seed: the same records every build."""
    import random

    rnd = random.Random(seed)
    pool = [r for r in V.recs if r[0] not in ("reserved", "vercmp")]
    for i in range(count):
        kind, _, desc, parts = rnd.choice(pool)
        parts = list(parts)
        j = rnd.choice([k for k, (l, _) in enumerate(parts) if l not in ("n", "now", "entry")])
        label, b = parts[j]
        b = bytearray(b)
        for _ in range(rnd.choice((1, 1, 1, 2, 3))):
            op = rnd.randrange(4)
            p = rnd.randrange(len(b)) if b else 0
            if op == 1 or not b:
                b[p:p] = bytes([rnd.choice(FUZZ_BYTES)])
            elif op == 0:
                b[p] = rnd.choice(FUZZ_BYTES)
            elif op == 2:
                del b[p]
            else:
                b[p] ^= 1 << rnd.randrange(8)
        parts[j] = (label, bytes(b))
        V.recs.append((kind, judge(kind, parts, V.sn, V.names), "fuzz %d (%s)" % (i, desc), parts))


def cmd_vectors(args):
    args = list(args)
    out = opt(args, "-o")
    bin_dir = opt(args, "--bin")
    fuzz = int(opt(args, "--fuzz", "400"))
    if args or not out:
        sys.exit("usage: desopkg.py vectors -o FILE [--bin DIR] [--fuzz N]")
    V = build_vectors(bin_dir, fuzz)
    b = V.blob()
    with open(out, "wb") as f:
        f.write(b)
    print("%s: %d vectors, %d bytes" % (out, len(V.recs), len(b)))


def cmd_test(args):
    args = list(args)
    bin_dir = opt(args, "--bin")
    progs = bin_programs(bin_dir)
    where = bin_dir or ("build/user" if progs is not None else "fallback list – build first for the full /bin")
    # 1. the lists of cmdnames.rs
    lists = cmd_lists()
    n_listed = len(set(sum(lists.values(), [])))
    sh_src = open(os.path.join(ROOT, "user", "bin", "sh.rs"), encoding="utf-8").read()
    if "mod cmdnames" not in sh_src or re.search(r"^const (BUILTINS|INFO_COMMANDS|KERNEL_ONLY|SYSCTL_BUILTINS)\b", sh_src, re.M):
        print("[PKG HOST TEST] FAIL sh.rs must take its name lists from user/lib/cmdnames.rs")
        sys.exit(1)
    print("[PKG HOST TEST] 1/6 user/lib/cmdnames.rs: %d names in 4 lists, sh.rs uses them PASS" % n_listed)
    # 2. every rule on its own
    V = build_vectors(bin_dir, fuzz=0)
    kinds = {}
    for r in V.recs:
        kinds[r[0]] = kinds.get(r[0], 0) + 1
    refused = sum(1 for r in V.recs if r[1] not in ("ok", "lt", "eq", "gt"))
    print("[PKG HOST TEST] 2/6 %d vectors (%s), %d mutations refused with the intended reason PASS" % (len(V.recs), ", ".join("%s %d" % kv for kv in sorted(kinds.items())), refused))
    # 3. reserved names: every name of the lists and of /bin
    listed, bins = system_names(bin_dir)
    sn = system_name_fn(bin_dir)
    r = judge_reserved(("\n".join(sorted(listed | bins)) + "\n").encode(), sn, sorted(listed | bins))
    if r != "ok":
        print("[PKG HOST TEST] FAIL reserved names: %s" % r)
        sys.exit(1)
    print("[PKG HOST TEST] 3/6 %d system names (%d listed + %d programs of /bin from %s) refused as package and program names PASS" % (len(listed | bins), len(listed), len(bins), where))
    # 4. the tools end to end: pack, index, check
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "src")
        os.makedirs(os.path.join(src, "bin"))
        os.makedirs(os.path.join(src, "share", "witaj"))
        open(os.path.join(src, "bin", "witaj"), "wb").write(elf_program())
        open(os.path.join(src, "share", "witaj", "hello.txt"), "wb").write(b"hi\n")
        open(os.path.join(src, "desopkg.meta"), "wb").write(b"name=witaj\nversion=1.0.0\nsummary=Test\n")
        repo = os.path.join(d, "repo")
        os.makedirs(os.path.join(repo, "packages"))
        devnull = open(os.devnull, "w")
        old = sys.stdout
        sys.stdout = devnull
        try:
            cmd_pack([src, "-o", os.path.join(repo, "packages", "witaj-1.0.0.pkg")])
            cmd_index([repo, "--serial", "7", "--key", TEST_KEY, "--keyid", TEST_KEYID])
            cmd_keys([TEST_KEY, "--keyid", TEST_KEYID, "-o", os.path.join(d, "keys")])
        finally:
            sys.stdout = old
        idx = open(os.path.join(repo, "index"), "rb").read()
        verify_index(idx, open(os.path.join(repo, "index.sig"), "rb").read(), parse_keys(open(os.path.join(d, "keys"), "rb").read()))
        parsed = parse_index(idx)
        pkgb = open(os.path.join(repo, "packages", "witaj-1.0.0.pkg"), "rb").read()
        check_pkg_against_index(pkgb, parsed["packages"][0], sn)
    print("[PKG HOST TEST] 4/6 pack -> index (signed, low-S) -> keys -> check: the package against the signed index PASS")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    try:
        if cmd == "pack":
            cmd_pack(args)
        elif cmd == "index":
            cmd_index(args)
        elif cmd == "keys":
            cmd_keys(args)
        elif cmd == "check":
            cmd_check(args)
        elif cmd == "vectors":
            cmd_vectors(args)
        elif cmd == "--test":
            cmd_test(args)
        else:
            sys.exit(__doc__)
    except Refused as e:
        sys.exit("refused: %s" % e.reason)


if __name__ == "__main__":
    main()
