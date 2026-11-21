#!/usr/bin/env python3
# DeSo OS ABI tool (docs/abi/README.md) – abi/abi.toml is the one source of truth for what a
# program may rely on; this tool checks it, generates the files that follow from it and guards
# the locks.  Python 3 standard library only (no tomllib – Linux Mint 21 has Python 3.10).
#
#   python3 tools/abigen.py              generate docs/abi/SYSCALLS.md, user/lib/abi_generated.rs and
#                                        kernel/user/abi_generated.rs from abi/abi.toml
#   python3 tools/abigen.py --check      the description, the locks, the generated files and the code
#                                        against the description; nothing written (exit 1 on any FAIL)
#   python3 tools/abigen.py --test       --check as tests 1-4 of the V081 plan + the mutations (test 10)
#                                        – what tests/test.sh runs ([ABI HOST TEST] lines)
#   python3 tools/abigen.py --new-lock   write abi/abi-<version>.lock for the version in abi.toml – only
#                                        when that lock does not exist yet and every older lock passes
#
# Rules (D4): within one major version entries are only added – never renumbered, changed or
# removed (stable -> deprecated is allowed).  A new entry gets since = the next minor, abi.toml's
# version becomes that minor and --new-lock writes its lock.  Old locks stay and are all checked;
# a lock is never rewritten, so a lock update can never approve a break.
#   --root DIR   work on another copy of the tree (the mutation test uses it)
import hashlib
import os
import re
import shutil
import sys
import tempfile

ARG_TYPES = ("handle", "ptr_in", "ptr_out", "len", "u64", "i64", "flags")
STATUSES = ("stable", "deprecated", "unstable", "reserved")
TEST_CLASSES = ("normal", "stateful", "blocking", "hardware", "terminal")
CONST_TYPES = {"u64": (0, 2**64 - 1), "i64": (-2**63, 2**63 - 1), "usize": (0, 2**64 - 1), "u16": (0, 2**16 - 1)}
SYSCALL_KEYS = ("number", "name", "since", "status", "args", "returns", "errors", "path", "handles", "in_call", "test_class", "test")
CONST_KEYS = ("group", "name", "type", "value", "kernel", "lib", "meaning", "since", "status")
REGS = ("rdi", "rsi", "rdx", "r10", "r8", "r9")

TOML = "abi/abi.toml"
DOC = "docs/abi/SYSCALLS.md"
LIB = "user/lib/abi_generated.rs"
KERN = "kernel/user/abi_generated.rs"
DESO = "user/lib/deso.rs"
SYSCALLS_RS = "kernel/user/syscalls.rs"


class Fail(Exception):
    pass


# ---------------------------------------------------------------- a small TOML reader
# Enough TOML for abi.toml: comments, [table], [[array of tables]], key = value on one line;
# values: "strings" (\" \\ \n escapes), integers (decimal, 0x hex, _ separators, sign),
# true / false, [arrays] and { inline tables } nested in any way.

class _P:
    def __init__(self, s, line):
        self.s, self.i, self.line = s, 0, line

    def err(self, what):
        raise Fail("%s line %d: %s (at %r)" % (TOML, self.line, what, self.s[self.i:self.i + 20]))

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1

    def value(self):
        self.ws()
        if self.i >= len(self.s):
            self.err("value expected")
        c = self.s[self.i]
        if c == '"':
            out = []
            self.i += 1
            while True:
                if self.i >= len(self.s):
                    self.err("unterminated string")
                c = self.s[self.i]
                if c == '"':
                    self.i += 1
                    return "".join(out)
                if c == "\\":
                    nx = self.s[self.i + 1:self.i + 2]
                    m = {'"': '"', "\\": "\\", "n": "\n", "t": "\t"}.get(nx)
                    if m is None:
                        self.err("bad escape")
                    out.append(m)
                    self.i += 2
                    continue
                out.append(c)
                self.i += 1
        if c == "[":
            self.i += 1
            arr = []
            while True:
                self.ws()
                if self.s[self.i:self.i + 1] == "]":
                    self.i += 1
                    return arr
                arr.append(self.value())
                self.ws()
                if self.s[self.i:self.i + 1] == ",":
                    self.i += 1
                elif self.s[self.i:self.i + 1] != "]":
                    self.err("',' or ']' expected")
        if c == "{":
            self.i += 1
            tab = {}
            while True:
                self.ws()
                if self.s[self.i:self.i + 1] == "}":
                    self.i += 1
                    return tab
                k = self.key()
                self.ws()
                if self.s[self.i:self.i + 1] != "=":
                    self.err("'=' expected")
                self.i += 1
                if k in tab:
                    self.err("key %s given twice" % k)
                tab[k] = self.value()
                self.ws()
                if self.s[self.i:self.i + 1] == ",":
                    self.i += 1
                elif self.s[self.i:self.i + 1] != "}":
                    self.err("',' or '}' expected")
        m = re.compile(r"true|false|[+-]?0x[0-9A-Fa-f_]+|[+-]?[0-9][0-9_]*").match(self.s, self.i)
        if not m:
            self.err("unknown value")
        self.i = m.end()
        t = m.group(0)
        if t in ("true", "false"):
            return t == "true"
        return int(t.replace("_", ""), 0)

    def key(self):
        m = re.compile(r"[A-Za-z0-9_-]+").match(self.s, self.i)
        if not m:
            self.err("key expected")
        self.i = m.end()
        return m.group(0)


def parse_toml(text):
    root = {}
    cur = root
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[\[([A-Za-z0-9_]+)\]\]", line)
        if m:
            cur = {"_line": n}
            root.setdefault(m.group(1), []).append(cur)
            continue
        m = re.fullmatch(r"\[([A-Za-z0-9_]+)\]", line)
        if m:
            cur = root.setdefault(m.group(1), {"_line": n})
            continue
        p = _P(line, n)
        k = p.key()
        p.ws()
        if p.s[p.i:p.i + 1] != "=":
            p.err("'=' expected")
        p.i += 1
        v = p.value()
        p.ws()
        if p.i < len(p.s) and not p.s[p.i:].lstrip().startswith("#"):
            p.err("text after the value")
        if k in cur:
            p.err("key %s given twice" % k)
        cur[k] = v
    return root


# ---------------------------------------------------------------- the description (test 2)

def ver(s, where):
    m = re.fullmatch(r"([0-9]+)\.([0-9]+)", s if isinstance(s, str) else "")
    if not m:
        raise Fail("%s: version %r is not MAJOR.MINOR" % (where, s))
    return int(m.group(1)), int(m.group(2))


def load(root):
    with open(os.path.join(root, TOML), encoding="utf-8") as f:
        d = parse_toml(f.read())
    return validate(d)


def validate(d):
    """Test 2: the description is complete and consistent.  Returns the checked model."""
    errs = []

    def need(cond, msg):
        if not cond:
            errs.append(msg)

    abi = d.get("abi", {})
    version = ver(abi.get("version"), "[abi] version")
    sys_ = d.get("syscall", [])
    consts = d.get("const", [])
    cmap = {}
    for c in consts:
        w = "const at line %d" % c.get("_line", 0)
        for k in CONST_KEYS:
            need(k in c, "%s: no %s" % (w, k))
        for k in c:
            need(k in CONST_KEYS or k == "_line", "%s: unknown key %s" % (w, k))
        if not all(k in c for k in CONST_KEYS):
            continue
        name = c["name"]
        need(re.fullmatch(r"[A-Z][A-Z0-9_]*", name) is not None, "%s: bad name %r" % (w, name))
        need(name not in cmap, "constant %s given twice" % name)
        need(c["type"] in CONST_TYPES, "%s: unknown type %s" % (name, c["type"]))
        if c["type"] in CONST_TYPES:
            lo, hi = CONST_TYPES[c["type"]]
            need(isinstance(c["value"], int) and lo <= c["value"] <= hi, "%s: value %r does not fit %s" % (name, c["value"], c["type"]))
        need(c["status"] in ("stable", "deprecated", "unstable"), "%s: bad status %s" % (name, c["status"]))
        need(isinstance(c["lib"], bool), "%s: lib must be true / false" % name)
        try:
            need(ver(c["since"], name) <= version, "%s: since %s is newer than the ABI version" % (name, c["since"]))
        except Fail as e:
            errs.append(str(e))
        need(c["kernel"] == "" or re.fullmatch(r"crate(::[A-Za-z_][A-Za-z0-9_]*)+", c["kernel"]) is not None, "%s: bad kernel path %r" % (name, c["kernel"]))
        cmap[name] = c
    groups = {}
    for c in cmap.values():
        groups.setdefault(c["group"], []).append(c)
    errors = {c["name"] for c in groups.get("error", [])}
    kinds = {c["name"][5:]: c["value"] for c in groups.get("kind", [])}
    rights = {c["name"][2:]: c["value"] for c in groups.get("right", []) if c["name"] != "R_ALL"}
    need(len(errors) > 0 and len(kinds) > 0 and len(rights) > 0, "the description needs error, kind and right constants")
    for e in errors:
        need(cmap[e]["value"] < 0, "%s: an error must be negative" % e)
    vals = {}
    for e in sorted(errors):
        v = cmap[e]["value"]
        need(v not in vals, "%s and %s have the same value %d" % (vals.get(v), e, v))
        vals[v] = e

    nums = {}
    names = set()
    for s in sys_:
        w = "syscall at line %d" % s.get("_line", 0)
        for k in SYSCALL_KEYS:
            need(k in s, "%s: no %s" % (w, k))
        for k in s:
            need(k in SYSCALL_KEYS or k == "_line", "%s: unknown key %s" % (w, k))
        if not all(k in s for k in SYSCALL_KEYS):
            continue
        name = s["name"]
        w = name
        need(re.fullmatch(r"SYS_[A-Z0-9_]+", name) is not None, "%s: bad name" % w)
        need(name not in names, "syscall %s given twice" % name)
        names.add(name)
        need(isinstance(s["number"], int) and s["number"] >= 0, "%s: bad number" % w)
        need(s["number"] not in nums, "number %s given to %s and %s" % (s["number"], nums.get(s["number"]), name))
        nums[s["number"]] = name
        need(s["status"] in STATUSES, "%s: bad status %s" % (w, s["status"]))
        try:
            need(ver(s["since"], w) <= version, "%s: since %s is newer than the ABI version" % (w, s["since"]))
        except Fail as e:
            errs.append(str(e))
        need(s["test_class"] in TEST_CLASSES, "%s: bad test_class %s" % (w, s["test_class"]))
        need(isinstance(s["test"], str) and s["test"].strip() != "", "%s: no test named (every entry is tested or names where it is checked)" % w)
        need(isinstance(s["returns"], str) and s["returns"] != "", "%s: no returns" % w)
        need(isinstance(s["path"], bool), "%s: path must be true / false" % w)
        need(isinstance(s["args"], list) and len(s["args"]) <= 6, "%s: at most 6 arguments" % w)
        an = set()
        for i, a in enumerate(s["args"]):
            need(isinstance(a, dict) and set(a) == {"name", "type", "meaning"}, "%s argument %d: needs name, type, meaning" % (w, i))
            if not isinstance(a, dict) or set(a) != {"name", "type", "meaning"}:
                continue
            need(a["type"] in ARG_TYPES, "%s argument %d: unknown type %s" % (w, i, a["type"]))
            need(re.fullmatch(r"[a-z][a-z0-9_]*", a["name"]) is not None and a["name"] not in an, "%s argument %d: bad or repeated name %r" % (w, i, a["name"]))
            need(a["meaning"].strip() != "", "%s argument %d: no meaning" % (w, i))
            an.add(a["name"])
        need(isinstance(s["errors"], list) and all(e in errors for e in s["errors"]), "%s: errors must name ERROR_* constants (%s)" % (w, [e for e in s["errors"] if e not in errors]))
        need(s["errors"] == sorted(set(s["errors"])), "%s: errors sorted and without repeats" % w)
        if s["status"] == "reserved":
            need(s["args"] == [] and s["handles"] == [] and s["errors"] == ["ERROR_NOT_IMPLEMENTED"] and not s["path"], "%s: a reserved number has no arguments and only ERROR_NOT_IMPLEMENTED" % w)
        elif s["status"] != "unstable":
            need("ERROR_NOT_IMPLEMENTED" not in s["errors"], "%s: ERROR_NOT_IMPLEMENTED only for reserved numbers" % w)
        regs = set()
        for h in s["handles"]:
            need(isinstance(h, dict) and {"reg", "kinds", "need"} <= set(h) <= {"reg", "kinds", "need", "conds"}, "%s: a handle needs reg, kinds, need (conds)" % w)
            if not isinstance(h, dict) or not {"reg", "kinds", "need"} <= set(h):
                continue
            r = h["reg"]
            need(isinstance(r, int) and 0 <= r < len(s["args"]) and s["args"][r]["type"] == "handle", "%s: handle register %s is not a handle argument" % (w, r))
            need(r not in regs, "%s: handle register %s twice" % (w, r))
            regs.add(r)
            need(h["kinds"] == ["ANY"] or (h["kinds"] and all(k in kinds for k in h["kinds"])), "%s: unknown kinds %s" % (w, h["kinds"]))
            need(all(x in rights for x in h["need"]), "%s: unknown rights %s" % (w, h["need"]))
            conds = h.get("conds", [])
            need(len(conds) <= 2, "%s: at most 2 conditions" % w)
            for c in conds:
                ok = isinstance(c, dict) and set(c) == {"reg", "bit", "right"}
                need(ok, "%s: a condition needs reg, bit, right" % w)
                if ok:
                    need(isinstance(c["reg"], int) and 0 <= c["reg"] < len(s["args"]) and s["args"][c["reg"]]["type"] == "flags", "%s: condition register %s is not a flags argument" % (w, c["reg"]))
                    need(isinstance(c["bit"], int) and c["bit"] > 0 and c["right"] in rights, "%s: bad condition" % w)
        for i, a in enumerate(s["args"]):
            if isinstance(a, dict) and a.get("type") == "handle" and i not in regs:
                need(s["in_call"] != "", "%s: handle argument %s is in no rights row and in_call is empty" % (w, a["name"]))
    if nums:
        top = max(nums)
        gaps = [n for n in range(top + 1) if n not in nums]
        need(not gaps, "numbers without an entry: %s (a removed number stays as status = \"reserved\")" % gaps)
    if errs:
        raise Fail("\n".join("description: " + e for e in errs))
    sys_ = sorted(sys_, key=lambda s: s["number"])
    return {"version": version, "syscalls": sys_, "consts": [cmap[n] for n in sorted(cmap, key=lambda n: (order_of(cmap[n]["group"]), cmap[n]["group"], cmap[n]["value"] if cmap[n]["group"] != "error" else -cmap[n]["value"], n))],
            "cmap": cmap, "kinds": kinds, "rights": rights}


GROUP_ORDER = ["error", "kind", "right", "open", "memory", "seek", "spawn", "wait", "channel", "wait_many", "dir", "random", "time", "sysctl", "slot", "pci", "net", "startup"]


def order_of(g):
    return GROUP_ORDER.index(g) if g in GROUP_ORDER else len(GROUP_ORDER)


# ---------------------------------------------------------------- what follows from the description

def short(name):
    return name[4:].lower()


def kind_mask(m, h):
    if h["kinds"] == ["ANY"]:
        return 0xFFFE
    x = 0
    for k in h["kinds"]:
        x |= 1 << m["kinds"][k]
    return x


def rights_mask(m, names):
    x = 0
    for r in names:
        x |= m["rights"][r]
    return x


def rights_text(m):
    """What kernel/user/sysrights.rs text() prints for this description."""
    out = []
    for s in m["syscalls"]:
        if s["status"] == "reserved":
            continue
        line = "%d %s %s" % (s["number"], short(s["name"]), "path" if s["path"] else "-")
        for h in s["handles"]:
            line += " %d:%x:%x" % (h["reg"], kind_mask(m, h), rights_mask(m, h["need"]))
            for c in h.get("conds", []):
                line += "+%d:%x:%x" % (c["reg"], c["bit"], m["rights"][c["right"]])
        if s["in_call"]:
            line += " | checked in the call: " + s["in_call"]
        out.append(line + "\n")
    return "".join(out)


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def lit(c):
    v, t = c["value"], c["type"]
    if t == "i64" or (0 <= v < 256):
        return str(v)
    return "0x%X" % v


HEADER = "// Generated by tools/abigen.py from abi/abi.toml – do not edit (docs/abi/README.md).\n"


def gen_lib(m):
    maj, mnr = m["version"]
    o = [HEADER, "// The DeSo OS ABI %d.%d as constants for programs.\n#![allow(dead_code)]\n\n" % (maj, mnr)]
    o.append("pub const ABI_MAJOR: u16 = %d;\npub const ABI_MINOR: u16 = %d;\n\n" % (maj, mnr))
    o.append("// System calls (number in rax; arguments rdi, rsi, rdx, r10, r8, r9; result in rax).\n")
    for s in m["syscalls"]:
        if s["status"] in ("reserved", "unstable"):
            continue
        o.append("pub const %s: u64 = %d;\n" % (s["name"], s["number"]))
    o.append("/// Numbers 0..SYSCALL_COUNT have an entry (reserved ones give ERROR_NOT_IMPLEMENTED).\npub const SYSCALL_COUNT: u64 = %d;\n" % (m["syscalls"][-1]["number"] + 1))
    res = [s["number"] for s in m["syscalls"] if s["status"] == "reserved"]
    o.append("pub const RESERVED: [u64; %d] = [%s];\n" % (len(res), ", ".join(map(str, res))))
    gated = [(s["number"], s["handles"][0]["reg"], s["name"]) for s in m["syscalls"] if s["handles"] and s["status"] != "unstable"]
    o.append("/// (syscall, register of its first handle argument) – every row of the rights table.\npub const HANDLE_ARGS: [(u64, usize, &str); %d] = [\n" % len(gated))
    for n, r, name in gated:
        o.append("    (%d, %d, %s),\n" % (n, r, rust_str(name)))
    o.append("];\n")
    paths = [s["number"] for s in m["syscalls"] if s["path"] and s["status"] != "unstable"]
    o.append("/// Calls that name a path (refused in the file sandbox).\npub const PATH_CALLS: [u64; %d] = [%s];\n" % (len(paths), ", ".join(map(str, paths))))
    grp = None
    for c in m["consts"]:
        if not c["lib"] or c["status"] == "unstable":
            continue
        if c["group"] != grp:
            grp = c["group"]
            o.append("\n// %s\n" % grp)
        o.append("pub const %s: %s = %s;\n" % (c["name"], c["type"], lit(c)))
    return "".join(o)


def gen_kernel(m):
    maj, mnr = m["version"]
    o = [HEADER, "// The kernel side of ABI TEST (kernel/user/test_abi.rs): the rights table and the constants\n"
                 "// the description promises.\n#![allow(dead_code)]\n\n"]
    o.append("pub const ABI_MAJOR: u16 = %d;\npub const ABI_MINOR: u16 = %d;\n" % (maj, mnr))
    o.append("pub const SYSCALL_COUNT: usize = %d;\n" % (m["syscalls"][-1]["number"] + 1))
    o.append("/// kernel/user/sysrights.rs text() as the description gives it.\npub const RIGHTS_TEXT: &str = concat!(\n")
    for line in rights_text(m).splitlines(True):
        o.append("    %s,\n" % rust_str(line))
    o.append(");\n\n")
    o.append("/// Every syscall number and every constant with a kernel path against the kernel's value;\n"
             "/// Err(name) at the first difference, Ok(how many were compared).\n"
             "pub fn check() -> Result<usize, &'static str> {\n    let mut n = 0usize;\n"
             "    macro_rules! c {\n        ($k:expr, $v:expr, $name:expr) => {\n            if ($k) as i128 != $v {\n                return Err($name);\n            }\n            n += 1;\n        };\n    }\n")
    for s in m["syscalls"]:
        if s["status"] in ("reserved", "unstable"):
            continue
        o.append("    c!(crate::user::syscalls::%s, %d, %s);\n" % (s["name"], s["number"], rust_str(s["name"])))
    for c in m["consts"]:
        if c["kernel"]:
            o.append("    c!(%s, %d, %s);\n" % (c["kernel"], c["value"], rust_str(c["name"])))
    o.append("    Ok(n)\n}\n\n/// Reserved numbers – no row in the rights table.\npub const RESERVED: [usize; %d] = [%s];\n" % (
        len([s for s in m["syscalls"] if s["status"] == "reserved"]), ", ".join(str(s["number"]) for s in m["syscalls"] if s["status"] == "reserved")))
    return "".join(o)


def md(s):
    return s.replace("|", "\\|")


def rights_human(m, s):
    parts = []
    for h in s["handles"]:
        a = s["args"][h["reg"]]["name"]
        t = "%s: %s" % (a, "/".join(h["kinds"]))
        if h["need"]:
            t += " needs " + "+".join(h["need"])
        for c in h.get("conds", []):
            t += ", %s if %s has 0x%x" % (c["right"], s["args"][c["reg"]]["name"], c["bit"])
        parts.append(t)
    if s["path"]:
        parts.append("path (refused in the file sandbox)")
    if s["in_call"]:
        parts.append("checked in the call: " + s["in_call"])
    return "; ".join(parts) or "–"


def gen_doc(m):
    maj, mnr = m["version"]
    o = ["<!-- Generated by tools/abigen.py from abi/abi.toml – do not edit. -->\n",
         "# DeSo system calls – ABI %d.%d\n\n" % (maj, mnr),
         "What a program may rely on (rules: [README.md](README.md)).  A call: number in `rax`, arguments in `rdi`, `rsi`, "
         "`rdx`, `r10`, `r8`, `r9`, `syscall`; the result in `rax` as i64 – `>= 0` a value, `< 0` an `ERROR_*` code.  "
         "The errors listed are the ones ABI %d.%d documents for the call; a program treats any other negative value as a "
         "failure too.  Argument types: `handle`, `ptr_in` (the kernel reads it), `ptr_out` (the kernel writes it), `len`, "
         "`u64`, `i64`, `flags`.  Every handle argument goes through the rights gate first: a missing handle or one of the "
         "wrong kind = `ERROR_INVALID_HANDLE`, a missing right = `ERROR_ACCESS_DENIED`.\n\n" % (maj, mnr)]
    o.append("| # | Call | Arguments | Returns | Rights | Status | Since | Test |\n|---|---|---|---|---|---|---|---|\n")
    for s in m["syscalls"]:
        args = ", ".join("`%s: %s`" % (a["name"], a["type"]) for a in s["args"]) or "–"
        o.append("| %d | `%s` | %s | %s | %s | %s | %s | %s: %s |\n" % (
            s["number"], s["name"], args, md(s["returns"]), md(rights_human(m, s)), s["status"], s["since"], s["test_class"], md(s["test"])))
    o.append("\n## Calls in detail\n")
    for s in m["syscalls"]:
        o.append("\n### %d `%s`\n\n" % (s["number"], s["name"]))
        if s["args"]:
            for i, a in enumerate(s["args"]):
                o.append("- `%s` (%s, %s): %s\n" % (a["name"], REGS[i], a["type"], a["meaning"]))
        else:
            o.append("- no arguments\n")
        o.append("- returns: %s\n- errors: %s\n- rights: %s\n" % (s["returns"], ", ".join("`%s`" % e for e in s["errors"]) or "–", rights_human(m, s)))
    o.append("\n## Constants\n")
    grp = None
    for c in m["consts"]:
        if c["group"] != grp:
            grp = c["group"]
            o.append("\n### %s\n\n| Name | Type | Value | Meaning | Since | Status |\n|---|---|---|---|---|---|\n" % grp)
        o.append("| `%s` | %s | `%s` | %s | %s | %s%s |\n" % (c["name"], c["type"], lit(c), md(c["meaning"]) or "–", c["since"], c["status"],
                                                        "" if c["lib"] else " (not in the program library – the loader's contract)"))
    return "".join(o)


def generated(m):
    return {DOC: gen_doc(m), LIB: gen_lib(m), KERN: gen_kernel(m)}


# ---------------------------------------------------------------- locks (test 1)

def lock_entries(m, upto):
    """{name: line} of every entry a lock of version `upto` holds (unstable never)."""
    out = {}
    for s in m["syscalls"]:
        if s["status"] == "unstable" or ver(s["since"], s["name"]) > upto:
            continue
        if s["status"] == "reserved":
            out[s["name"]] = "%s number=%d reserved" % (s["name"], s["number"])
            continue
        args = ", ".join("%s:%s" % (a["name"], a["type"]) for a in s["args"])
        rights = []
        for h in s["handles"]:
            t = "%s %s need %s" % (s["args"][h["reg"]]["name"], "|".join(h["kinds"]), "|".join(h["need"]) or "-")
            for c in h.get("conds", []):
                t += " +%s if %s&0x%x" % (c["right"], s["args"][c["reg"]]["name"], c["bit"])
            rights.append(t)
        out[s["name"]] = "%s number=%d args=(%s) returns=%s rights=[%s] path=%s status=%s" % (
            s["name"], s["number"], args, "never" if s["returns"] == "never" else "value", "; ".join(rights), "yes" if s["path"] else "no", s["status"])
    for c in m["consts"]:
        if c["status"] == "unstable" or ver(c["since"], c["name"]) > upto:
            continue
        out[c["name"]] = "%s type=%s value=%d status=%s" % (c["name"], c["type"], c["value"], c["status"])
    return out


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def lock_text(m, upto):
    e = lock_entries(m, upto)
    lines = [e[k] for k in sorted(e, key=lambda k: (not k.startswith("SYS_"), k))]
    o = ["# DeSo OS ABI %d.%d lock – written once by tools/abigen.py --new-lock, never edited.\n" % upto,
         "# One line per entry + the SHA-256 of the line; TOTAL = SHA-256 of all entry lines.\n"]
    o += ["%s  sha256=%s\n" % (l, sha(l)) for l in lines]
    o.append("TOTAL sha256=%s\n" % sha("\n".join(lines)))
    return "".join(o)


def read_lock(path):
    """{name: line}; Fail on a damaged lock."""
    lines, total = [], None
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            raw = raw.rstrip("\n")
            if not raw or raw.startswith("#"):
                continue
            if raw.startswith("TOTAL sha256="):
                total = raw[len("TOTAL sha256="):]
                continue
            mm = re.fullmatch(r"(.*)  sha256=([0-9a-f]{64})", raw)
            if not mm or sha(mm.group(1)) != mm.group(2):
                raise Fail("%s line %d: damaged (the line does not match its SHA-256)" % (os.path.basename(path), n))
            lines.append(mm.group(1))
    if total is None or sha("\n".join(lines)) != total:
        raise Fail("%s: damaged (TOTAL does not match - a line added, removed or moved)" % os.path.basename(path))
    out = {}
    for l in lines:
        out[l.split(" ", 1)[0]] = l
    return out


FIELD = re.compile(r" (?=(?:number|args|returns|rights|path|status|type|value)=)")


def fields(line):
    parts = FIELD.split(line)
    d = {"name": parts[0]}
    for p in parts[1:]:
        k, v = p.split("=", 1)
        d[k] = v
    if line.endswith(" reserved"):
        d["status"] = "reserved"
        d["number"] = d.get("number", "").replace(" reserved", "")
    return d


def diff_entry(name, old, new):
    a, b = fields(old), fields(new)
    out = []
    for k in ("number", "type", "value", "returns", "path", "rights"):
        if a.get(k) != b.get(k):
            out.append("ABI BREAK: %s %s: lock '%s', now '%s'" % (name, k, a.get(k), b.get(k)))
    if a.get("args") != b.get("args"):
        la = [x for x in (a.get("args") or "()")[1:-1].split(", ") if x]
        lb = [x for x in (b.get("args") or "()")[1:-1].split(", ") if x]
        if len(la) != len(lb):
            out.append("ABI BREAK: %s argument count: lock %d, now %d" % (name, len(la), len(lb)))
        for i, (x, y) in enumerate(zip(la, lb)):
            if x != y:
                out.append("ABI BREAK: %s argument %d: lock '%s', now '%s'" % (name, i, x, y))
    sa, sb = a.get("status"), b.get("status")
    if sa != sb and not (sa == "stable" and sb == "deprecated"):
        out.append("ABI BREAK: %s status: lock '%s', now '%s'" % (name, sa, sb))
    return out


def lock_files(root):
    d = os.path.join(root, "abi")
    out = []
    for f in os.listdir(d):
        mm = re.fullmatch(r"abi-([0-9]+)\.([0-9]+)\.lock", f)
        if mm:
            out.append(((int(mm.group(1)), int(mm.group(2))), os.path.join(d, f)))
    return sorted(out)


def check_locks(root, m):
    """Test 1.  Returns a list of lines; Fail with the human diff."""
    locks = lock_files(root)
    if not locks:
        raise Fail("no abi/abi-*.lock (python3 tools/abigen.py --new-lock)")
    msgs, report = [], []
    top = locks[-1][0]
    if m["version"] > top:
        msgs.append("ABI %d.%d has no lock yet (python3 tools/abigen.py --new-lock)" % m["version"])
    if m["version"] < top:
        msgs.append("abi.toml version %d.%d is older than lock %d.%d" % (m["version"] + top))
    for v, path in locks:
        try:
            old = read_lock(path)
        except Fail as e:
            msgs.append(str(e))
            continue
        now = lock_entries(m, v)
        n0 = len(msgs)
        for name in sorted(old):
            if name not in now:
                msgs.append("ABI BREAK: %s removed (lock %d.%d)" % ((name,) + v))
            elif old[name] != now[name]:
                msgs += diff_entry(name, old[name], now[name])
        for name in sorted(now):
            if name not in old:
                msgs.append("ABI ADD WITHOUT VERSION: %s (since %s, but not in lock %d.%d - a new entry needs the next minor and its lock)" % ((name, (m["cmap"].get(name) or next(s for s in m["syscalls"] if s["name"] == name))["since"]) + v))
        changes = len(msgs) - n0
        report.append("ABI %d.%d lock: %s" % (v + ("OK (%d entries)" % len(old) if not changes else "FAILED (%d changes)" % changes,)))
    for s in m["syscalls"] + m["consts"]:
        if s["status"] != "unstable" and ver(s["since"], s["name"]) > top:
            msgs.append("ABI ADD WITHOUT VERSION: %s since %s - no lock for that version" % (s["name"], s["since"]))
    if msgs:
        raise Fail("\n".join(msgs + report))
    return report


# ---------------------------------------------------------------- the code against the description (test 4, host part)

def eval_rust_int(expr):
    e = expr.strip()
    e = re.sub(r"(?<=[0-9A-Fa-f])_(?=[0-9A-Fa-f])", "", e)
    e = e.replace("u64::MAX", str(2**64 - 1)).replace("usize::MAX", str(2**64 - 1))
    mm = re.fullmatch(r"fds\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)", e)
    if mm:
        return int(mm.group(1)) | int(mm.group(2)) << 16 | int(mm.group(3)) << 32
    if not re.fullmatch(r"[0-9a-fA-Fx\s+\-*()<>]+", e):
        raise Fail("cannot read the value %r" % expr)
    return eval(e, {"__builtins__": {}}, {})


def check_deso(root, m):
    """Every pub const of the program library has the value and type of the description, and every
    library constant of the description is there (until stage B the library keeps its own copy)."""
    with open(os.path.join(root, DESO), encoding="utf-8") as f:
        src = f.read()
    found = {}
    for mm in re.finditer(r"^pub const ([A-Z][A-Z0-9_]*): ([a-z0-9]+) = (.*?);\s*$", src, re.M):
        found[mm.group(1)] = (mm.group(2), eval_rust_int(mm.group(3)))
    msgs = []
    sysn = {s["name"]: s["number"] for s in m["syscalls"] if s["status"] not in ("reserved", "unstable")}
    for name, (t, v) in sorted(found.items()):
        if name.startswith("SYS_"):
            if name not in sysn:
                msgs.append("%s: %s is not in abi.toml" % (DESO, name))
            elif (t, v) != ("u64", sysn[name]):
                msgs.append("%s: %s = %s %s, abi.toml says u64 %d" % (DESO, name, t, v, sysn[name]))
            continue
        c = m["cmap"].get(name)
        if c is None:
            msgs.append("%s: %s is not in abi.toml (a constant programs see must be described)" % (DESO, name))
        elif (c["type"], c["value"]) != (t, v):
            msgs.append("%s: %s = %s %s, abi.toml says %s %s" % (DESO, name, t, v, c["type"], c["value"]))
        elif not c["lib"]:
            msgs.append("%s: %s is in the library but abi.toml says lib = false" % (DESO, name))
    for name in sysn:
        if name not in found:
            msgs.append("%s: %s missing" % (DESO, name))
    for c in m["consts"]:
        if c["lib"] and c["status"] != "unstable" and c["name"] not in found:
            msgs.append("%s: %s missing (abi.toml: lib = true)" % (DESO, c["name"]))
    if msgs:
        raise Fail("\n".join(msgs))
    return len(found)


def fn_body(src, name):
    mm = re.search(r"\n(?:pub(?:\([a-z]+\))? )?fn " + name + r"\((.*?)\n}\n", src, re.S)
    return mm.group(0) if mm else ""


def regs_used(src, text, depth=0):
    used = set()
    for i, a in enumerate(("a0", "a1", "a2")):
        if re.search(r"\b%s\b" % a, text):
            used.add(i)
    for i, r in enumerate(REGS):
        if re.search(r"\b(?:frame|f)\.%s\b" % r, text):
            used.add(i)
    if depth < 3:
        for fn, argl in re.findall(r"\b([a-z_][a-z0-9_]*)\(([^()]*\b(?:frame|f)\b[^()]*)\)", text):
            if re.search(r"\b(?:frame|f)\b(?!\.)", argl):
                used |= regs_used(src, fn_body(src, fn), depth + 1)
    return used


def check_kernel_src(root, m):
    """Syscall numbers in kernel/user/syscalls.rs = the description; the registers each dispatch arm
    reads = the number of arguments the description gives (an argument added, removed or moved past
    the end is caught here; the rights rows and the values in ABI TEST in the kernel)."""
    with open(os.path.join(root, SYSCALLS_RS), encoding="utf-8") as f:
        src = f.read()
    msgs = []
    kn = {mm.group(1): int(mm.group(2)) for mm in re.finditer(r"^pub const (SYS_[A-Z0-9_]+): u64 = (\d+);", src, re.M)}
    live = {s["name"]: s for s in m["syscalls"] if s["status"] not in ("reserved", "unstable")}
    for name, s in sorted(live.items()):
        if kn.get(name) != s["number"]:
            msgs.append("%s: %s = %s, abi.toml says %d" % (SYSCALLS_RS, name, kn.get(name), s["number"]))
    for name in sorted(kn):
        if name not in live:
            msgs.append("%s: %s is not in abi.toml (or marked reserved there)" % (SYSCALLS_RS, name))
    i = src.find("let result: SysResult = match frame.rax")
    j = src.find("_ => Err(ERROR_NOT_IMPLEMENTED)", i)
    if i < 0 or j < 0:
        raise Fail("%s: the dispatch (let result: SysResult = match frame.rax ... _ => Err(ERROR_NOT_IMPLEMENTED)) not found" % SYSCALLS_RS)
    arms = re.split(r"\n\s+(?=SYS_[A-Z0-9_]+ =>)", src[i:j])[1:]
    seen = set()
    for arm in arms:
        name = arm.split(" ", 1)[0]
        seen.add(name)
        if name not in live:
            continue
        used = regs_used(src, arm)
        n = max(used) + 1 if used else 0
        want = len(live[name]["args"])
        if n != want:
            msgs.append("ABI BREAK: %s: the kernel reads %d argument register(s) %s, abi.toml gives %d argument(s)" % (name, n, [REGS[k] for k in sorted(used)], want))
    for name in sorted(set(live) - seen):
        msgs.append("%s: %s has no arm in the dispatch" % (SYSCALLS_RS, name))
    if msgs:
        raise Fail("\n".join(msgs))
    return len(arms)


# ---------------------------------------------------------------- the commands

def check_generated(root, m):
    """Test 3: two runs give the same bytes, and they are the files in the tree."""
    a, b = generated(m), generated(validate(parse_toml(open(os.path.join(root, TOML), encoding="utf-8").read())))
    if a != b:
        raise Fail("the generator is not deterministic (two runs differ)")
    msgs = []
    for path, text in sorted(a.items()):
        p = os.path.join(root, path)
        if not os.path.exists(p):
            msgs.append("%s missing (python3 tools/abigen.py)" % path)
        elif open(p, encoding="utf-8").read() != text:
            msgs.append("%s differs from abi/abi.toml (python3 tools/abigen.py; never edit it by hand)" % path)
    if msgs:
        raise Fail("\n".join(msgs))
    return sum(len(t) for t in a.values())


def run_checks(root, out):
    """Tests 1-4 (host); prints [ABI HOST TEST] lines; True when all pass."""
    ok = True

    def step(nr, title, fn):
        nonlocal ok
        try:
            res = fn()
            out("[ABI HOST TEST] %d/5 %s: %s PASS" % (nr, title, res))
            return res
        except Fail as e:
            ok = False
            out("[ABI HOST TEST] %d/5 %s: FAIL" % (nr, title))
            for line in str(e).splitlines():
                out("    " + line)
            return None

    box = []

    def desc():
        box.append(load(root))
        mm = box[0]
        st = [s for s in mm["syscalls"] if s["status"] == "stable"]
        return "ABI %d.%d, %d syscall numbers (%d stable, %d reserved), %d constants, every stable entry with a test" % (
            mm["version"] + (len(mm["syscalls"]), len(st), len(mm["syscalls"]) - len(st), len(mm["consts"])))

    step(2, "description abi/abi.toml", desc)
    if not box:
        return False
    mm = box[0]
    step(1, "locks", lambda: "; ".join(check_locks(root, mm)))
    step(3, "generator", lambda: "deterministic, %d bytes = the files in the tree" % check_generated(root, mm))
    step(4, "code = description",
         lambda: "%s: %d syscall numbers and argument counts; %s: %d constants" % (SYSCALLS_RS, check_kernel_src(root, mm), DESO, check_deso(root, mm)))
    return ok


def copy_tree(root):
    tmp = tempfile.mkdtemp(prefix="deso-abi-")
    for rel in ("abi", "docs/abi", "tools"):
        src = os.path.join(root, rel)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(tmp, rel))
    for rel in (LIB, KERN, DESO, SYSCALLS_RS):
        os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
        shutil.copy(os.path.join(root, rel), os.path.join(tmp, rel))
    return tmp


def sub(path, old, new, count=1):
    with open(path, encoding="utf-8") as f:
        t = f.read()
    if old not in t:
        raise Fail("mutation: %r not found in %s" % (old, path))
    with open(path, "w", encoding="utf-8") as f:
        f.write(t.replace(old, new, count))


MUTATIONS = [
    # (description, file, old, new, the message that must appear, regenerate the files first)
    ("syscall renumbered", TOML, [('number = 2\nname = "SYS_READ"', 'number = 21\nname = "SYS_READ"'), ('number = 21\nname = "SYS_RESERVED_21"', 'number = 2\nname = "SYS_RESERVED_21"')], None,
     "ABI BREAK: SYS_READ number: lock '2', now '21'", True),
    ("arguments swapped", TOML, '{ name = "buf", type = "ptr_out", meaning = "where to" }, { name = "len", type = "len", meaning = "room" }]\nreturns = "bytes read',
     '{ name = "len", type = "len", meaning = "room" }, { name = "buf", type = "ptr_out", meaning = "where to" }]\nreturns = "bytes read', "ABI BREAK: SYS_READ argument 1: lock 'buf:ptr_out', now 'len:len'", True),
    ("argument type changed", TOML, '{ name = "len", type = "len", meaning = "how many" }]\nreturns = "bytes written"', '{ name = "len", type = "u64", meaning = "how many" }]\nreturns = "bytes written"',
     "ABI BREAK: SYS_WRITE argument 2", True),
    ("argument added", TOML, '{ name = "flags", type = "flags", meaning = "O_*" }]\nreturns = "handle"', '{ name = "flags", type = "flags", meaning = "O_*" }, { name = "mode", type = "u64", meaning = "x" }]\nreturns = "handle"',
     "ABI BREAK: SYS_OPEN argument count", True),
    ("right changed", TOML, 'handles = [{ reg = 0, kinds = ["CONSOLE", "FILE", "PIPE"], need = ["WRITE"] }]', 'handles = [{ reg = 0, kinds = ["CONSOLE", "FILE", "PIPE"], need = ["READ"] }]',
     "ABI BREAK: SYS_WRITE rights", True),
    ("error value changed", TOML, 'name = "ERROR_INVALID_HANDLE"\ntype = "i64"\nvalue = -9', 'name = "ERROR_INVALID_HANDLE"\ntype = "i64"\nvalue = -6', "ABI BREAK: ERROR_INVALID_HANDLE value: lock '-9', now '-6'", True),
    ("entry removed", TOML, '[[const]]\ngroup = "seek"\nname = "SEEK_END"\ntype = "u64"\nvalue = 2\nkernel = "crate::user::syscalls::SEEK_END"\nlib = true\nmeaning = "seek whence"\nsince = "1.0"\nstatus = "stable"\n', '',
     "ABI BREAK: SEEK_END removed", True),
    ("added without a new minor", TOML, '[[const]]\ngroup = "seek"', '[[const]]\ngroup = "seek"\nname = "SEEK_DATA"\ntype = "u64"\nvalue = 3\nkernel = ""\nlib = false\nmeaning = "x"\nsince = "1.0"\nstatus = "stable"\n\n[[const]]\ngroup = "seek"',
     "ABI ADD WITHOUT VERSION: SEEK_DATA", True),
    ("added as 1.1 without its lock", TOML, 'version = "1.0"', 'version = "1.1"\n\n[[const]]\ngroup = "seek"\nname = "SEEK_DATA"\ntype = "u64"\nvalue = 3\nkernel = ""\nlib = false\nmeaning = "x"\nsince = "1.1"\nstatus = "stable"',
     "ABI 1.1 has no lock yet", True),
    ("a hole in the numbers", TOML, 'number = 21\nname = "SYS_RESERVED_21"', 'number = 99\nname = "SYS_RESERVED_21"', "numbers without an entry: [21", False),
    ("an entry without a test", TOML, 'test = "abiprobe (gate) + FILE TEST"', 'test = ""', "no test named", False),
    ("lock line edited", "abi/abi-1.0.lock", "ERROR_INVALID_HANDLE type=i64 value=-9", "ERROR_INVALID_HANDLE type=i64 value=-7", "damaged", False),
    ("lock line removed", "abi/abi-1.0.lock", None, None, "damaged (TOTAL", False),
    ("generated file edited by hand", LIB, "pub const SYS_READ: u64 = 2;", "pub const SYS_READ: u64 = 3;", "differs from abi/abi.toml", False),
    ("library constant differs", DESO, "pub const ERROR_INVALID_HANDLE: i64 = -9;", "pub const ERROR_INVALID_HANDLE: i64 = -7;", "ERROR_INVALID_HANDLE = i64 -7, abi.toml says i64 -9", False),
    ("library constant not described", DESO, "pub const SEEK_SET: u64 = 0;", "pub const SEEK_SET: u64 = 0;\npub const SEEK_HOLE: u64 = 4;", "SEEK_HOLE is not in abi.toml", False),
    ("kernel renumbered", SYSCALLS_RS, "pub const SYS_READ: u64 = 2;", "pub const SYS_READ: u64 = 21;", "SYS_READ = 21, abi.toml says 2", False),
    ("kernel reads another argument", SYSCALLS_RS, "SYS_CLOSE => sys_close(p, a0),", "SYS_CLOSE => sys_close(p, a0 | a1),", "SYS_CLOSE: the kernel reads 2 argument register(s)", False),
]


def mutation_test(root, out):
    caught = 0
    for i, (desc, rel, old, new, want, regen) in enumerate(MUTATIONS, 1):
        tmp = copy_tree(root)
        try:
            p = os.path.join(tmp, rel)
            if old is None:
                with open(p, encoding="utf-8") as f:
                    lines = f.read().split("\n")
                k = next(n for n, l in enumerate(lines) if l.startswith("SYS_WRITE "))
                del lines[k]
                with open(p, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))
            elif isinstance(old, list):
                for o, n in old:
                    sub(p, o, n)
            else:
                sub(p, old, new)
            msgs = []
            try:
                m = load(tmp)
                if regen:
                    write_generated(tmp, m)
                for fn in (check_locks, check_generated, check_kernel_src, check_deso):
                    try:
                        fn(tmp, m)
                    except Fail as e:
                        msgs.append(str(e))
            except Fail as e:
                msgs.append(str(e))
            text = "\n".join(msgs)
            if want in text:
                caught += 1
                first = next(l for l in text.splitlines() if want in l)
                out("[ABI HOST TEST] mutation %d/%d %s: caught (%s)" % (i, len(MUTATIONS), desc, first.strip()))
            else:
                out("[ABI HOST TEST] mutation %d/%d %s: NOT CAUGHT - expected %r, got: %s" % (i, len(MUTATIONS), desc, want, text.replace("\n", " / ") or "no failure"))
        finally:
            shutil.rmtree(tmp)
    ok = caught == len(MUTATIONS)
    out("[ABI HOST TEST] 5/5 mutations: %d/%d caught %s" % (caught, len(MUTATIONS), "PASS" if ok else "FAIL"))
    return ok


def write_generated(root, m):
    for path, text in generated(m).items():
        p = os.path.join(root, path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.exists(p) and open(p, encoding="utf-8").read() == text:
            continue
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)


def main():
    args = sys.argv[1:]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if "--root" in args:
        k = args.index("--root")
        root = os.path.abspath(args[k + 1])
        del args[k:k + 2]
    mode = args[0] if args else "--generate"
    try:
        if mode == "--generate":
            m = load(root)
            write_generated(root, m)
            print("abigen: ABI %d.%d - %s, %s, %s" % (m["version"] + (DOC, LIB, KERN)))
        elif mode == "--check":
            sys.exit(0 if run_checks(root, print) else 1)
        elif mode == "--test":
            ok = run_checks(root, print)
            ok = mutation_test(root, print) and ok
            print("[ABI HOST TEST] %s" % ("PASS" if ok else "FAIL"))
            sys.exit(0 if ok else 1)
        elif mode == "--new-lock":
            m = load(root)
            path = os.path.join(root, "abi", "abi-%d.%d.lock" % m["version"])
            if os.path.exists(path):
                raise Fail("%s exists - a lock is never rewritten (a change to the ABI is a new minor or major)" % os.path.relpath(path, root))
            older = [x for x in lock_files(root) if x[0] < m["version"]]
            if older:
                # every older lock must still pass before a new one is written
                for v, p in older:
                    old = read_lock(p)
                    now = lock_entries(m, v)
                    bad = [n for n in old if now.get(n) != old[n]] + [n for n in now if n not in old]
                    if bad:
                        raise Fail("lock %d.%d does not pass (%s) - a new lock never approves a break" % (v + (", ".join(bad[:5]),)))
            with open(path, "x", encoding="utf-8") as f:
                f.write(lock_text(m, m["version"]))
            print("abigen: wrote %s" % os.path.relpath(path, root))
        else:
            print(__doc__ if __doc__ else "see the comment at the top of tools/abigen.py")
            sys.exit(2)
    except Fail as e:
        print("abigen: FAIL\n" + str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
