#!/usr/bin/env python3
"""The test repositories of PKG TEST (tests/pkg-test.sh) – one directory per scenario, served
by tests/repo-stub.py:

  make-repo.py OUT WITAJ_DIR [--big MIB]

WITAJ_DIR holds witaj-<version> (the SDK-built test program, tests/pkg/witaj/main.rs) for
1.0.0, 1.0.1, 1.1.0, 1.1.1, 1.1.3, 1.1.4.  Every scenario is OUT/<name>/deso/stable/x86_64/
{index, index.sig, packages/<name>-<version>.pkg}, signed with the test key
(tests/pkg/test-key.pem – "deso-test-1", the key of the self-test image's /etc/desopkg/keys).
Times are relative to now (the guest's clock is the host's RTC).

  serial  scenario   what
  10      v100       witaj 1.0.0 (needs fonts>=1.0.0), fonts 1.0.0
  11      v101       + witaj 1.0.1, 1.1.0 (needs fonts>=1.1.0), fonts 1.1.0, edytor 1.0.0
                     (needs witaj>=1.1.0), oldwitaj 1.0.0 (conflicts with witaj), ls 1.0.0 (a
                     system name – desopkg must refuse it before making a directory)
  20      tx         + witaj 1.1.1 (good), 1.1.2 (index SHA-256 of other bytes), 1.1.3 (index
                     size one byte more), 1.1.4 (one byte less); repo-stub's transfer modes
                     long / short / badlen / redirect act on witaj-1.1.1.pkg
  5       old        v100 with an older serial
  30      expired, future, badsig, otherkey, testing  – refused indexes
  40      big        tx + big 1.0.0 (MIB MiB of data, default 30)
"""
import hashlib
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import desopkg as d  # noqa: E402

KEY = os.path.join(HERE, "test-key.pem")
OTHER = os.path.join(HERE, "other-key.pem")
KEYID = "deso-test-1"
DAY = 86400


def pkg(name, version, summary, files, depends=(), conflicts=()):
    """A package without the tool's own checks (a system name like `ls` must be possible)."""
    m = d.make_manifest(name, version, summary, files, depends, conflicts)
    return d.make_pkg(m, b"".join(b for _, b, _ in files))


def entry(p, summary, **over):
    """The index entry of package bytes `p` (fields from its manifest, `over` replaces)."""
    h_end = p.index(b"\n") + 1
    mlen = int(p[:h_end].split()[2])
    m = p[h_end : h_end + mlen].decode()
    f = {}
    deps, confs = [], []
    for line in m.split("\n"):
        k, _, v = line.partition("=")
        if k == "depends":
            deps.append(v)
        elif k == "conflicts":
            confs.append(v)
        elif k in ("name", "version", "abi"):
            f[k] = v
    e = dict(name=f["name"], version=f["version"], abi=f["abi"], size=len(p), digest=hashlib.sha256(p).digest(), depends=deps, conflicts=confs, summary=summary)
    e.update(over)
    return d.index_entry_text(e["name"], e["version"], e["abi"], e["size"], e["digest"], e["depends"], e["conflicts"], e["summary"])


def write(out, scen, packages, entries, serial, issued, expires, channel="stable", sign_key=KEY, tamper=False):
    base = os.path.join(out, scen, "deso", "stable", "x86_64")
    os.makedirs(os.path.join(base, "packages"), exist_ok=True)
    for fname, b in packages.items():
        with open(os.path.join(base, "packages", fname), "wb") as f:
            f.write(b)
    idx = d.make_index(serial, d.fmt_date(issued), d.fmt_date(expires), entries, channel=channel)
    d.parse_index(idx)
    sig = d.sign_index(idx, sign_key, KEYID)
    if tamper:
        # Signed, then one byte of a summary changed: still a valid index, a wrong signature.
        i = idx.index(b"summary=") + 8
        idx = idx[:i] + bytes([idx[i] ^ 0x20]) + idx[i + 1 :]
        d.parse_index(idx)
    with open(os.path.join(base, "index"), "wb") as f:
        f.write(idx)
    with open(os.path.join(base, "index.sig"), "wb") as f:
        f.write(sig)


def main():
    args = sys.argv[1:]
    big_mib = 30
    if "--big" in args:
        i = args.index("--big")
        big_mib = int(args[i + 1])
        del args[i : i + 2]
    if len(args) != 2:
        sys.exit(__doc__)
    out, wdir = args
    now = int(time.time())
    iss, exp = now - 3600, now + 29 * DAY

    def witaj(ver):
        prog = open(os.path.join(wdir, "witaj-" + ver), "rb").read()
        hello = ("Witaj w DeSo OS - wersja %s\n" % ver).encode()
        deps = ["fonts>=1.1.0"] if ver >= "1.1.0" else ["fonts>=1.0.0"]
        return pkg("witaj", ver, "A greeting for DeSo OS", [("bin/witaj", prog, "program"), ("share/witaj/hello.txt", hello, "data")], deps)

    def data_pkg(name, ver, summary, depends=(), conflicts=()):
        return pkg(name, ver, summary, [("share/%s/readme.txt" % name, ("%s %s\n" % (name, ver)).encode(), "data")], depends, conflicts)

    P = {}
    E = {}

    def add(name, ver, p, summary, **over):
        P["%s-%s.pkg" % (name, ver)] = p
        E["%s-%s" % (name, ver)] = entry(p, summary, **over)

    add("witaj", "1.0.0", witaj("1.0.0"), "A greeting for DeSo OS")
    add("fonts", "1.0.0", data_pkg("fonts", "1.0.0", "Fonts for DeSo OS"), "Fonts for DeSo OS")
    v100 = ["witaj-1.0.0", "fonts-1.0.0"]
    write(out, "v100", {k + ".pkg": P[k + ".pkg"] for k in v100}, [E[k] for k in v100], 10, iss, exp)
    write(out, "old", {k + ".pkg": P[k + ".pkg"] for k in v100}, [E[k] for k in v100], 5, iss, exp)

    add("witaj", "1.0.1", witaj("1.0.1"), "A greeting for DeSo OS")
    add("witaj", "1.1.0", witaj("1.1.0"), "A greeting for DeSo OS")
    add("fonts", "1.1.0", data_pkg("fonts", "1.1.0", "Fonts for DeSo OS"), "Fonts for DeSo OS")
    add("edytor", "1.0.0", data_pkg("edytor", "1.0.0", "An editor for DeSo OS", depends=["witaj>=1.1.0"]), "An editor for DeSo OS")
    add("oldwitaj", "1.0.0", data_pkg("oldwitaj", "1.0.0", "The old greeting", conflicts=["witaj"]), "The old greeting")
    add("ls", "1.0.0", data_pkg("ls", "1.0.0", "A package with a system name"), "A package with a system name")
    v101 = v100 + ["witaj-1.0.1", "witaj-1.1.0", "fonts-1.1.0", "edytor-1.0.0", "oldwitaj-1.0.0", "ls-1.0.0"]
    write(out, "v101", {k + ".pkg": P[k + ".pkg"] for k in v101}, [E[k] for k in v101], 11, iss, exp)

    add("witaj", "1.1.1", witaj("1.1.1"), "A greeting for DeSo OS")
    w112 = witaj("1.1.1").replace(b"version=1.1.1", b"version=1.1.2")  # a valid package of 1.1.2...
    other = witaj("1.1.3")
    add("witaj", "1.1.2", w112, "A greeting for DeSo OS", digest=hashlib.sha256(other).digest(), size=len(w112))  # ...pinned to other bytes
    w113 = witaj("1.1.3")
    add("witaj", "1.1.3", w113, "A greeting for DeSo OS", size=len(w113) + 1)
    w114 = witaj("1.1.4")
    add("witaj", "1.1.4", w114, "A greeting for DeSo OS", size=len(w114) - 1)
    tx = v101 + ["witaj-1.1.1", "witaj-1.1.2", "witaj-1.1.3", "witaj-1.1.4"]
    write(out, "tx", {k + ".pkg": P[k + ".pkg"] for k in tx}, [E[k] for k in tx], 20, iss, exp)

    refused = {k + ".pkg": P[k + ".pkg"] for k in v100}
    rentries = [E[k] for k in v100]
    write(out, "expired", refused, rentries, 30, now - 40 * DAY, now - 10 * DAY)
    write(out, "future", refused, rentries, 30, now + 2 * DAY, now + 20 * DAY)
    write(out, "badsig", refused, rentries, 30, iss, exp, tamper=True)
    write(out, "otherkey", refused, rentries, 30, iss, exp, sign_key=OTHER)
    write(out, "testing", refused, rentries, 30, iss, exp, channel="testing")

    rnd = random.Random(82)
    blob = bytes(rnd.getrandbits(8) for _ in range(1024 * 1024)) * big_mib
    add("big", "1.0.0", pkg("big", "1.0.0", "A big package", [("share/big/data.bin", blob, "data")]), "A big package")
    write(out, "big", {k + ".pkg": P[k + ".pkg"] for k in tx + ["big-1.0.0"]}, [E[k] for k in tx + ["big-1.0.0"]], 40, iss, exp)
    print("%s: scenarios v100 v101 tx old expired future badsig otherkey testing big (%d MiB)" % (out, big_mib))


if __name__ == "__main__":
    main()
