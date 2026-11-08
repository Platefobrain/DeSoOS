#!/usr/bin/env python3
# Builds `roots` – the trusted CA store of DeSoOS (/etc/certs/roots at boot) – from Mozilla's
# root store (NSS certdata.txt).
#
#   gen-roots.py <certdata.txt> <out>
#
# certdata.txt comes from NSS, tag NSS_TAG below:
#   https://raw.githubusercontent.com/nss-dev/nss/<NSS_TAG>/lib/ckfw/builtins/certdata.txt
# and is checked against CERTDATA_SHA256, so the same input always gives the same file.
# Updating the store = a new tag + its SHA-256 here, run the script, rebuild – no code change.
#
# Taken: only the certificates whose trust object says CKA_TRUST_SERVER_AUTH =
# CKT_NSS_TRUSTED_DELEGATOR (trusted to issue server certificates), with their
# CKA_NSS_SERVER_DISTRUST_AFTER date when there is one (server certificates issued after
# it are not trusted).  Everything else (e-mail only, distrusted, code signing) is left out.
#
# Format (numbers big-endian):
#   "DSCR" u16 version (1) u16 number of anchors
#   u8 len + NSS tag (ASCII), 32 bytes SHA-256 of certdata.txt
#   per anchor: i64 distrust-after (Unix seconds, 0 = none), u16 len + certificate (DER)
import calendar, hashlib, re, struct, sys

NSS_TAG = "NSS_3_133_RTM"
CERTDATA_SHA256 = "3ec2b4d240dc12c747eaf450061db84af757c483bbda302f9e29ceb5d70be510"


def octal(lines):
    out = bytearray()
    for l in lines:
        for o in re.findall(r"\\([0-7]{3})", l):
            out.append(int(o, 8))
    return bytes(out)


def objects(text):
    """certdata.txt -> list of dicts {attribute: value}; MULTILINE_OCTAL values as bytes."""
    objs, cur, lines = [], None, text.splitlines()
    i = 0
    while i < len(lines):
        l = lines[i]
        if l.startswith("#") or not l.strip():
            i += 1
            continue
        parts = l.split(None, 2)
        if parts[0] == "CKA_CLASS":
            cur = {}
            objs.append(cur)
        if cur is None:
            i += 1
            continue
        if len(parts) >= 2 and parts[1] == "MULTILINE_OCTAL":
            j = i + 1
            while lines[j] != "END":
                j += 1
            cur[parts[0]] = octal(lines[i + 1:j])
            i = j + 1
            continue
        cur[parts[0]] = parts[2] if len(parts) > 2 else parts[1]
        i += 1
    return objs


def utc_time(b):
    s = b.decode()
    if not re.fullmatch(r"\d{12}Z", s):
        sys.exit(f"unexpected distrust-after date {s!r}")
    y = int(s[:2])
    y += 2000 if y < 50 else 1900
    return calendar.timegm((y, int(s[2:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12])))


def main():
    raw = open(sys.argv[1], "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    if got != CERTDATA_SHA256:
        sys.exit(f"certdata.txt: SHA-256 {got}, expected {CERTDATA_SHA256} ({NSS_TAG})")
    objs = objects(raw.decode("utf-8"))
    certs = {}
    for o in objs:
        if o.get("CKA_CLASS") == "CKO_CERTIFICATE":
            certs[(o["CKA_ISSUER"], o["CKA_SERIAL_NUMBER"])] = o
    anchors = []
    for o in objs:
        if o.get("CKA_CLASS") != "CKO_NSS_TRUST":
            continue
        if o.get("CKA_TRUST_SERVER_AUTH") != "CKT_NSS_TRUSTED_DELEGATOR":
            continue
        c = certs[(o["CKA_ISSUER"], o["CKA_SERIAL_NUMBER"])]
        da = c.get("CKA_NSS_SERVER_DISTRUST_AFTER")
        when = utc_time(da) if isinstance(da, bytes) else 0
        anchors.append((c["CKA_LABEL"].strip('"'), when, c["CKA_VALUE"]))
    anchors.sort(key=lambda a: a[0])
    out = b"DSCR" + struct.pack(">HH", 1, len(anchors))
    out += struct.pack(">B", len(NSS_TAG)) + NSS_TAG.encode() + bytes.fromhex(CERTDATA_SHA256)
    for _, when, der in anchors:
        out += struct.pack(">qH", when, len(der)) + der
    open(sys.argv[2], "wb").write(out)
    distrusted = sum(1 for a in anchors if a[1])
    print(f"{sys.argv[2]}: {len(anchors)} anchors ({distrusted} with a distrust-after date), {len(out)} bytes, "
          f"SHA-256 {hashlib.sha256(out).hexdigest()} ({NSS_TAG})")


main()
