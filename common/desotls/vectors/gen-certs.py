#!/usr/bin/env python3
# Builds certs.bin – the certificate-chain cases the DeSoTLS tests (tests.rs) run in the
# kernel CERT TEST and in /bin/certtest.  Each case is a chain, trust anchors, a host, a time
# and the expected answer (an Error name from mod.rs, or OK).
#
#   gen-certs.py <out.bin>
#
# The certificates are made with Python `cryptography`; the ones the library cannot make
# (duplicate extensions, written-out defaults, odd PSS parameters, v1 / v2, keys off the
# curve, …) are built by editing the DER of a normal certificate and signing it again with
# the right key – so every bad case differs from a good one in exactly the point it tests.
# Keys are random: a new run gives other bytes, the same cases and answers.
#
# Format (big-endian):  "DSCC" u16 version (1) u16 cases
#   per case: u8 len + name, u8 len + expected (Error name or "OK"), u8 len + host,
#             i64 now, u8 anchors, each (i64 distrust-after, u16 len + DER),
#             u8 certificates (server certificate first), each u16 len + DER
import datetime, struct, sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

NOW = int(datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc).timestamp())
T0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
T1 = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)
DAY = datetime.timedelta(days=1)

# ---- a tiny DER tree: (tag, bytes) for primitives, (tag, [children]) for constructed ----

def dlen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def enc(node):
    tag, v = node
    if isinstance(v, list):
        v = b"".join(enc(c) for c in v)
    return bytes([tag]) + dlen(len(v)) + v

def dec(b):
    """One element -> (node, rest)."""
    tag = b[0]
    l = b[1]
    p = 2
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(b[2:2 + n], "big")
        p = 2 + n
    v = b[p:p + l]
    if tag & 0x20:
        kids, r = [], v
        while r:
            k, r = dec(r)
            kids.append(k)
        return (tag, kids), b[p + l:]
    return (tag, v), b[p + l:]

def tree(der):
    return dec(der)[0]

def oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for a in parts[2:]:
        s = [a & 0x7f]
        a >>= 7
        while a:
            s.append(0x80 | (a & 0x7f))
            a >>= 7
        out += bytes(reversed(s))
    return (0x06, out)

SEQ, SET, INT, BOOL, OCT, BIT, NULL = 0x30, 0x31, 0x02, 0x01, 0x04, 0x03, 0x05

def integer(n):
    return (INT, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))

# ---- keys and signing ----

class Key:
    def __init__(self, kind):
        self.kind = kind
        if kind == "p256":
            self.k = ec.generate_private_key(ec.SECP256R1())
        elif kind == "p384":
            self.k = ec.generate_private_key(ec.SECP384R1())
        elif kind.startswith("rsa"):
            self.k = rsa.generate_private_key(65537, int(kind[3:]))
        self.pub = self.k.public_key()

    def default_hash(self):
        return hashes.SHA384() if self.kind == "p384" else hashes.SHA256()

    def sign_raw(self, data, alg):
        """alg: ('ecdsa', hash) | ('pkcs1', hash) | ('pss', hash, salt)."""
        if alg[0] == "ecdsa":
            return self.k.sign(data, ec.ECDSA(alg[1]))
        if alg[0] == "pkcs1":
            return self.k.sign(data, padding.PKCS1v15(), alg[1])
        return self.k.sign(data, padding.PSS(padding.MGF1(alg[1]), alg[2]), alg[1])

def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DeSoOS test")])

def build(subject, issuer, key, issuer_key, *, ca=False, path_len=None, san=None, ku=None, eku=None, nc=None,
          extra=(), nb=T0, na=T1, bc=True, bc_critical=True, alg=None, serial=None):
    b = x509.CertificateBuilder().subject_name(subject if isinstance(subject, x509.Name) else name(subject))
    b = b.issuer_name(issuer if isinstance(issuer, x509.Name) else name(issuer))
    b = b.public_key(key.pub).serial_number(serial or x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
    if bc:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=bc_critical)
    if ku is not None:
        b = b.add_extension(ku, critical=True)
    elif ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if san is not None:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    if nc is not None:
        b = b.add_extension(nc[0], critical=nc[1])
    for ext, crit in extra:
        b = b.add_extension(ext, critical=crit)
    if alg is None or alg[0] in ("ecdsa", "pkcs1"):
        h = alg[1] if alg else issuer_key.default_hash()
        return b.sign(issuer_key.k, h).public_bytes(serialization_der())
    # PSS through cryptography's rsa_padding
    return b.sign(issuer_key.k, alg[1], rsa_padding=padding.PSS(padding.MGF1(alg[1]), alg[2])).public_bytes(serialization_der())

def serialization_der():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER

# ---- editing a certificate and signing it again ----

def parts(der):
    t = tree(der)
    return t[1][0], t[1][1]          # tbs node, algorithm node

def resign(tbs, alg_node, issuer_key, alg):
    tbs_der = enc(tbs)
    sig = issuer_key.sign_raw(tbs_der, alg)
    return enc((SEQ, [tbs, alg_node, (BIT, b"\x00" + sig)]))

def alg_of(der):
    return parts(der)[1]

def edit(der, issuer_key, f, alg=None, alg_node=None):
    """f(tbs_children) edits the list in place; signs again with the same algorithm."""
    tbs, a = parts(der)
    kids = list(tbs[1])
    f(kids)
    a = alg_node or a
    if alg_node is not None:
        # the inner algorithm identifier follows the outer one
        idx = 1 if kids[0][0] == 0xa0 else 0
        kids[idx + 1] = alg_node
    return resign((SEQ, kids), a, issuer_key, alg or ("ecdsa", issuer_key.default_hash()) if issuer_key.kind.startswith("p") else alg or ("pkcs1", hashes.SHA256()))

def ext_list(kids):
    """The list of Extension nodes inside [3] of the tbs children."""
    for k in kids:
        if k[0] == 0xa3:
            return k[1][0][1]
    raise ValueError("no extensions")

def ext_node(oid_dotted, value_node, critical=None):
    kids = [oid(oid_dotted)]
    if critical is not None:
        kids.append((BOOL, b"\xff" if critical else b"\x00"))
    kids.append((OCT, enc(value_node) if isinstance(value_node, tuple) else value_node))
    return (SEQ, kids)

# ---- the cases ----

cases = []

def case(nm, expected, host, chain, anchors, now=NOW):
    cases.append((nm, expected, host, now, [(a, 0) if isinstance(a, bytes) else a for a in anchors], chain))

def main():
    R = Key("rsa2048")          # root
    I = Key("p256")             # intermediate
    L = Key("p256")             # server
    root = build("Test Root", "Test Root", R, R, ca=True)
    inter = build("Test ICA", "Test Root", I, R, ca=True)
    leaf = build("www.example.com", "Test ICA", L, I, san=["www.example.com", "example.com"])
    ok = [leaf, inter]
    case("basic chain", "OK", "www.example.com", ok, [root])
    case("intermediates in another order", "OK", "example.com", [leaf, root, inter], [root])
    case("leaf directly under the root", "OK", "a.example.com", [build("a", "Test Root", L, R, san=["a.example.com"])], [root])
    case("host in upper case", "OK", "WWW.Example.COM", ok, [root])
    case("unknown CA", "UnknownIssuer", "www.example.com", ok, [build("Other Root", "Other Root", R, R, ca=True)])
    case("no anchors", "UnknownIssuer", "www.example.com", ok, [])
    case("intermediate missing", "UnknownIssuer", "www.example.com", [leaf], [root])
    case("empty chain", "Empty", "www.example.com", [], [root])

    # algorithms
    R384 = Key("p384")
    root384 = build("Root 384", "Root 384", R384, R384, ca=True)
    Ipss = Key("rsa2048")
    ipss = build("ICA PSS", "Root 384", Ipss, R384, ca=True)
    lpss = build("pss", "ICA PSS", L, Ipss, san=["pss.example.com"], alg=("pss", hashes.SHA256(), 32))
    case("P-384/SHA-384 root, RSA-PSS SHA-256 salt 32", "OK", "pss.example.com", [lpss, ipss], [root384])
    lpss512 = build("pss", "ICA PSS", L, Ipss, san=["pss.example.com"], alg=("pss", hashes.SHA512(), 64))
    case("RSA-PSS SHA-512 salt 64", "OK", "pss.example.com", [lpss512, ipss], [root384])
    l512 = build("p1", "ICA PSS", L, Ipss, san=["p1.example.com"], alg=("pkcs1", hashes.SHA512()))
    case("RSA PKCS#1 SHA-512", "OK", "p1.example.com", [l512, ipss], [root384])
    l384 = build("p1", "ICA PSS", L, Ipss, san=["p1.example.com"], alg=("pkcs1", hashes.SHA384()))
    case("RSA PKCS#1 SHA-384", "OK", "p1.example.com", [l384, ipss], [root384])
    i384 = build("ICA 384", "Root 384", I, R384, ca=True, alg=("ecdsa", hashes.SHA256()))
    case("ECDSA P-384 key with SHA-256", "BadSignature", "www.example.com",
         [build("www", "ICA 384", L, I, san=["www.example.com"]), i384], [root384])
    sha1 = edit(build("sha1", "Test ICA", L, I, san=["sha1.example.com"]), I, lambda k: None, ("ecdsa", hashes.SHA1()),
                (SEQ, [oid("1.2.840.10045.4.1")]))
    case("ECDSA with SHA-1", "UnsupportedSignatureAlgorithm", "sha1.example.com", [sha1, inter], [root])
    i_rsa = Key("rsa2048")
    ica_rsa = build("ICA RSA", "Test Root", i_rsa, R, ca=True)
    lsha1 = edit(build("sha1", "ICA RSA", L, i_rsa, san=["sha1.example.com"]), i_rsa, lambda k: None, ("pkcs1", hashes.SHA1()),
                 (SEQ, [oid("1.2.840.113549.1.1.5"), (NULL, b"")]))
    case("RSA with SHA-1", "UnsupportedSignatureAlgorithm", "sha1.example.com", [lsha1, ica_rsa], [root])
    p521 = Key.__new__(Key); p521.kind = "p521"; p521.k = ec.generate_private_key(ec.SECP521R1()); p521.pub = p521.k.public_key()
    l521 = build("p521", "Test ICA", p521, I, san=["p521.example.com"])
    case("P-521 server key", "UnsupportedKey", "p521.example.com", [l521, inter], [root])
    weak = Key("rsa1024")
    lweak = build("weak", "ICA RSA", weak, i_rsa, san=["weak.example.com"])
    case("RSA-1024 server key", "BadKey", "weak.example.com", [lweak, ica_rsa], [root])
    iweak = build("ICA weak", "Test Root", weak, R, ca=True)
    case("RSA-1024 intermediate key", "BadKey", "w.example.com", [build("w", "ICA weak", L, weak, san=["w.example.com"]), iweak], [root])

    # signatures
    bad = bytearray(leaf)
    bad[-5] ^= 1
    case("server signature changed", "BadSignature", "www.example.com", [bytes(bad), inter], [root])
    badi = bytearray(inter)
    badi[-5] ^= 1
    case("intermediate signature changed", "BadSignature", "www.example.com", [leaf, bytes(badi)], [root])
    other_i = build("Test ICA", "Test Root", Key("p256"), R, ca=True)
    case("intermediate with the right name, other key", "BadSignature", "www.example.com", [leaf, other_i], [root])
    case("right and wrong intermediate presented", "OK", "www.example.com", [leaf, other_i, inter], [root])

    # validity
    case("server expired", "Expired", "www.example.com", ok, [root], now=int(T1.timestamp()) + 1)
    case("server not yet valid", "NotYetValid", "www.example.com", ok, [root], now=int(T0.timestamp()) - 1)
    case("first second", "OK", "www.example.com", ok, [root], now=int(T0.timestamp()))
    case("last second", "OK", "www.example.com", ok, [root], now=int(T1.timestamp()))
    old_i = build("Test ICA", "Test Root", I, R, ca=True, na=T0 + 100 * DAY)
    case("intermediate expired", "Expired", "www.example.com", [leaf, old_i], [root])
    old_root = build("Test Root", "Test Root", R, R, ca=True, na=T0 + 100 * DAY)
    case("anchor expired", "Expired", "www.example.com", ok, [old_root])
    utc2050 = build("www", "Test ICA", L, I, san=["www.example.com"], na=datetime.datetime(2051, 1, 1, tzinfo=datetime.timezone.utc))
    case("notAfter in GeneralizedTime (2051)", "OK", "www.example.com", [utc2050, inter], [root])

    # names
    wild = build("wild", "Test ICA", L, I, san=["*.example.com"])
    case("wildcard one label", "OK", "abc.example.com", [wild, inter], [root])
    case("wildcard two labels", "NameMismatch", "a.b.example.com", [wild, inter], [root])
    case("wildcard and the bare domain", "NameMismatch", "example.com", [wild, inter], [root])
    case("wildcard over a public suffix", "NameMismatch", "example.com", [build("w", "Test ICA", L, I, san=["*.com"]), inter], [root])
    case("partial wildcard", "NameMismatch", "foo.example.com", [build("w", "Test ICA", L, I, san=["f*.example.com"]), inter], [root])
    case("wrong host", "NameMismatch", "www.example.org", ok, [root])
    nosan = build("www.example.com", "Test ICA", L, I)
    case("only a commonName", "NoSubjectAltName", "www.example.com", [nosan, inter], [root])
    case("IP address host", "IpHostUnsupported", "192.0.2.1", ok, [root])
    case("IPv6 host", "IpHostUnsupported", "::1", ok, [root])
    case("invalid host", "InvalidHost", "exa mple.com", ok, [root])
    case("host with a trailing dot", "InvalidHost", "www.example.com.", ok, [root])
    idn = build("idn", "Test ICA", L, I, san=["xn--bcher-kva.example"])
    case("IDN in A-label form", "OK", "xn--bcher-kva.example", [idn, inter], [root])

    # basic constraints and path length
    case("server certificate is a CA", "CaAsLeaf", "ca.example.com", [build("ca", "Test ICA", L, I, ca=True, san=["ca.example.com"]), inter], [root])
    nobc = build("Test ICA", "Test Root", I, R, bc=False, ku=x509.KeyUsage(True, False, False, False, False, False, False, False, False))
    case("intermediate without basicConstraints", "BasicConstraintsNotCritical", "www.example.com", [leaf, nobc], [root])
    noncrit = build("Test ICA", "Test Root", I, R, ca=True, bc_critical=False)
    case("intermediate basicConstraints not critical", "BasicConstraintsNotCritical", "www.example.com", [leaf, noncrit], [root])
    notca = build("Test ICA", "Test Root", I, R, ca=False, ku=x509.KeyUsage(True, False, False, False, False, False, False, False, False))
    case("intermediate with cA FALSE", "NotCa", "www.example.com", [leaf, notca], [root])
    root_nc_bc = build("Test Root", "Test Root", R, R, ca=True, bc_critical=False)
    case("anchor basicConstraints not critical (allowed)", "OK", "www.example.com", ok, [root_nc_bc])
    root_pl0 = build("Test Root", "Test Root", R, R, ca=True, path_len=0)
    case("anchor pathLen 0, one intermediate", "PathLenExceeded", "www.example.com", ok, [root_pl0])
    case("anchor pathLen 0, no intermediate", "OK", "a.example.com", [build("a", "Test Root", L, R, san=["a.example.com"])], [root_pl0])
    I2 = Key("p256")
    inter_pl0 = build("Test ICA", "Test Root", I, R, ca=True, path_len=0)
    inter2 = build("ICA 2", "Test ICA", I2, I, ca=True)
    leaf2 = build("www", "ICA 2", L, I2, san=["www.example.com"])
    case("intermediate pathLen 0, one more below", "PathLenExceeded", "www.example.com", [leaf2, inter2, inter_pl0], [root])
    case("intermediate pathLen 1, one more below", "OK", "www.example.com", [leaf2, inter2, build("Test ICA", "Test Root", I, R, ca=True, path_len=1)], [root])
    # self-issued (key rollover): same name as the root, another key, signed by the root
    Rn = Key("p256")
    selfi = build("Test Root", "Test Root", Rn, R, ca=True)
    lself = build("s", "Test Root", L, Rn, san=["s.example.com"])
    case("pathLen 0 and a self-issued intermediate", "OK", "s.example.com", [lself, selfi], [root_pl0])
    nonself = build("Rollover", "Test Root", Rn, R, ca=True)
    case("pathLen 0 and the same intermediate not self-issued", "PathLenExceeded", "s.example.com",
         [build("s", "Rollover", L, Rn, san=["s.example.com"]), nonself], [root_pl0])

    # key usage and extended key usage
    case("server keyUsage without digitalSignature", "KeyUsage", "k.example.com",
         [build("k", "Test ICA", L, I, san=["k.example.com"], ku=x509.KeyUsage(False, False, True, False, True, False, False, False, False)), inter], [root])
    case("intermediate keyUsage without keyCertSign", "KeyUsage", "www.example.com",
         [leaf, build("Test ICA", "Test Root", I, R, ca=True, ku=x509.KeyUsage(True, False, False, False, False, False, True, False, False))], [root])
    case("server keyUsage with keyCertSign", "BadExtension", "k.example.com",
         [build("k", "Test ICA", L, I, san=["k.example.com"], ku=x509.KeyUsage(True, False, False, False, False, True, False, False, False)), inter], [root])
    case("server extKeyUsage clientAuth only", "ExtKeyUsage", "e.example.com",
         [build("e", "Test ICA", L, I, san=["e.example.com"], eku=[ExtendedKeyUsageOID.CLIENT_AUTH]), inter], [root])
    case("server extKeyUsage serverAuth", "OK", "e.example.com",
         [build("e", "Test ICA", L, I, san=["e.example.com"], eku=[ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), inter], [root])
    case("intermediate extKeyUsage clientAuth only", "ExtKeyUsage", "www.example.com",
         [leaf, build("Test ICA", "Test Root", I, R, ca=True, eku=[ExtendedKeyUsageOID.CLIENT_AUTH])], [root])
    case("intermediate extKeyUsage anyExtendedKeyUsage", "OK", "www.example.com",
         [leaf, build("Test ICA", "Test Root", I, R, ca=True, eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])], [root])

    # name constraints
    def ncx(permitted=None, excluded=None, crit=True):
        p = [x509.DNSName(n) for n in permitted] if permitted is not None else None
        e = [x509.DNSName(n) for n in excluded] if excluded is not None else None
        return (x509.NameConstraints(permitted_subtrees=p, excluded_subtrees=e), crit)
    inc = build("Test ICA", "Test Root", I, R, ca=True, nc=ncx(permitted=["example.com"]))
    case("permitted subtree, name inside", "OK", "www.example.com", [leaf, inc], [root])
    case("permitted subtree, name outside", "NameConstraintViolation", "www.other.org",
         [build("o", "Test ICA", L, I, san=["www.other.org"]), inc], [root])
    case("permitted subtree, any name outside (not the host)", "NameConstraintViolation", "www.example.com",
         [build("o", "Test ICA", L, I, san=["www.example.com", "evil.org"]), inc], [root])
    inx = build("Test ICA", "Test Root", I, R, ca=True, nc=ncx(excluded=["bad.example.com"]))
    case("excluded subtree, name inside", "NameConstraintViolation", "x.bad.example.com",
         [build("x", "Test ICA", L, I, san=["x.bad.example.com"]), inx], [root])
    case("excluded subtree, name beside", "OK", "notbad.example.com", [build("x", "Test ICA", L, I, san=["notbad.example.com"]), inx], [root])
    inxb = build("Test ICA", "Test Root", I, R, ca=True, nc=ncx(excluded=["bar.example.com"]))
    case("excluded name covered by a wildcard (CVE-2025-61727)", "NameConstraintViolation", "foo.example.com", [wild, inxb], [root])
    inc_nc = build("Test ICA", "Test Root", I, R, ca=True, nc=ncx(permitted=["example.com"], crit=False))
    case("non-critical name constraints are enforced", "NameConstraintViolation", "www.other.org",
         [build("o", "Test ICA", L, I, san=["www.other.org"]), inc_nc], [root])
    root_nc = build("Test Root", "Test Root", R, R, ca=True, nc=ncx(permitted=["example.com"]))
    case("anchor name constraints", "NameConstraintViolation", "www.other.org",
         [build("o", "Test ICA", L, I, san=["www.other.org"]), inter], [root_nc])
    # self-issued intermediate below a constrained root: its own name is not checked, the leaf is
    selfi_san = build("Test Root", "Test Root", Rn, R, ca=True, san=["outside.org"])
    case("self-issued intermediate outside permitted (allowed)", "OK", "s.example.com",
         [build("s", "Test Root", L, Rn, san=["s.example.com"]), selfi_san], [root_nc])
    case("leaf below it outside permitted", "NameConstraintViolation", "s.other.org",
         [build("s", "Test Root", L, Rn, san=["s.other.org"]), selfi_san], [root_nc])
    nonself_san = build("ICA X", "Test Root", Rn, R, ca=True, san=["outside.org"])
    case("intermediate (not self-issued) outside permitted", "NameConstraintViolation", "s.example.com",
         [build("s", "ICA X", L, Rn, san=["s.example.com"]), nonself_san], [root_nc])
    ipnc = build("Test ICA", "Test Root", I, R, ca=True,
                 nc=(x509.NameConstraints(permitted_subtrees=None, excluded_subtrees=[x509.IPAddress(__import__("ipaddress").ip_network("10.0.0.0/8"))]), True))
    case("name constraints with an IP subtree", "UnsupportedNameConstraint", "www.example.com", [leaf, ipnc], [root])

    # edited certificates
    def with_ext(der, ikey, ext, alg=None):
        return edit(der, ikey, lambda k: ext_list(k).append(ext), alg)
    unknown = ext_node("1.3.6.1.4.1.99999.1", (NULL, b""), critical=True)
    case("unknown critical extension", "UnknownCriticalExtension", "www.example.com", [with_ext(leaf, I, unknown), inter], [root])
    unknown_nc = ext_node("1.3.6.1.4.1.99999.1", (NULL, b""))
    case("unknown non-critical extension", "OK", "www.example.com", [with_ext(leaf, I, unknown_nc), inter], [root])
    dup = edit(leaf, I, lambda k: ext_list(k).append(ext_list(k)[-1]))
    case("duplicate extension", "DuplicateExtension", "www.example.com", [dup, inter], [root])
    crit_false = ext_node("1.3.6.1.4.1.99999.1", (NULL, b""), critical=False)
    case("critical FALSE written out", "BadDer", "www.example.com", [with_ext(leaf, I, crit_false), inter], [root])
    def bool_one(k):
        ex = ext_list(k)
        for i, e in enumerate(ex):
            if len(e[1]) == 3 and e[1][1][0] == BOOL:
                ex[i] = (SEQ, [e[1][0], (BOOL, b"\x01"), e[1][2]])
                return
    case("BOOLEAN 0x01 instead of 0xFF", "BadDer", "www.example.com", [edit(leaf, I, bool_one), inter], [root])
    def empty_exts(k):
        for i, x in enumerate(k):
            if x[0] == 0xa3:
                k[i] = (0xa3, [(SEQ, [])])
    case("empty extensions list", "BadExtension", "www.example.com", [edit(leaf, I, empty_exts), inter], [root])
    def ku_nonminimal(k):
        ex = ext_list(k)
        for i, e in enumerate(ex):
            if e[1][0] == oid("2.5.29.15"):
                ex[i] = ext_node("2.5.29.15", (BIT, b"\x00\x80"), critical=True)
    case("keyUsage BIT STRING not minimal", "BadExtension", "www.example.com", [edit(leaf, I, ku_nonminimal), inter], [root])
    def v2(k):
        k[0] = (0xa0, [integer(1)])
    case("version 2", "UnsupportedVersion", "www.example.com", [edit(leaf, I, v2), inter], [root])
    def v1(k):
        del k[0]
        k[:] = [x for x in k if x[0] != 0xa3]
    v1root = edit(root, R, v1)
    case("v1 anchor", "OK", "www.example.com", ok, [v1root])
    v1inter = edit(inter, R, v1)
    case("v1 intermediate", "UnsupportedVersion", "www.example.com", [leaf, v1inter], [root])
    def unique_id(k):
        idx = [i for i, x in enumerate(k) if x[0] == 0xa3][0]
        k.insert(idx, (0x81, b"\x00\x01"))
    case("issuerUniqueID present", "BadDer", "www.example.com", [edit(leaf, I, unique_id), inter], [root])
    # inner algorithm differs from the outer one
    def inner_alg(k):
        idx = 1 if k[0][0] == 0xa0 else 0
        k[idx + 1] = (SEQ, [oid("1.2.840.10045.4.3.3")])
    case("inner and outer algorithm differ", "AlgorithmMismatch", "www.example.com", [edit(leaf, I, inner_alg), inter], [root])
    # PSS parameters
    def pss_alg(h_oid, mgf_oid, salt=None, trailer=None, with_null=False):
        def hid(o):
            return (SEQ, [oid(o)] + ([(NULL, b"")] if with_null else []))
        params = [(0xa0, [hid(h_oid)]), (0xa1, [(SEQ, [oid("1.2.840.113549.1.1.8"), hid(mgf_oid)])])]
        if salt is not None:
            params.append((0xa2, [integer(salt)]))
        if trailer is not None:
            params.append((0xa3, [integer(trailer)]))
        return (SEQ, [oid("1.2.840.113549.1.1.10"), (SEQ, params)])
    S256 = "2.16.840.1.101.3.4.2.1"
    S512 = "2.16.840.1.101.3.4.2.3"
    good_pss = pss_alg(S256, S256, salt=32)
    case("PSS parameters edited by hand (control)", "OK", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA256(), 32), good_pss), ipss], [root384])
    case("PSS hash parameters NULL (allowed)", "OK", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA256(), 32), pss_alg(S256, S256, salt=32, with_null=True)), ipss], [root384])
    case("PSS MGF1 hash differs", "UnsupportedSignatureAlgorithm", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA256(), 32), pss_alg(S256, S512, salt=32)), ipss], [root384])
    case("PSS salt 20 written out", "BadDer", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA256(), 20), pss_alg(S256, S256, salt=20)), ipss], [root384])
    case("PSS default salt 20", "OK", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA256(), 20), pss_alg(S256, S256)), ipss], [root384])
    case("PSS salt 16", "UnsupportedSignatureAlgorithm", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA256(), 16), pss_alg(S256, S256, salt=16)), ipss], [root384])
    case("PSS trailer field written", "UnsupportedSignatureAlgorithm", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA256(), 32), pss_alg(S256, S256, salt=32, trailer=1)), ipss], [root384])
    case("PSS with SHA-1 defaults", "UnsupportedSignatureAlgorithm", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA1(), 20), (SEQ, [oid("1.2.840.113549.1.1.10"), (SEQ, [])])), ipss], [root384])
    case("PSS salt in the parameters, other salt used", "BadSignature", "pss.example.com",
         [edit(lpss, Ipss, lambda k: None, ("pss", hashes.SHA256(), 48), pss_alg(S256, S256, salt=32)), ipss], [root384])
    # RSA PKCS#1 with absent parameters (RFC 4055: accept)
    def rsa_noparams(der, ikey):
        a = (SEQ, [oid("1.2.840.113549.1.1.11")])
        return edit(der, ikey, lambda k: None, ("pkcs1", hashes.SHA256()), a)
    case("RSA PKCS#1 algorithm without NULL", "OK", "www.example.com", [leaf, rsa_noparams(inter, R)], [root])
    # SPKI edits: an EC point off the curve, an RSASSA-PSS key
    def spki_point_off(k):
        idx = 6 if k[0][0] == 0xa0 else 5
        spki = k[idx]
        pt = bytearray(spki[1][1][1][1:])
        pt[-1] ^= 1
        k[idx] = (SEQ, [spki[1][0], (BIT, b"\x00" + bytes(pt))])
    case("server EC key off the curve", "BadKey", "www.example.com", [edit(leaf, I, spki_point_off), inter], [root])
    def spki_pss(k):
        idx = 6 if k[0][0] == 0xa0 else 5
        spki = k[idx]
        k[idx] = (SEQ, [(SEQ, [oid("1.2.840.113549.1.1.10")]), spki[1][1]])
    case("RSASSA-PSS key in the SPKI", "UnsupportedKey", "pss.example.com", [edit(lpss, Ipss, spki_pss, ("pss", hashes.SHA256(), 32)), ipss], [root384])
    # name constraints edited: leading period, minimum written, empty, in the server certificate
    def nc_raw(der, ikey, value, crit=True, alg=None):
        def f(k):
            ex = ext_list(k)
            ex[:] = [e for e in ex if e[1][0] != oid("2.5.29.30")]
            ex.append(ext_node("2.5.29.30", value, critical=crit))
        return edit(der, ikey, f, alg)
    def subtree(n, extra=()):
        return (SEQ, [(0x82, n.encode())] + list(extra))
    rsa_alg = ("pkcs1", hashes.SHA256())
    case("name constraint with a leading period", "BadExtension", "www.example.com",
         [leaf, nc_raw(inter, R, (SEQ, [(0xa0, [subtree(".example.com")])]), alg=rsa_alg)], [root])
    case("name constraint with minimum written", "BadExtension", "www.example.com",
         [leaf, nc_raw(inter, R, (SEQ, [(0xa0, [subtree("example.com", [(0x80, b"\x00")])])]), alg=rsa_alg)], [root])
    case("empty name constraints", "BadExtension", "www.example.com", [leaf, nc_raw(inter, R, (SEQ, []), alg=rsa_alg)], [root])
    case("name constraints in the server certificate", "BadExtension", "www.example.com",
         [nc_raw(leaf, I, (SEQ, [(0xa0, [subtree("example.com")])])), inter], [root])
    # empty subject
    empty_crit = build(x509.Name([]), "Test ICA", L, I, extra=[(x509.SubjectAlternativeName([x509.DNSName("e.example.com")]), True)])
    case("empty subject, critical subjectAltName", "OK", "e.example.com", [empty_crit, inter], [root])
    empty_noncrit = build(x509.Name([]), "Test ICA", L, I, san=["e.example.com"])
    case("empty subject, non-critical subjectAltName", "BadExtension", "e.example.com", [empty_noncrit, inter], [root])

    # limits
    big = build("big", "Test ICA", L, I, san=["big.example.com"], extra=[(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.99999.2"), b"\x04\x82\x40\x00" + b"x" * 0x4000), False)])
    case("certificate over 16 KiB", "CertTooLarge", "big.example.com", [big, inter], [root])
    case("nine certificates", "ChainTooLong", "www.example.com", [leaf] + [inter] * 8, [root])
    # a path of 9 (server, 7 intermediates, anchor)
    keys = [Key("p256") for _ in range(7)]
    chain_certs = []
    prev_name, prev_key = "Test Root", R
    for n, k in enumerate(keys):
        chain_certs.append(build(f"Deep {n}", prev_name, k, prev_key, ca=True))
        prev_name, prev_key = f"Deep {n}", k
    deep_leaf = build("deep", prev_name, L, prev_key, san=["deep.example.com"])
    case("path longer than 8", "ChainTooLong", "deep.example.com", [deep_leaf] + list(reversed(chain_certs)), [root])
    case("path of exactly 8", "OK", "deep.example.com",
         [build("deep", "Deep 5", L, keys[5], san=["deep.example.com"])] + list(reversed(chain_certs[:6])), [root])
    decoys = []
    for _ in range(33):
        k = Key("p256")
        decoys.append(build("Test ICA", "Test ICA", k, k, ca=True))
    case("33 anchors with the issuer's name", "TooManySignatureChecks", "www.example.com", [leaf, inter], decoys + [root])
    case("30 decoys and the right path (32 signature checks)", "OK", "www.example.com", [leaf, inter], decoys[:30] + [root])
    many_names = build("many", "Test ICA", L, I, san=[f"n{i}.example.com" for i in range(257)])
    case("257 names", "TooManyNames", "n1.example.com", [many_names, inter], [root])
    names256 = build("many", "Test ICA", L, I, san=[f"n{i}.example.com" for i in range(256)])
    case("256 names", "OK", "n255.example.com", [names256, inter], [root])

    # loops, broken extras, distrust
    A, B = Key("p256"), Key("p256")
    ab = build("Loop A", "Loop B", A, B, ca=True)
    ba = build("Loop B", "Loop A", B, A, ca=True)
    case("A and B sign each other, no anchor", "UnknownIssuer", "l.example.com", [build("l", "Loop A", L, A, san=["l.example.com"]), ab, ba], [root])
    case("A and B sign each other, presented again and again", "UnknownIssuer", "l.example.com",
         [build("l", "Loop A", L, A, san=["l.example.com"]), ab, ba, ab, ba, ab, ba, ab], [root])
    junk = bytearray(inter)
    junk[1] ^= 0x01
    case("an unrelated broken certificate", "OK", "www.example.com", [leaf, bytes(junk), inter], [root])
    case("the needed intermediate is broken", "BadDer", "www.example.com", [leaf, bytes(junk)], [root])
    case("distrusted after a date before notBefore", "Distrusted", "www.example.com", ok, [(root, int(T0.timestamp()) - 1)])
    case("distrusted after a date after notBefore", "OK", "www.example.com", ok, [(root, int(T0.timestamp()) + 1)])

    out = b"DSCC" + struct.pack(">HH", 1, len(cases))
    for nm, exp, host, now, anchors, chain in cases:
        b = lambda s: struct.pack(">B", len(s)) + s.encode()
        out += b(nm) + b(exp) + b(host) + struct.pack(">qB", now, len(anchors))
        for der, when in anchors:
            out += struct.pack(">qH", when, len(der)) + der
        out += struct.pack(">B", len(chain)) + b"".join(struct.pack(">H", len(c)) + c for c in chain)
    open(sys.argv[1], "wb").write(out)
    print(f"{sys.argv[1]}: {len(cases)} cases, {len(out)} bytes")

main()
