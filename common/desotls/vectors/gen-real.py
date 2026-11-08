#!/usr/bin/env python3
# Builds real.bin – real certificate chains of public web servers (as published in the test
# data of rustls/webpki, ISC licence), for the DeSoTLS tests: each must verify against its
# CA at the time given, the expired ones must not.  The kernel CERT TEST also checks them
# against /etc/certs/roots (Mozilla's store) where that CA is still in it.
#
#   gen-real.py <webpki/tests directory> <out.bin>
#
# webpki commit COMMIT, every file checked against its SHA-256 below.
# Format: as certs.bin ("DSCC"), see gen-certs.py.
import hashlib, os, struct, sys

COMMIT = "ce6321747dfcf218f3a1fb76c6f0650ad0f4f509"
# (name, expected, host, time, anchor file, [chain files])
CASES = [
    ("netflix 2017 (RSA)", "OK", "account.netflix.com", 1492441716, "netflix/ca.der", ["netflix/ee.der", "netflix/inter.der"]),
    ("sanofi 2025 (RSA, algorithm without NULL)", "OK", "irelease-dev.sanofi.com", 1746549566, "sanofi/ca.der", ["sanofi/ee.der", "sanofi/inter.der"]),
    ("cloudflare-dns 2022 (ECDSA)", "OK", "cloudflare-dns.com", 1663495771, "cloudflare_dns/ca.der", ["cloudflare_dns/ee.der", "cloudflare_dns/inter.der"]),
    ("cloudflare-dns, other name", "OK", "one.one.one.one", 1663495771, "cloudflare_dns/ca.der", ["cloudflare_dns/ee.der", "cloudflare_dns/inter.der"]),
    ("web-platform.test (260 names)", "TooManyNames", "web-platform.test", 1619256684, "wpt/ca.der", ["wpt/ee.der"]),
    ("Amazon Root CA 1 (RSA 2048)", "OK", "valid.rootca1.demo.amazontrust.com", 1742000000, "amazon/AmazonRootCA1.cer", ["amazon/valid.rootca1.demo.amazontrust.com.cer", "amazon/r2m03.cer"]),
    ("Amazon Root CA 2 (RSA 4096)", "OK", "valid.rootca2.demo.amazontrust.com", 1742000000, "amazon/AmazonRootCA2.cer", ["amazon/valid.rootca2.demo.amazontrust.com.cer", "amazon/r4m02.cer"]),
    ("Amazon Root CA 3 (P-256)", "OK", "valid.rootca3.demo.amazontrust.com", 1742000000, "amazon/AmazonRootCA3.cer", ["amazon/valid.rootca3.demo.amazontrust.com.cer", "amazon/e2m03.cer"]),
    ("Amazon Root CA 4 (P-384)", "OK", "valid.rootca4.demo.amazontrust.com", 1742000000, "amazon/AmazonRootCA4.cer", ["amazon/valid.rootca4.demo.amazontrust.com.cer", "amazon/e3m02.cer"]),
    ("Amazon expired demo", "Expired", "expired.rootca1.demo.amazontrust.com", 1742000000, "amazon/AmazonRootCA1.cer", ["amazon/expired.rootca1.demo.amazontrust.com.cer", "amazon/r2m03.cer"]),
    ("Amazon demo, wrong host", "NameMismatch", "valid.rootca2.demo.amazontrust.com", 1742000000, "amazon/AmazonRootCA1.cer", ["amazon/valid.rootca1.demo.amazontrust.com.cer", "amazon/r2m03.cer"]),
    ("Amazon demo, wrong root", "UnknownIssuer", "valid.rootca1.demo.amazontrust.com", 1742000000, "amazon/AmazonRootCA3.cer", ["amazon/valid.rootca1.demo.amazontrust.com.cer", "amazon/r2m03.cer"]),
]
SHA256 = {
    "amazon/AmazonRootCA1.cer": "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e",
    "amazon/AmazonRootCA2.cer": "1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4",
    "amazon/AmazonRootCA3.cer": "18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4",
    "amazon/AmazonRootCA4.cer": "e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092",
    "amazon/e2m03.cer": "493e78eee8cca1f26e6494ed924985af3fa9e6110eaa61c3214e8d73b4047316",
    "amazon/e3m02.cer": "a7d15e62c78825919fb59bde58efcfb0225b4107dfc60026885420185dc69b63",
    "amazon/expired.rootca1.demo.amazontrust.com.cer": "c799dafce7d30e80b8a765e2e1f8743034345cc0ef73758e2611e9917bbf17de",
    "amazon/r2m03.cer": "bf8a69027bcc8d2d42a6e6d25bdd4873f6a34b8f90edf07e86c5d6916da0b933",
    "amazon/r4m02.cer": "2cc39f6789b967b0282aeaca4548f602a1b274e90d260773e9e7b0f7c0f13432",
    "amazon/valid.rootca1.demo.amazontrust.com.cer": "6a434267814ef4966139b6e9fdb31490c2b614ad18612e263a75c4eae39273b7",
    "amazon/valid.rootca2.demo.amazontrust.com.cer": "297ff8b2af18da061a8607b8378e75b2304629b4bfff5f8f14c3d803d35a8ce4",
    "amazon/valid.rootca3.demo.amazontrust.com.cer": "78828b25c76d9f2e4aea9d42484702e4e3be97133d4d28493f493e68c9a195c5",
    "amazon/valid.rootca4.demo.amazontrust.com.cer": "e08da5e94f5c95b4134d86010581afaa69c29812d187dfb4b0db23cf76f6eafb",
    "cloudflare_dns/ca.der": "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161",
    "cloudflare_dns/ee.der": "c93386adf01223e637a3aca7c68988bb8240c4afd5d204c206bc35d7a4358dd1",
    "cloudflare_dns/inter.der": "f7a9a1b2fd964a3f2670bd668d561fb7c55d3aa9ab8391e7e169702db8a3dbcf",
    "netflix/ca.der": "eb04cf5eb1f39afa762f2bb120f296cba520c1b97db1589565b81cb9a17b7244",
    "netflix/ee.der": "d58b0dcbd15594693041633bbc788af700df3f8f243a1e09afe8cc585010322c",
    "netflix/inter.der": "564dbc6a76550fd2d4f4bac6448a1157b33cbd8e0b3fd76d72107540964a85b5",
    "sanofi/ca.der": "f8aacafa1a7e8b345a8f74fbe123d2248d4edb5033db42ebfacf4274b78e38c5",
    "sanofi/ee.der": "8a7df74a7c4d76287f41255e2d267a5bd6cfc41fda9a404f2ddc8858a787b934",
    "sanofi/inter.der": "20a53953f9b299284540797aba822d795f498ad8fd027e01c00386262a681335",
    "wpt/ca.der": "d2d38f5c7ce32127361f269145006c88fa0706868139d528182b2d153ef47fd0",
    "wpt/ee.der": "46aec06a7a43456c98ca33e74b3b8dd73d709d14ea2c9eee730e1b724afe9469",
}


def main():
    src, out_path = sys.argv[1], sys.argv[2]
    def read(f):
        b = open(os.path.join(src, f), "rb").read()
        if hashlib.sha256(b).hexdigest() != SHA256[f]:
            sys.exit(f"{f}: SHA-256 differs from the pinned one")
        return b
    out = b"DSCC" + struct.pack(">HH", 1, len(CASES))
    s = lambda t: struct.pack(">B", len(t)) + t.encode()
    for nm, exp, host, now, anchor, chain in CASES:
        a = read(anchor)
        out += s(nm) + s(exp) + s(host) + struct.pack(">qB", now, 1) + struct.pack(">qH", 0, len(a)) + a
        out += struct.pack(">B", len(chain)) + b"".join(struct.pack(">H", len(c)) + c for c in (read(f) for f in chain))
    open(out_path, "wb").write(out)
    print(f"{out_path}: {len(CASES)} cases, {len(out)} bytes")


main()
