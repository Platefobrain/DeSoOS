#!/usr/bin/env python3
# Builds wycheproof.bin – the Wycheproof signature vectors the DeSoCrypto tests (tests.rs)
# run in /bin/cryptotest and the kernel CRYPTO TEST.
#
#   gen-wycheproof.py <dir with the JSON files> <out.bin> [--full]
#
# The JSON files come from https://github.com/C2SP/wycheproof, commit COMMIT below,
# directory testvectors_v1; each is checked against its SHA-256 here, so the same input
# always gives the same wycheproof.bin.  Without --full: the sets that go into the repo
# (ECDSA P-256 + P-384, RSA PKCS#1 2048/SHA-256, PSS 2048/SHA-256, PSS "misc" with
# SHA-256/384/512 and the same MGF1 hash).  --full adds RSA 3072/4096 (checked on the host,
# not shipped – about 330 KB more).
#
# Format (all numbers big-endian):
#   "DSWP" u16 version (1) u16 number of sets
#   per set:  u8 kind (1 PKCS#1 v1.5, 2 PSS, 3 ECDSA)  u8 hash (1 SHA-256, 2 SHA-384, 3 SHA-512)
#             u8 MGF1 hash  u16 salt length  u16 len + key A  u16 len + key B  u16 cases
#             RSA: A = n without leading zero bytes, B = e;  ECDSA: A = 04 || X || Y, B empty
#   per case: u16 tcId  u8 expected (1 valid, 0 invalid, 2 "acceptable")  u16 len + msg
#             u16 len + signature
import hashlib, json, os, struct, sys

COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
FILES = {
    "ecdsa_secp256r1_sha256_test.json": "182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332",
    "ecdsa_secp384r1_sha384_test.json": "8a5b3ae1760975143414811f13588c24d951d9d8c904195087ba327591dfe9cc",
    "rsa_signature_2048_sha256_test.json": "94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393",
    "rsa_pss_2048_sha256_mgf1_32_test.json": "7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c",
    "rsa_pss_misc_test.json": "1fac515f67fea8ccbf44ea08fde2de00cd76169f774a54ce2994c9963c31e84f",
}
FULL = {
    "rsa_signature_3072_sha384_test.json": "73499ee649d8fb703b3f0f455fa36f7682fde677c590a736958ebce05ab27dae",
    "rsa_signature_4096_sha512_test.json": "9d6e67b1eb0d7040db411835238efd20e9302399a258bdff82de3f38e0f2855a",
    "rsa_pss_3072_sha256_mgf1_32_test.json": "cca48433e6d1accb57f65b3396c4f4dd93c776467101c3f0948e74c283fd4749",
    "rsa_pss_4096_sha512_mgf1_32_test.json": "af1e1c1c593edf91be3e9880927231d57f9df082f2d8caec2a61d9874ade101f",
}
HASH = {"SHA-256": 1, "SHA-384": 2, "SHA-512": 3}
RESULT = {"valid": 1, "invalid": 0, "acceptable": 2}


def blob(b):
    return struct.pack(">H", len(b)) + b


def strip(b):
    return b.lstrip(b"\0") or b"\0"


def main():
    src, out = sys.argv[1], sys.argv[2]
    files = dict(FILES)
    if "--full" in sys.argv:
        files.update(FULL)
    sets = []
    for name, want in files.items():
        raw = open(os.path.join(src, name), "rb").read()
        got = hashlib.sha256(raw).hexdigest()
        if got != want:
            sys.exit(f"{name}: SHA-256 {got}, expected {want}")
        d = json.loads(raw)
        for g in d["testGroups"]:
            if name.startswith("ecdsa"):
                kind, h, mgf, salt = 3, HASH[g["sha"]], 0, 0
                a, b = bytes.fromhex(g["publicKey"]["uncompressed"]), b""
            else:
                if g["sha"] not in HASH:
                    continue
                pk = g["publicKey"]
                a, b = strip(bytes.fromhex(pk["modulus"])), strip(bytes.fromhex(pk["publicExponent"]))
                if name.startswith("rsa_pss"):
                    if g.get("mgfSha") != g["sha"]:
                        continue
                    kind, h, mgf, salt = 2, HASH[g["sha"]], HASH[g["mgfSha"]], g["sLen"]
                else:
                    kind, h, mgf, salt = 1, HASH[g["sha"]], 0, 0
            cases = b"".join(
                struct.pack(">HB", t["tcId"], RESULT[t["result"]]) + blob(bytes.fromhex(t["msg"])) + blob(bytes.fromhex(t["sig"]))
                for t in g["tests"]
            )
            sets.append(struct.pack(">BBBH", kind, h, mgf, salt) + blob(a) + blob(b) + struct.pack(">H", len(g["tests"])) + cases)
    data = b"DSWP" + struct.pack(">HH", 1, len(sets)) + b"".join(sets)
    open(out, "wb").write(data)
    print(f"{out}: {len(sets)} sets, {len(data)} bytes, SHA-256 {hashlib.sha256(data).hexdigest()}")


main()
