#!/usr/bin/env python3
# Makes the certificates of the time service's tests (tests/nts-server, NTS TEST): a chain with
# an intermediate CA, so the second check of a bootstrap (every certificate valid over
# T +- U) can be tested on the intermediate too.
#
#   nts-root.pem        "DeSo OS NTS Test Root" (ECDSA P-256, pathLen 1, 2025-2060) – the
#                       time service's test table trusts it (and ca.pem)
#   nts-good.pem/.key   tls.deso (2025-2060) <- "NTS Test Intermediate A" (2025-2060)
#   nts-intshort.pem/.key  tls.deso (2025-2060) <- "NTS Test Intermediate B", valid only
#                       until 2030-01-01 00:00:00 UTC (the server certificate outlives it)
#
# Each server .pem holds the server certificate and its intermediate (not the root).  Run
# once; the files are kept in the repository (test keys only – never trust them anywhere
# else).  The certificates of gen-test-certs.py are not touched.
#   gen-nts-certs.py <dir>
import datetime, os, sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

out = sys.argv[1] if len(sys.argv) > 1 else "."
UTC = datetime.timezone.utc
START = datetime.datetime(2025, 1, 1, tzinfo=UTC)
END = datetime.datetime(2060, 1, 1, tzinfo=UTC)
SHORT = datetime.datetime(2030, 1, 1, tzinfo=UTC)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM)


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def ca(cn, key, issuer_name, issuer_key, path_len, end):
    return (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(START).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(issuer_key, hashes.SHA256()))


def leaf(key, issuer, issuer_key):
    return (x509.CertificateBuilder().subject_name(name("tls.deso")).issuer_name(issuer.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(START).not_valid_after(END)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("tls.deso")]), critical=False)
            .sign(issuer_key, hashes.SHA256()))


def write(fname, data):
    with open(os.path.join(out, fname), "wb") as f:
        f.write(data)


root_key = ec.generate_private_key(ec.SECP256R1())
root = ca("DeSo OS NTS Test Root", root_key, name("DeSo OS NTS Test Root"), root_key, 1, END)
int_a_key = ec.generate_private_key(ec.SECP256R1())
int_a = ca("NTS Test Intermediate A", int_a_key, root.subject, root_key, 0, END)
int_b_key = ec.generate_private_key(ec.SECP256R1())
int_b = ca("NTS Test Intermediate B", int_b_key, root.subject, root_key, 0, SHORT)
write("nts-root.pem", pem(root))
for n, (issuer, issuer_key) in {"nts-good": (int_a, int_a_key), "nts-intshort": (int_b, int_b_key)}.items():
    k = ec.generate_private_key(ec.SECP256R1())
    write(n + ".pem", pem(leaf(k, issuer, issuer_key)) + pem(issuer))
    write(n + ".key", pem_key(k))
print("NTS test certificates written to", out)
