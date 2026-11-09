#!/usr/bin/env python3
# Makes the certificates of the HTTPS self-tests (tests/tls-stub.py, /bin/tlstest):
#
#   ca.pem            "DeSoOS Test CA" (ECDSA P-256) – the guest trusts it with --anchor
#   other-ca.pem      "Other Test CA" – the one a man in the middle would use
#   rsa.pem/.key      tls.desoos, RSA 2048 (CertificateVerify: RSA-PSS)
#   ecdsa.pem/.key    tls.desoos, ECDSA P-256
#   expired.pem/.key  tls.desoos, valid 2020-2021
#   future.pem/.key   tls.desoos, valid from 2040
#   wrongname.pem/.key  other.desoos (the guest connects to tls.desoos)
#   badsig.pem        rsa.pem with one bit of its signature changed (key: rsa.key)
#   mitm.pem/.key     tls.desoos, issued by Other Test CA
#
# Each server .pem holds the server certificate and the CA certificate after it.  Run once;
# the files are kept in the repository (test keys only – never trust them anywhere else).
#   gen-test-certs.py <dir>
import datetime, os, sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

out = sys.argv[1] if len(sys.argv) > 1 else "."
UTC = datetime.timezone.utc
NOW_START = datetime.datetime(2025, 1, 1, tzinfo=UTC)
FAR = datetime.datetime(2045, 1, 1, tzinfo=UTC)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def ca(cn):
    k = ec.generate_private_key(ec.SECP256R1())
    c = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn)).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW_START).not_valid_after(FAR)
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
         .sign(k, hashes.SHA256()))
    return k, c


def leaf(key, host, ca_key, ca_cert, start=NOW_START, end=FAR):
    return (x509.CertificateBuilder().subject_name(name(host)).issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(ca_key, hashes.SHA256()))


def write(fname, data):
    with open(os.path.join(out, fname), "wb") as f:
        f.write(data)


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM)


ca_key, ca_cert = ca("DeSoOS Test CA")
other_key, other_cert = ca("Other Test CA")
write("ca.pem", pem(ca_cert))
write("other-ca.pem", pem(other_cert))

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
servers = {
    "rsa": (rsa_key, leaf(rsa_key, "tls.desoos", ca_key, ca_cert), ca_cert),
    "ecdsa": (ec_key, leaf(ec_key, "tls.desoos", ca_key, ca_cert), ca_cert),
    "expired": (ec_key, leaf(ec_key, "tls.desoos", ca_key, ca_cert, datetime.datetime(2020, 1, 1, tzinfo=UTC), datetime.datetime(2021, 1, 1, tzinfo=UTC)), ca_cert),
    "future": (ec_key, leaf(ec_key, "tls.desoos", ca_key, ca_cert, datetime.datetime(2040, 1, 1, tzinfo=UTC), FAR), ca_cert),
    "wrongname": (ec_key, leaf(ec_key, "other.desoos", ca_key, ca_cert), ca_cert),
    "mitm": (ec_key, leaf(ec_key, "tls.desoos", other_key, other_cert), other_cert),
}
for n, (k, c, issuer) in servers.items():
    write(n + ".pem", pem(c) + pem(issuer))
    write(n + ".key", pem_key(k))
# The RSA certificate with one bit of its signature changed.
der = bytearray(servers["rsa"][1].public_bytes(serialization.Encoding.DER))
der[-20] ^= 1
bad = x509.load_der_x509_certificate(bytes(der))
write("badsig.pem", pem(bad) + pem(ca_cert))
print("test certificates written to", out)
