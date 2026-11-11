# DeSoTLS – the TLS 1.3 connection

How DeSoTLS 0.2 (`common/desotls/`) connects to a server: the handshake, the records, KeyUpdate, the end of a
connection, every refusal, and how `netget https://` uses it. Certificates – what is checked in the server's
chain – are in `CERTIFICATES.md`; what the library is, in `README.md`.

**The rule above all:** either the server is fully authenticated – its certificate chain (`verify.rs`), its
CertificateVerify signature and its Finished – or no application data is sent. `Client::connect` returns only
after the server's Finished verified and ours was sent; every error sends an alert and leaves the connection dead
(every later call returns the same error). There is no "insecure" switch, no fallback to an older version and no
"try without checking the date".

## What it speaks

| Yes | No |
|---|---|
| client only | server |
| TLS 1.3 (RFC 8446) | TLS 1.2 and older – a server that offers only them is refused |
| key exchange X25519 | P-256 / P-384 ECDHE, ML-KEM hybrids; **HelloRetryRequest is never accepted** (table below) |
| TLS_AES_128_GCM_SHA256 (0x1301), TLS_CHACHA20_POLY1305_SHA256 (0x1303) | other cipher suites |
| CertificateVerify: ECDSA P-256 / SHA-256, ECDSA P-384 / SHA-384, RSA-PSS (rsae) with SHA-256/384/512 | PKCS#1 v1.5 in CertificateVerify (allowed only in certificates), Ed25519, SHA-1 |
| alerts, close_notify, KeyUpdate in both directions | resumption (NewSessionTicket read and ignored), 0-RTT, client certificates (refused), ALPN, OCSP stapling |

| | Linux (OpenSSL / rustls) | Windows (Schannel) | RedoxOS (rustls) | DeSoOS (DeSoTLS) |
|---|---|---|---|---|
| where | a library in the program | LSASS + the program's process | a library in the program | `common/desotls` in the program; the kernel has no TLS |
| TLS 1.2 | yes | yes | yes | no |
| groups | X25519, P-256, P-384, hybrids | X25519, P-256, P-384 | X25519, P-256, P-384, hybrid | X25519 only |
| HelloRetryRequest | yes | yes | yes | refused |
| keys of a connection | in the program (kTLS: records in the kernel) | in LSASS | in the program | only in the program – netd sees ciphertext |

## The files

| File | What |
|---|---|
| `client.rs` | `Client`: the handshake state machine, application data, KeyUpdate, close; `Transport` (whatever carries the bytes – netd's TCP for netget, a script in the tests); `TlsError` |
| `record.rs` | records: header, `Protection` (one direction's AEAD key, iv and record number), TLSInnerPlaintext |
| `schedule.rs` | the key schedule (HKDF-Expand-Label, Derive-Secret, the handshake / master / traffic secrets, Finished, KeyUpdate) |
| `tls_tests.rs` | the tests (RFC 8448, scripted servers) – only in `/bin/tlstest` and the host checks |

`Client` is about 120 KiB (a 64 KiB handshake-message buffer for the Certificate, a 24 KiB receive buffer, a
16 KiB send buffer and 16 KiB of decrypted data); programs keep it in a static. The library has no heap and makes
no syscalls; the randomness (client random, session id, X25519 secret) comes from the caller (`getrandom`).

## The handshake

```
ClientHello            ──>
                       <──  ServerHello                     (plain)
                       <──  EncryptedExtensions             (server handshake key)
                       <──  Certificate                     (verify.rs: chain, host, date)
                       <──  CertificateVerify               (signature over the transcript)
                       <──  Finished                        (HMAC over the transcript)
Finished               ──>                                  (client handshake key)
application data       <──> application data                (application keys)
```

**ClientHello:** legacy_version 0x0303, 32 random bytes, a 32-byte random session id (compatibility mode,
RFC 8446 D.4), the offered cipher suites (both, or one with `netget --cipher`), no compression, and the
extensions server_name (the host), supported_groups (x25519), signature_algorithms, signature_algorithms_cert,
supported_versions (TLS 1.3 only) and key_share (one X25519 share). The two signature lists (RFC 8446 4.2.3):

| Extension | For | Contents, in order of preference |
|---|---|---|
| signature_algorithms | CertificateVerify | ecdsa_secp256r1_sha256 (0x0403), ecdsa_secp384r1_sha384 (0x0503), rsa_pss_rsae_sha256 / 384 / 512 (0x0804–0x0806) – **no PKCS#1** |
| signature_algorithms_cert | signatures in certificates | the same + rsa_pkcs1_sha256 / 384 / 512 (0x0401, 0x0501, 0x0601) |

**ServerHello** (refused when): no supported_versions – the server speaks TLS 1.2 or older (protocol_version);
supported_versions other than 0x0304, legacy_version other than 0x0303, a session id that is not ours, a cipher
suite we did not offer, compression, a key share of another group or of the wrong length, a low-order X25519
point (illegal_parameter); no key_share (missing_extension); any other extension (unsupported_extension); a
duplicate (illegal_parameter).

**HelloRetryRequest** (a ServerHello whose random is SHA-256("HelloRetryRequest")) – never accepted; the
reason is told apart (RFC 8446 4.1.4 and 4.2.8):

| HelloRetryRequest | Alert | Message |
|---|---|---|
| a cookie, no key_share (a valid HRR – it would change the ClientHello) | handshake_failure | "HelloRetryRequest unsupported" |
| selected_group = x25519 (already in our key_share) | illegal_parameter | "HRR asks for group already offered" |
| selected_group not in our supported_groups | illegal_parameter | "server asked for undeclared group secp256r1" (the name when known, otherwise the number) |
| neither key_share nor cookie (nothing would change) | illegal_parameter | "HRR changes nothing" |
| malformed | decode_error | "malformed HelloRetryRequest" |

**EncryptedExtensions:** only server_name (empty – the server used our name), supported_groups (its preference,
not used) and – only if offered – record_size_limit; anything else is unsupported_extension.

**CertificateRequest:** refused (handshake_failure, "the server asks for a client certificate").

**Certificate:** an empty request context, 1..8 certificates (more: chain too long), no extensions in the
entries (we asked for none). The chain goes to `verify::server(chain, anchors, host, now)` – every rule in
`CERTIFICATES.md`; a refusal sends the matching alert (expired / not yet valid → certificate_expired, unknown
issuer or distrusted → unknown_ca, an unsupported algorithm or key → unsupported_certificate, the rest →
bad_certificate). The server's key is copied out for the next message.

**CertificateVerify:** the algorithm must be in signature_algorithms (otherwise illegal_parameter – PKCS#1 here
is refused) and fit the key (ECDSA P-256 with 0x0403, P-384 with 0x0503, RSA with the PSS ones). The signed
content, exactly:

```
64 × 0x20  ‖  "TLS 1.3, server CertificateVerify"  ‖  0x00  ‖  Transcript-Hash(ClientHello … Certificate)
```

RSA-PSS uses TLS's rule (salt = hash length, MGF1 with the same hash – `PssParams::tls`), not a certificate's
parameters. A signature that does not verify: decrypt_error.

**Finished:** HMAC(finished_key, Transcript-Hash(… CertificateVerify)), compared in constant time; a wrong one:
decrypt_error. Then the application secrets (transcript up to the server's Finished), our Finished with the client
handshake key, and the application keys in both directions.

**The transcript** is one running SHA-256: a message is added only after the state machine accepted it, and only
in the one allowed order (ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished) – anything
else is unexpected_message. A handshake message must not run across a change of keys (after ServerHello and after
the server's Finished, RFC 8446 5.1): unexpected_message.

## The key schedule

Both cipher suites use SHA-256, so every secret is 32 bytes (`schedule.rs`, RFC 8446 7.1):

```
0  ──HKDF-Extract──  Early Secret  ──Derive-Secret("derived")──┐
X25519 shared secret ──HKDF-Extract──  Handshake Secret  ──>  c hs traffic, s hs traffic   (CH..SH)
                                      └─Derive-Secret("derived")──┐
0  ──HKDF-Extract──  Master Secret  ──>  c ap traffic, s ap traffic   (CH..server Finished)
```

From a traffic secret: key (16 bytes for AES-128-GCM, 32 for ChaCha20) = HKDF-Expand-Label(secret, "key"),
iv = HKDF-Expand-Label(secret, "iv", 12), finished key = HKDF-Expand-Label(secret, "finished", 32); after a
KeyUpdate the next secret = HKDF-Expand-Label(secret, "traffic upd", 32). No PSK, no 0-RTT. Every secret lives
in a `Secret` and is wiped when dropped; the handshake secrets are wiped once the application keys exist.

## Records

```
record = type (1) ‖ 0x0303 (2) ‖ length (2) ‖ fragment
protected: type 23, fragment = AEAD(content ‖ real type ‖ zero padding), additional data = the header
nonce = iv XOR (64-bit record number, big-endian, left-padded to 12 bytes)
```

Each direction has its own key, iv and record number; the number starts at 0 for each new key and never wraps
(at 2^64 − 1 the connection ends). A record is not tied to one read of TCP: the receive buffer collects bytes
until a whole record is there, and one read may bring several records.

| Limit | Value | Over it |
|---|---|---|
| protected record | 2^14 + 256 bytes after the header | record_overflow |
| plaintext in a record | 2^14 bytes | record_overflow |
| handshake message | 64 KiB (Certificate), 16 KiB (others) | decode_error |
| empty records (and ChangeCipherSpec) in a row | 32 | unexpected_message |
| KeyUpdates in a row without data | 16 | unexpected_message |

A record whose tag does not verify – changed, replayed, out of order (a wrong record number gives a wrong nonce) –
is bad_record_mac. Only zeros inside (no content type): unexpected_message. A ChangeCipherSpec (one byte 0x01,
unprotected) is ignored until the server's Finished (middlebox compatibility), refused afterwards. After the
ServerHello every record must be protected.

## KeyUpdate

Only the sender's direction changes (RFC 8446 4.6.3): a KeyUpdate from the server moves our receive key to the
next generation; ours moves our send key. update_requested from the server: we answer once with our own
KeyUpdate (update_not_requested) before anything else. A value other than 0 / 1 is illegal_parameter, a wrong
length decode_error, a KeyUpdate that is not the last message of its record unexpected_message.
`Client::key_update(t, request)` sends one (netget `--key-update` sends one asking the server to update too).

## The end of a connection

The server's close_notify is the clean end: `read` returns 0 from then on. A TCP end without it is an error of its
own kind – `Kind::Truncated` after the peer's FIN, `Kind::Reset` after a reset (the transport's `Err`; for netget,
netd's empty message) – the data may be cut. `close` sends our close_notify once. A fatal
alert from the server ends the connection with `Kind::PeerAlert`.

## netget https://

`netget [-o file] [-v] [--cipher aes|chacha] [--anchor ca.pem] [--key-update] https://host[:port]/path`

1. The clock (syscall 59) must be plausible – otherwise "TLS refused: clock not plausible: … – nothing sent"
   (exit 5), before netd is even asked for a connection.
2. The trusted CAs: `/etc/certs/roots` (sealed, Mozilla's) – or only the CA in `--anchor` (PEM or DER).
3. TCP through netd, the handshake; a summary on stderr:
   `netget: TLS 1.3, TLS_AES_128_GCM_SHA256, x25519, rsa_pss_rsae_sha256, 2 certificates up to <CA>`.
4. The request – only now, after the server's Finished: `GET <path> HTTP/1.1`, `Host`, `User-Agent`,
   `Accept-Encoding: identity`, `Connection: close` (one request per connection, no keep-alive).
5. The answer, record by record (the parser `user/lib/http.rs`), then up to 2 s for the connection's end, then
   our close_notify.

The answer's framing (the same rules for http://; RFC 9110, RFC 9112 §6.3, in this order):

| Answer | Result |
|---|---|
| 1xx other than 101 (100 Continue, 103 Early Hints) | skipped, at most 4 – a fifth is an error; with Content-Length or Transfer-Encoding – error |
| 101 Switching Protocols | error – no upgrade was asked for |
| 204 | ends with its head; Content-Length or Transfer-Encoding – error (RFC 9110 §8.6, RFC 9112 §6.1) |
| 304 | ends with its head; Content-Length, Transfer-Encoding and Content-Encoding describe the 200 that was not sent – only their syntax is checked |
| 205 | no content: Content-Length 0, an empty chunked body or nothing; a byte of content – error |
| Transfer-Encoding: chunked | complete with the last chunk (size 0) and the trailer section |
| Transfer-Encoding: anything else, in two fields, or in an HTTP/1.0 answer | error |
| Transfer-Encoding and Content-Length together | error (RFC 9112 §6.3: a sign of request smuggling; curl, WinHTTP and Redox let Transfer-Encoding win) |
| Content-Length: N | exactly N bytes (N = 0 – an empty body) |
| Content-Length twice – also with the same value | error (RFC 9110 §8.6 allows identical ones, as curl and Go do; netget refuses – a simple, strict client) |
| neither | everything up to the end – for https only with the server's close_notify; a TCP end without it is "cut short" |
| Content-Encoding other than identity, in an answer with content | error – netget decodes nothing (gzip is not supported) |
| Content-Encoding with parameters (`identity;level=1`) – in any answer, also 304 | error – a content coding is a plain token (RFC 9110 §8.4); only transfer codings take parameters (RFC 9112 §7) |
| any byte after the end of the answer – also in a later record, also after a 204 / 304 head | error (one request per connection: it is not a second answer) |
| a malformed head: a status line other than "HTTP/1.x NNN", a header name that is not a token, a control character in a value, a line without ":", a folded line, more than 8 KiB, a Content-Length that is not a decimal number, a bad Connection list (not tokens, more than 32 names, an end-to-end field such as Content-Length or Host) | error |

Chunked bodies: the size in 1–16 hex digits (17 – also with leading zeros – is an error, so is a total that
overflows 64 bits); chunk extensions are skipped but must follow RFC 9112 §7.1.1 (`;name[=token|quoted-string]`,
an unclosed quote or a backslash before nothing is an error); CRLF exactly (a bare LF is an error), also after
every chunk's data; a chunk-size line of at most 4 KiB. Trailers are kept apart from the head – never merged,
never framing; at most 8 KiB, the same syntax as headers; refused there (DeSoOS policy built from the categories of
RFC 9110 §6.5.1 – fields needed before the content): Content-Length, Transfer-Encoding, Host, Content-Encoding,
Content-Type, Content-Range, Trailer, Connection, Keep-Alive, TE, Upgrade, Cache-Control, Expires, Set-Cookie,
Authorization, WWW-Authenticate – and every field the answer's Connection names. `-v` prints the heads (also the
skipped 1xx) and the trailers. The parser takes the bytes in any pieces with the same result (`/bin/httptest`).

After a whole answer (by its Content-Length, its last chunk or its 204 / 304 head) netget reads on to the end of the
connection, at most 2 s:

| What comes | Result |
|---|---|
| close_notify, FIN | 0 |
| FIN or a reset without close_notify, no more data | 0 with a warning (as curl and Go; for https the framing is inside the authenticated stream) |
| nothing for 2 s | 0 with a warning "the server did not close the connection", netget closes it |
| more data | 4 |
| a broken record, a server alert | 5 – never taken for a missing close_notify |

Before the answer is whole (fewer bytes than Content-Length, before the last chunk, without a length and without
close_notify) a FIN or a reset is "cut short" (3) – for http too: netd tells a reset apart with an empty message.

| Exit | Meaning |
|---|---|
| 0 | a whole 2xx answer |
| 1 | wrong usage, a file problem |
| 2 | no connection (netd, DNS, TCP, the server closed during the handshake) |
| 3 | cut short: fewer bytes than Content-Length, before the last chunk, or https ended without close_notify before the answer was complete, or a reset before the answer was complete (also http without a length) |
| 4 | an HTTP status other than 2xx, or a malformed answer (framing, headers, trailers, coding, data after the end) |
| 5 | TLS refused: certificate, clock, handshake, record, a server alert |

## Tests

**`/bin/httptest`** (NET TEST 5): the HTTP parser `user/lib/http.rs` without a network – 66 answers (every
rule above, valid and refused, the end of the connection) and a chunked body of 40 000 bytes, each fed whole, byte
by byte and in random pieces with the same result; 4800 mutations – never a panic, the body handed out always
equals the parser's count.

**`common/desotls/tls_tests.rs`** (134 checks, run by `/bin/tlstest` in TLS TEST 1 and on the host):

- RFC 8448 §3: the published ClientHello is sent (our record must be the RFC's, byte for byte), the published
  ServerHello, EncryptedExtensions, Certificate, CertificateVerify (RSA-PSS by the RFC's 1024-bit key – a key
  size allowed only in this test, `PublicKey::new_for_test`) and server Finished are received; every secret,
  key and iv the RFC lists must come out, and our Finished must carry the RFC's client verify_data. The vectors
  come from the tlslite-ng test suite's copy of RFC 8448; the client verify_data and the KeyUpdate generations
  were computed from them with Python's hashlib / hmac – not with this code. The same flight cut into 1–7 byte
  pieces.
- On that session: data in several records, 1–7 byte pieces and several records in one piece, a full 16 KiB
  record, zero padding, KeyUpdate from the server (update_requested answered once, three generations, record
  numbers) and from us (with and without request), close_notify, FIN and reset without it, a fatal alert; refused:
  a changed byte, a replayed record, a skipped record number, an oversized record, an unprotected record, 33 empty
  records, only padding, KeyUpdate 2 / wrong length / not at the end of its record / 17 in a row.
- Changed server flights: the Finished, the CertificateVerify signature, a certificate the signature does not
  cover, PKCS#1 and a mismatched algorithm in CertificateVerify, an extra extension, a request context, a
  CertificateRequest, wrong order, a Certificate twice or missing, application data before the Finished, data
  across the key change, an unprotected record – each with its alert, nothing but the alert after the
  ClientHello, and the connection dead.
- Every HelloRetryRequest row of the table and broken ServerHellos (no supported_versions, TLS 1.2 selected,
  another session id, a suite not offered, an extension not offered, a P-256 share, a duplicate).
- On the host, 32 hand-made mutations of the code (Finished not checked, CertificateVerify skipped or with the
  client's context string, the transcript missing a message or in the wrong order, the wrong KeyUpdate direction,
  record numbers not counting, the nonce without the number, padding kept, limits removed, …) – all 32 caught.

**TLS TEST 2** – `init test /bin/tlstest net` (87 cases): `/bin/netget https://` against `tests/tls-stub.py` on the host
(Python `ssl` = OpenSSL; certificates in `tests/tls/`, made by `gen-test-certs.py`): both cipher suites, an RSA
and an ECDSA server, 1 MiB with a pattern, `--key-update` (OpenSSL answers with its own KeyUpdate), the framing
cases above – HTTP/1.1 from `tests/http_pages.py` (shared with NET TEST's `tests/http-stub.py`): chunked bodies
(with trailers, extensions, quoted strings, 16 hex digits, 1 MiB in random chunk sizes), 100 Continue, 204 / 205 /
304, a reset, a FIN without close_notify and a server that stays silent after a whole answer (0 with a warning,
within 4 s), cut before the last chunk (3), 28 refused answers (4), Content-Encoding with parameters in 200 and
304 (4, "bad Content-Encoding") –, resets (in the middle, without a length – 3;
after a whole answer – 0), and the refusals – unknown CA (without `--anchor`), expired, not yet valid, another name, a
broken signature, a man in the middle with a certificate from another CA, a TLS 1.2-only server, a server without
X25519 – each exit 5 with tls-stub's counter showing that no request reached the server. A man in the middle that
holds the server's keys (from its keylog) changes the Finished and the CertificateVerify (exit 5, no request),
changes or replays a record after the handshake (exit 5), cuts the server's bytes into 1–7 byte pieces, sends
several records at once, and inserts three KeyUpdates from the server (all exit 0 – also with a chunked answer);
a sixth breaks the tag of the record with the server's close_notify after a whole answer (exit 5). `[RESULT-TLS]`: checks, cases,
the time of a whole `/hello` and the speed of `/big`.

**TLS TEST 3** – a clock made not plausible (a self-test switch in `rtc.rs`): netget refuses before connecting.

## Not done

Revocation (CRL, OCSP) and Certificate Transparency are not checked (`CERTIFICATES.md`). Not audited, not for
production use.
