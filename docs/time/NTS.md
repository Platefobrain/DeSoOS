# NTS – Network Time Security (RFC 8915)

DeSoOS's NTS client: `user/lib/nts.rs` (no input / output – records, fields, checks), `user/bin/nettime.rs`
(`--nts` carries the bytes), DeSoTLS 0.3 (ALPN, exporter) and DeSoCrypto 0.7 (AES-SIV-CMAC-256) underneath. Status
in v0.79 stage B: **read only** – `nettime --nts` shows an authenticated time and changes nothing. Raising the last
known good time and correcting the clock come with the time service (stage D).

## How it goes

1. **NTS-KE** – TCP to the server, port 4460 unless given (`host:port`): the name lookup and the connection get
   3 × `-t` (default 6 s; netd alone would wait 1 + 2 + 4 + 8 = 15 s for a SYN-ACK), the TLS part 3 × `-t` again;
   TLS 1.3 with ALPN `ntske/1` – the server must confirm it; the certificate is checked against `/etc/certs/roots` (or only the CA in `--anchor`) at the wall
   clock's time. A clock that is not plausible: refused before anything is sent (exit 2).
2. The request: Next Protocol {0 = NTPv4}, AEAD {15 = AEAD_AES_SIV_CMAC_256}, End of Message – all critical.
3. The response is read to End of Message, then the server's `close_notify` must come (RFC 8915 §4) – nothing else
   may follow End of Message. Then our `close_notify`.
4. **Keys** from the TLS exporter: label `EXPORTER-network-time-security`, context 00 00 | 00 0f | 00 (C2S) / 01
   (S2C), 32 bytes each (RFC 9846 §7.5 – from `exporter_secret`).
5. **NTP** to the negotiated server and port (else the KE server's address and 123), one UDP socket per server, all
   servers at once, at most 2 queries per server (the second after `-t` ms of silence, or right after an NTS NAK).

## NTS-KE response – what is accepted

| Record | Rule |
|---|---|
| Next Protocol (1) | exactly once, exactly {0}, Critical Bit set; an empty body – refused |
| AEAD (4) | exactly once, exactly {15} (Critical Bit either way) |
| New Cookie (5) | Critical Bit not set; 16–1024 bytes **and a length divisible by 4** (an NTP extension field is a multiple of 4 and the server needs its exact bytes back – a cookie is never padded); others skipped; at most 8 kept; none usable – refused |
| Server Negotiation (6) | at most once, 1–253 bytes of host name (letters, digits, `.`, `-`) or IPv4 address – used for NTP |
| Port Negotiation (7) | at most once, not 0 – used for NTP |
| Error (2) | refused, with its code (Critical Bit not set or not exactly 2 bytes – refused as malformed) |
| Warning (3) | refused (RFC 8915 §4.1.4: unknown warning codes are errors; none are defined); malformed as for Error |
| unknown | critical bit – refused; otherwise skipped |
| End of Message (0) | must come, Critical Bit set, empty body; nothing after it; the whole message ≤ 65 536 bytes (decrypted TLS data) |

Server and Port Negotiation may carry the Critical Bit or not (§4.1.7–4.1.8).

## NTP with NTS – the request

48-byte header (random Transmit, Precision 0x20 – a privacy constant from the data-minimization draft, not the clock's
precision) + Unique Identifier (0x0104, 32 random bytes) + NTS Cookie (0x0204) + Cookie Placeholder × p (0x0304,
as long as the cookie, zeros) + NTS Authenticator (0x0404: nonce length 16, ciphertext length 16, a random nonce, the
SIV of AES-SIV under C2S over everything before this field, empty plaintext).

**Placeholders:** take one cookie (it leaves the pool for good – also when no answer comes); r = unused cookies left;
p = min(7, 7 − r) (the server returns 1 + p, so the pool stays ≤ 8); fewer while the request would be longer than
1200 bytes (paths with a smaller MTU – no PMTU discovery here); never longer than 1469 bytes (an answer may be up to 3
bytes longer than the request, 1472 is netd's limit).

## NTP with NTS – the answer, in this order

1. length ≥ 48, mode 4, version 3 / 4, Origin = our Transmit; the extension fields well formed (length a multiple of
   4, at least 16, inside the packet);
2. **stratum 0**: only an NTS NAK (Kiss code `NTSN`) with our Unique Identifier counts – a control message, never a
   time: the next query (new cookie) goes out at once; when that fails too, a new NTS-KE is needed. Any other
   stratum-0 answer – ignored (not authenticated);
3. our Unique Identifier (exactly one, before the Authenticator); the Authenticator **exactly once**, its padding
   (after the nonce, after the ciphertext, the additional padding) all zeros (§5.6 – these bytes are not covered by
   the Authenticator itself), and valid (AES-SIV with S2C, everything before it as associated data); fields after it are not authenticated and not used;
   new cookies come only from its encrypted part;
4. then every check of `ntp.rs` on the header (LI, stratum 1–15, timestamps, root delay / dispersion, distance).

## Limits (v0.79 stage B)

- read only – nothing sets the clock or the lower bound (stage D)
- needs a plausible clock for the certificate (the bootstrap without one comes with stage D)
- NTS-KE one server after the other (NTP then in parallel): a dead server delays the next ones by up to 3 × `-t`
  (6 s by default) – chrony runs every source on its own; cookies and keys only in memory – after a restart always a
  new NTS-KE (RFC 8915 recommends keeping one cookie; that needs the writable disk)
- only AEAD_AES_SIV_CMAC_256, only NTPv4, only IPv4; 1200-byte default request limit without PMTU discovery

## Tests

- **NTP TEST 1/3** (`ntptest`, no network): every NTS-KE refusal and acceptance (37 responses, the Critical Bit and
  exact lengths among them), the Authenticator's three paddings, the zeroing guard, the cookie pool, the
  placeholder count (8 cases), the request byte for byte with its Authenticator checked by AES-SIV, every kind of
  answer (authenticated, fields after the Authenticator, wrong / missing Unique Identifier, bad / wrong-key
  Authenticator, Origin, stratum 16 inside, DENY / NTSN without our Unique Identifier, NTS NAK, plain NTP, two
  Authenticators, a malformed field).
- **NTP TEST 2/3** (`ntptest net`): `nettime --nts` against `tests/nts-server` – a Rust program on **rustls** and
  RustCrypto **aes-siv**, independent of DeSoTLS / DeSoCrypto: 27 NTS-KE responses (every refusal above, no
  `close_notify`, 65 536 / 65 537 bytes, Server Negotiation through a name, no ALPN), 15 kinds of NTP answers (the
  stale Unique Identifier after a retry, duplicates, NTS NAK, unauthenticated DENY / NTSN, a plain answer, stratum 16,
  wrong key, two Authenticators, NAK to every query); the server counts requests, cookies seen twice (always 0),
  Authenticators that did not verify (always 0), the longest request and the placeholders.
- Also in NTP TEST 2/3: a KE server that never answers the SYN (`tests/tls-stub.py`, port 58471) is given up after
  3 × `-t`, alone and before a good server (which still gives the time).
- **NTP TEST 3/3**: a clock that is not plausible – `nettime --nts` refuses before it asks netd for anything.
