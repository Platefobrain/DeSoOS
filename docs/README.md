# DeSoOS documentation

The documentation of the whole system. Change history is in `../CHANGELOG.md`; each main code folder has its own
`README.md` (what it holds and where to start reading).

| Document | What it describes |
|---|---|
| `ARCHITECTURE.md` | How DeSoOS is built and how its parts work together: boot, memory, scheduler, syscalls and handles, IPC, user-space services and drivers, permissions (DCP), files, DeSoFS, network, USB, cryptography, certificates |
| `RELEASE.md` | One report per release: tests passed (QEMU TCG / KVM), real hardware, performance against the previous release, known problems; at the top – the current limitations of the system |
| `desofs/README.md` | DeSoFS – DeSoOS's own copy-on-write file system: what it does, the `desofs` commands, where the code and the tests are |
| `desofs/FORMAT.md` | The DeSoFS on-disk format 1, byte by byte (closed specification) |
| `desocrypto/README.md` | DeSoCrypto – DeSoOS's own cryptographic library: what it has, who uses it, where the code and the tests are |
| `desocrypto/ALGORITHMS.md` | Every DeSoCrypto module and its API, the rules of the code (limits, key wiping, timing, signatures on public data only), AES-NI / PCLMULQDQ and the kernel, the tests, speed |
| `desotls/README.md` | DeSoTLS – DeSoOS's own TLS library: what it does, where things are |
| `desotls/HANDSHAKE.md` | The TLS 1.3 connection: the handshake, every refusal (HelloRetryRequest table, alerts), the key schedule, records and their limits, KeyUpdate, the end of a connection, `netget https://` (framing, exit codes), the tests (RFC 8448, OpenSSL, a man in the middle) |
| `desotls/CERTIFICATES.md` | How a server's certificate chain is checked: the X.509 profile, the order of the checks, path building, every refusal, the CA store file format, the wall clock, the tests (x509-limbo) |
