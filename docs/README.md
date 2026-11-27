# DeSo OS documentation

The documentation of the whole system. Change history is in `../CHANGELOG.md`; each main code folder has its own
`README.md` (what it holds and where to start reading).

| Document | What it describes |
|---|---|
| `ARCHITECTURE.md` | How DeSo OS is built and how its parts work together: boot, memory, scheduler, syscalls and handles, IPC, user-space services and drivers, permissions (DCP), files, DeSoFS, network, USB, cryptography, certificates |
| `RELEASE.md` | One report per release: tests passed (QEMU TCG / KVM), real hardware, performance against the previous release, known problems; at the top – the current limitations of the system |
| `abi/README.md` | The DeSo OS ABI: what a program may rely on (system calls, handles and rights, constants, the loader's limits), the rules for changing it, the locks and the tests |
| `abi/STARTUP.md` | How a program starts and ends (part of ABI 1.0): the file, the first instruction, the stack, the slots, exit codes |
| `abi/SERVICES.md` | The service protocols with their own versions: `svc` (init's service manager), `net` (netd), `time` |
| `abi/SDK.md` | The SDK: a program built outside the repository (`sdk/`, `deso-build.sh`, the template) and put on `/disk/bin` |
| `abi/SYSCALLS.md` | Every system call and constant of the ABI – generated from `abi/abi.toml` |
| `pkg/FORMAT.md` | desopkg's file formats (v0.82): the package and its manifest, the signed index, the key store, the repository configuration, an accepted index, a generation; every refusal with its reason id; the test vectors |
| `desofs/README.md` | DeSoFS – DeSo OS's own copy-on-write file system: what it does, the `desofs` commands, where the code and the tests are |
| `desofs/FORMAT.md` | The DeSoFS on-disk format 1, byte by byte (closed specification) |
| `desocrypto/README.md` | DeSoCrypto – DeSo OS's own cryptographic library: what it has, who uses it, where the code and the tests are |
| `desocrypto/ALGORITHMS.md` | Every DeSoCrypto module and its API, the rules of the code (limits, key wiping, timing, signatures on public data only), AES-NI / PCLMULQDQ and the kernel, the tests, speed |
| `desotls/README.md` | DeSoTLS – DeSo OS's own TLS library: what it does, where things are |
| `desotls/HANDSHAKE.md` | The TLS 1.3 connection: the handshake, every refusal (HelloRetryRequest table, alerts), the key schedule, records and their limits, KeyUpdate, the end of a connection, `netget https://` (HTTP/1.1 framing, chunked, trailers, the end after an answer, exit codes), the tests (RFC 8448, OpenSSL, a man in the middle) |
| `time/README.md` | Time in DeSo OS: the RTC, the wall clock, plausibility, the sources and how far each is trusted, the tools |
| `time/LKG.md` | The last known good time: what raises it, the record in `/disk/.deso/lkg`, atomic saving, the order of the clock's reasons (7, 8), `/.deso` protected, threats, LKG TEST |
| `time/NTS.md` | NTS (RFC 8915): NTS-KE over TLS 1.3, the records accepted, keys from the exporter, NTP with NTS (fields, placeholders, the order of the checks), limits, the tests against rustls |
| `time/TIMEKEEPER.md` | The time service (`/bin/timekeeper`): the built-in servers and operators, a round, the bootstrap and the second check of the kept chain, the quorum and the envelope, `SYS_TIME_SET` / `SYS_TIME_BOUND`, recovery from an unreadable LKG, what the kernel cannot check, NTS TEST |
| `desotls/CERTIFICATES.md` | How a server's certificate chain is checked: the X.509 profile, the order of the checks, path building, every refusal, the CA store file format, the wall clock, the tests (x509-limbo) |
