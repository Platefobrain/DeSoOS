# The SDK of ABI 1.0 – a frozen copy

This directory is the DeSo OS SDK exactly as it was when ABI 1.0 was released (v0.81.0): `deso-build.sh`, `libdeso`,
the template, and `programs/` – programs written against it. It is never edited and never refreshed from the
current `sdk/`; `sdk/compat/abi-1.0.lock` holds the SHA-256 of every file and of the whole, and
`tools/abigen.py --check` refuses any change (a file changed, added or removed).

`tests/sdk-test.sh` copies this directory alone into an empty temporary directory, builds `programs/compat10.rs` with
this copy's own `deso-build.sh` and runs it on the current system (SDK TEST 2/2): what a program built with the 1.0
SDK relies on – the start, system calls, handles, files, time and the service protocols – must keep working on every
later DeSo OS with ABI 1.x. Only a deliberate ABI 2.0 may end that, with its own `compat/abi-2.0` and a clear refusal
of 1.0 programs.
