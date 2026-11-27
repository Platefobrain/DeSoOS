# desopkg – programs from the internet

`/bin/desopkg` (v0.82) installs, updates, removes and checks programs from DecodeSoft's repository
on the writable `/disk`. The system itself (kernel, `/bin`, `/etc`) is changed only by
`make-usb.sh`. File formats, byte by byte: `FORMAT.md`.

## Commands

| Command | What it does |
|---|---|
| `desopkg refresh` | fetches and checks the signed index |
| `desopkg install <name>…` | the newest version with its dependencies |
| `desopkg install <name>=<version>` | exactly that version – also an older one (a downgrade warning and `y/N`) |
| `desopkg update` | everything with a newer version (always refreshes the index first) |
| `desopkg update <name>…` | only the named packages (and what their new versions need) |
| `desopkg remove <name>…` | removes; dependencies nobody needs any more are listed as "no longer needed" |
| `desopkg reinstall <name>…` | the same version again, downloaded anew (repair after `verify`) |
| `desopkg list` | installed packages, why (explicit / dependency), newer versions available, the generation |
| `desopkg search <phrase>` | names and summaries in the accepted index |
| `desopkg info <name>` | installed and available versions, dependencies, size, programs |
| `desopkg verify [<name>]` | every installed file against its manifest: `OK`, `MISSING`, `MODIFIED`, `UNEXPECTED`, `SHADOWED`, `DAMAGED` |

`-y` answers the question itself. Exit codes: 0 OK, 1 usage, 2 refused (signature, rules,
dependencies), 3 network / time, 4 disk / lock / memory, 5 aborted by the user.

After `install`, a program is run by typing its name: the shell looks for a name in its
built-ins, `/bin`, `/disk/bin` and then the installed packages – a package never hides a system
name or a program copied to `/disk/bin`. A package program gets its full path as `argv[0]`, so it
finds its data in `../share/`.

## How a change is made

```
/disk/pkg/<package>/<version>-<16 hex>/bin/…, share/…, package    a version directory
/disk/pkg/gen/<n>                                                  generation n: the installed set
/disk/pkg/index/<serial>                                           an accepted index with its signature
```

1. The lock (`/tmp/desopkg.lock`), the current generation, the index (refreshed when there is
   none or it expired), the plan and `y/N`, the space.
2. Each new package is downloaded **into memory** (exactly the size the signed index gives, its
   SHA-256, every rule of `FORMAT.md` §3), then written to a new directory next to the old ones –
   the `package` file last.
3. A new file `gen/<m>` names the new set. **The current generation is the highest one that is
   valid** (like the DeSoFS superblock): until `gen/<m>` is whole, the old one is in force.
4. `gc`: everything nothing points to is removed (the previous generation and its directories stay
   as a spare, and the two newest indexes).

A crash or a power loss at any point leaves the old or the new generation whole; the next desopkg
command finishes the clean-up. There is no journal and nothing to repair.

## Trust

The index is signed (ECDSA P-256, key ids in `/etc/desopkg/keys`, low-S, a domain line), valid at
most 30 days and never older than the accepted one (serial); every package is pinned by its size
and SHA-256 in the index. HTTPS goes to exactly the host of `/etc/desopkg/repo` (no redirects), the
certificates are checked against `/etc/certs/roots`, and nothing is sent before the time service
(NTS) has set the clock. What this does not protect against (a local program with access to
`/disk`): `FORMAT.md` §8.

## Code

| Where | What |
|---|---|
| `user/bin/desopkg.rs` | the commands, the lock, downloads, the change |
| `user/lib/pkgfmt.rs` | every file format (`FORMAT.md`) |
| `user/lib/pkgstate.rs` | the state on the disk: the current generation, accepted indexes, `gc` – shared with `sh` |
| `user/lib/pkgsolve.rs` | dependencies (pure code) |
| `user/lib/fetch.rs` | the HTTP(S) client shared with `netget` |
| `user/lib/cmdnames.rs` | the names the system keeps (shared with `sh`) |
| `tools/desopkg.py` | on the host: `pack`, `index` (signing), `keys`, `check`, the test vectors |

## Tests

| Test | What |
|---|---|
| PKG HOST TEST (`tests/test.sh`) | `tools/desopkg.py --test`, Rust = Python on the formats' vectors, the solver's table |
| PKG FORMAT TEST (`tests/test.sh`, QEMU) | the vectors judged by `pkgfmt.rs` in user space, `/etc/desopkg`, every `/bin` program through `check_program` |
| PKG TEST (`tests/pkg-test.sh`, QEMU) | desopkg against `tests/repo-stub.py`: install, run, update, downgrade, dependencies, refusals, remove, verify, reinstall, refused indexes and transfers, no memory, a big package; the normal image holds nothing of the self-test image |

The self-test image (desopkg built with `--cfg selftest`) trusts the test CA `/etc/desopkg/ca` and
the self-test time instead of NTS, and has crash points for the tests; none of that exists in a
normal image (checked by PKG TEST).
