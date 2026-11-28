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

## The repository at decodesoft.pl

DeSo OS installs from one repository: DecodeSoft's, `https://decodesoft.pl/deso/` (`/etc/desopkg/repo`). Every normal
image trusts one key, `decodesoft-2026-01` – its public half is `user/etc/desopkg/keys` in this project; the private
half exists only on DecodeSoft's build machine. Anyone who builds DeSo OS from this project gets the same key and the
same repository: `desopkg install` works without any setup.

What the server holds (a static folder – no program runs on it):

```
deso/stable/x86_64/index                      the list of packages: name, version, size, SHA-256, dependencies
deso/stable/x86_64/index.sig                  its signature (ECDSA P-256, key decodesoft-2026-01)
deso/stable/x86_64/packages/<name>-<version>.pkg
```

### Publishing (DecodeSoft)

1. **The key – once.** `tools/deso-repo.sh key`: the private key `~/.deso-keys/decodesoft-2026-01.pem` (mode 600) and
   its public half into `user/etc/desopkg/keys`. Back the private key up off line (a second stick). Never copy it into
   the project, onto the server or into an image. An existing key is never replaced: systems that trust it would
   refuse an index signed with a new one.
2. **The packages and the index.** `tools/deso-repo.sh build` builds the packages with the SDK, packs them, signs the
   index (valid 30 days) and checks it again – into `~/Pulpit/deso-repo/deso/stable/x86_64/`. The serial is the UTC
   time `YYYYMMDDHHMM`, but always above the index already there (two builds in one minute, or a clock behind it), so
   a system that took the last upload takes the next one. Only `stable/x86_64` is replaced, and only when it holds
   nothing but the script's own files: the index already there must carry a good signature and its packages must match
   it; a damaged index, a missing signature or any other file stops the build with the reason and the file names, and
   nothing is changed. The new files are built and checked in `x86_64.new`, then swapped in by two renames
   (`x86_64` → `x86_64.old`, `x86_64.new` → `x86_64`); if that is interrupted, the next `build` puts `x86_64.old`
   back first. Other folders and files in `deso/` are never touched.
3. **Upload.** The folder `stable` into `deso/` at the top of the site (`public_html/deso/stable/…`). Check that
   `https://decodesoft.pl/deso/stable/x86_64/index` opens and starts with `format=1`.
4. **Again within 30 days.** An expired index is refused by every system: run `build` and upload again before then –
   also when nothing changed (a new serial, a new date).

A new program or a new version: its package is added to `tools/deso-repo.sh build` (the source with `sdk/deso-build.sh`,
a `desopkg.meta` with `name=`, `version=`, `summary=`, optional `depends=` / `conflicts=`, the program in `bin/`, data
in `share/`), then steps 2–3. Old versions may stay in the index – `desopkg install name=version` can go back to them.
A version once published is never changed: a fix gets a new version number.

### A repository of your own (a fork)

Someone who builds DeSo OS with their own programs makes their own key and points the system at their own server:

1. `tools/deso-repo.sh key` in their copy of the project – their key replaces DecodeSoft's in `user/etc/desopkg/keys`.
2. `user/etc/desopkg/repo`: `url=` their server (`https://<host>/<path>/`), `repo=` their name.
3. Their packages: `tools/desopkg.py pack DIR -o <name>-<version>.pkg` for each, all into
   `deso/stable/x86_64/packages/`, then
   `tools/desopkg.py index deso/stable/x86_64 --serial N --key ~/.deso-keys/<key>.pem --keyid <id> --repo <name>`.
4. Upload `deso/`, build the image (`./make-usb.sh`).

Their systems then trust only their key: DecodeSoft's packages no longer install there (one repository per system).

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
| PKG TEST (`tests/pkg-test.sh`, QEMU) | part 1: desopkg against `tests/repo-stub.py` – install, run, update, downgrade, dependencies, refusals, remove, verify, reinstall, refused indexes and transfers, no memory, a big package; part 2: desopkg killed at every crash point (K1–K10), the lock, the shell against `gc`, damaged indexes and generations; four power losses (QEMU killed at K2h, K6, K7h, K9); the normal image holds nothing of the self-test image |
| `tests/pkg-test.sh --mutants` (QEMU, TCG) | six builds, each with one check of desopkg switched off (signature, serial, expiry, paths, directories before the generation, the generation's hash) – each must fail the short sequence a normal desopkg passes |

The self-test image (desopkg and sh built with `--cfg selftest`) trusts the test CA
`/etc/desopkg/ca` and the self-test time instead of NTS, and has the tests' switches in `/tmp`:
`desopkg-crash` (stop at a crash point as if killed, or hang there for a power loss),
`desopkg-nomem`, `sh-pause` (the shell waits between finding a package program and starting it);
none of that exists in a normal image (checked by PKG TEST).

PKG TEST stops QEMU with `kill -9`: it checks that desopkg recovers from the machine stopping at
any point, not that data in a disk cache is lost – everything QEMU already wrote reaches the
image. Lost unflushed writes and failed writes / flushes are tested by DeSoFS itself (DESOFS TEST
15–18, a crash after every write). A real power cut on hardware has not been tested.

### Crash points

| Point | Where | What the next start finds |
|---|---|---|
| K1 | right after the lock | nothing changed; the dead one's lock is taken over |
| K2 / K2h / K3 | before / in the middle of / after writing `index/<serial>` | the previous index; a half-written file does not count; a whole one counts (valid by its signature) |
| K4, K5 | before the download / after the checks | nothing on the disk |
| K6 | in the middle of a version directory | a directory without `package` – nothing points to it, `gc` removes it |
| K7 | before `gen/<m>` | a complete directory nothing points to – `gc` removes it |
| K7h | in the middle of `gen/<m>` | the file is not valid: the old generation is in force; it stays until a newer one exists |
| K8 | after `gen/<m>` | the new generation is in force whole |
| K9 | inside `gc` (after the generation files) | the new generation; the next command finishes `gc` |
| K10 | before giving the lock back | everything done; the lock is taken over |
