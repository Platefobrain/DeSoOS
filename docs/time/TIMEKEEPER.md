# The time service (`/bin/timekeeper`)

The only program that may set the wall clock and raise the last known good time (v0.79 stage D). It is init's `time`
service (`user/etc/services/time.svc`): it asks NTS servers of three different operators, and when at least two of
them agree it gives the kernel the time with `SYS_TIME_SET`. Everything else in DeSo OS only reads the time.

## The servers

The list is built into the program – one entry per server, each with its operator:

| Server | NTS-KE port | operator_id |
|---|---|---|
| `time.cloudflare.com` | 4460 | `cloudflare` |
| `nts.netnod.se` | 4460 | `netnod` |
| `ptbtime1.ptb.de` | 4460 | `ptb` |

- A server is an **entry of the list**, not a name or an address. Its vote counts by the entry's `operator_id`;
  nothing a server sends changes that – not its certificate and not NTS-KE's Server / Port Negotiation (a server that
  sends NTP elsewhere is still its own entry's vote).
- No argument, message or file adds a server. `nettime --nts host` is another program: it has no right to set
  anything, never bootstraps and only shows the result.
- Different operators are different organisations, not proof of independent infrastructure: a common network
  provider, a common upstream (GNSS) or a common CA may exist. The quorum protects against one wrong or taken-over
  source, not against a common cause.

## What the service gets (time.svc)

| Grant | Slot | What for |
|---|---|---|
| `grant settime` | 7 | the SETTIME handle – `SYS_TIME_SET` (only init gets it from the kernel; it cannot be sent in a message) |
| `grant net` | 3 | a service channel of its own that may only open network connections and UDP sockets |
| `grant roots` | 8 | the trusted CA store (`/etc/certs/roots`) opened for reading |
| `files none` | – | no file access by path |
| `tests off` | – | not started by `init test` (the kernel self-tests start it themselves, with a test list) |

## A round

At start, then every hour; after a round that set nothing, again when the next server's NTS-KE backoff allows, at the
latest in a minute.

1. **The state.** `SYS_TIME_BOUND` gives the bound B and the state of the LKG file; syscall 59 says whether the clock
   is plausible.
2. **NTS-KE** (`user/lib/ntske.rs`) with every server that has no cookies left, if its backoff allows: 10 s after a
   failure, then ×1.5, at most 5 days; only an NTS-KE followed by a good NTS answer resets it.
   - The clock plausible: the ordinary certificate check at its time.
   - Not plausible – a **bootstrap**: every certificate of the chain needs only `notAfter >= B` (`notBefore` is not
     looked at), and DeSoTLS keeps the chain that server sent in that handshake (`PeerChain`).
3. **NTS queries** (`user/lib/nts.rs`) to every server at once, at most two queries of 2 s each; an answer counts only
   authenticated. Each good answer is an interval T ± U (`user/lib/timesync.rs`):
   - δ = (T4 − T1) − (T3 − T2); −1 ms counts as 0, less than that, T4 < T1 or more than 10 s – refused;
   - T = T3 + δ/2;
   - U = ⌈δ/2⌉ + ⌈root delay/2⌉ + ⌈root dispersion⌉ + 1000 ms.
4. **The second check** (bootstrap only): the kept chain – the same bytes, not a result and not a certificate fetched
   again – is checked once more, fully (signatures, CAs and basicConstraints, pathLen, key usages, the name from the
   list, every certificate and the anchor valid over the whole [T − U, T + U] of that server's own answer, widened
   outwards to whole seconds). A failure wipes that server's keys, cookies and chain; it has no vote.
5. **The quorum** (`timesync::quorum`): one vote per operator; a group of at least two whose intervals, each widened
   by 1 s on both sides, meet; the largest such group wins; two different groups of that size (A~B, B~C, A≁C) –
   "ambiguous quorum", nothing is set. The final interval is the **envelope** of the members' own intervals:
   [min(T − U), max(T + U)], T its middle, U half its width.
6. **`SYS_TIME_SET(T, U, operators)`** – the kernel checks the numbers and the LKG and sets the clock (below).

## The kernel's side

`SYS_TIME_SET` (60) – SETTIME with WRITE needed:

1. servers 2 or 3, U ≤ 10 s, T − U not before the build date, T + U not after 2099, no overflow – otherwise
   `ERROR_INVALID_ARGUMENT`;
2. T + U below the LKG – `ERROR_NOT_PERMITTED` (the LKG never goes down);
3. L = ⌊T − U − 2 s⌋; L above the LKG – the LKG raised to L and saved (`LKG.md`);
4. **repair write**: the LKG file unreadable (reason 8) – every accepted call writes it anew with max(L, the LKG in
   memory), also when that is not higher; only a write that succeeds makes the file good; a failed one keeps reason 8
   and the next call tries again; a pending save (`NOT SAVED`) is retried by every call;
5. the wall clock set to max(T, LKG) – one atomic value, only the wall clock: the uptime, `sleep`, timeouts, timers and
   the scheduler never see the step; the RTC is never written. From then on the RTC's own reasons (1–6) no longer
   count; the LKG file (8) and the LKG (7) still do.

Every call is written to the kernel log (`[TIME] set by pid ...` / `[TIME] refused ...`), every refusal also to the
DCP audit (`dcp audit`). The result bits: 1 LKG raised, 2 file written, 4 the write was a repair, 8 LKG not saved.

`SYS_TIME_BOUND` (61) – no right needed, reads only. Exactly 40 bytes (`len` < 40 – `ERROR_INVALID_ARGUMENT`, nothing
written), one consistent picture under the same lock as `SYS_TIME_SET`:

| Offset | Field |
|---|---|
| 0 | B – the bootstrap bound, computed by the kernel (u64, s) |
| 8 | the LKG in memory (u64, s; 0 = none) |
| 16 | the build date (u64, s) |
| 24 | the LKG's source (u16: 0 none, 2 NTS, 3 self-test) |
| 26 | the file state (u16: 0 not read, 1 no volume, 2 no file, 3 good, 4 unreadable) |
| 28 | why unreadable (u16) |
| 30 | flags (u16: 1 recovery mode, 2 not saved, 4 the clock plausible) |
| 32 | 0 (8 bytes) |

## The bound B and recovery

| The LKG file | B |
|---|---|
| good | the LKG in memory (it is at least the file's value) |
| missing / no system volume | the LKG in memory if one was raised in this start, otherwise the build date |
| **unreadable (reason 8)** | **max(the LKG in memory, the build date)** – recovery mode |

The rule is the same max(LKG in memory, build date) in every row; recovery mode is only the name of the last row (the
file's own value is unknown, so only what is in memory and the build date remain). It is chosen by the file state, not
by the verdict's first reason (a dead RTC battery and a damaged file at once is still recovery). With a readable file
the build date never replaces the LKG: a certificate whose `notAfter` lies between the build date and the LKG is
refused.

Recovery is not a quiet reset: nothing changes by itself – the clock stays not plausible until an authenticated time
from two operators, after the second check, writes a new LKG. There is no manual "forget the LKG": anyone with a shell
could lower the bound with it. Without a network the clock stays not plausible and `date` says why.

## What the kernel cannot check

The kernel trusts the service's word that T came from NTS and from different operators – it cannot check either (the
service could call with `servers = 2` after one server). It enforces what it can: the right, the numbers, the LKG never
lower, the order of the writes. A fault in or a takeover of the time service means a wrong time within these rules.

## Tests – NTS TEST (39th suite)

1. `/bin/synctest`: the interval of one answer, refusals, the quorum and the envelope, a tie, one vote per operator,
   the backoff 10 / 15 / 22.5 s, the span of the second check, the kept chain (24 KiB, 8 certificates);
2. the kernel alone: the refused numbers, L raised and saved, never lower, the clock never below the LKG, the repair
   write with max(L, LKG in memory), a failed repair (reason 8 stays, retried), B, the clock stepped back and forth
   while two programs read it (each reading one clock or the other) and sleeps untouched;
3. the right: `timetest set` (no handle, another kind, SETTIME without WRITE, every number, an LKG lowered – all
   refused, nothing changed, all in the DCP audit), `timetest bound` (len 39 / 40 / 41 / 4096, NULL, a kernel
   address, unmapped, read-only, across the end of a mapping); timekeeper without SETTIME, or with a server as an
   argument – refused;
4. timekeeper against `tests/nts-server` with the clock plausible: two operators set the clock; one server, two that
   disagree, one operator twice, a tie, NTP sent to another entry's server – nothing; 1.8 s apart – U ≥ 0.9 s + their
   own;
5. recovery from a damaged LKG file: bootstrap with B = the build date, the second checks, two of three operators, the
   file written anew, reason 8 gone, read back the same;
6. the second check on the kept chain (bootstrap with the RTC "battery lost"): a server certificate not valid yet, a
   time after its CA expired, an intermediate that ends inside T ± U (valid at T itself), an intermediate expired at T
   – each thrown out; expired before B and a wrong name – refused in the first step;
7. the bound: reason 7 with a good file – B = the LKG, a chain ending before it refused, no recovery; reason 8 with a
   higher LKG in memory – B = that LKG, not the build date; the kernel refuses a time below the LKG.

RESTART TEST: the first start damages the LKG on `/disk` and the time service recovers it; the second start reads it
back at boot – good, NTS, no reason 8.

Mutations caught (14): B = the build date with a good file (reason 7); B = the build date with an unreadable file
while a higher LKG is in memory; a server given as an argument used; no repair write when L is not higher; the repair
write with L instead of max(L, LKG); a quorum of one in recovery; the second check skipped in recovery; the second
check on the first step's result instead of the chain; the second check at the single point T; another server's
chain in the second check; the operator taken from the host name; the kernel taking T + U below the LKG; the clock set
below the LKG; `SYS_TIME_BOUND` taking a buffer shorter than 40 bytes.

Test servers (`tests/nts-server`, rustls + RustCrypto): NTS-KE at 58600 + j with a chosen certificate (tests/tls:
`nts-good` with an intermediate, `nts-intshort` whose intermediate ends 2030-01-01, `future`, `expired`, `wrongname`,
`rsa`) and NTP at 58630 + j with a chosen time (the host's, shifted by 0.4 / 1.8 / 3 / 6 / 30 s, or fixed). The test
list exists only in the self-test image (`timekeeper test:<case>`).

## Compared with other systems

| | Authenticated | Who sets the clock | Agreement | Bootstrap without a clock |
|---|---|---|---|---|
| Linux (chrony with NTS) | yes, optional | chronyd (root) | source selection (intersection of intervals) | the certificate time check can be skipped until the first sync (`nocerttimecheck`) – no second check |
| Windows (w32time) | no NTS | w32time | – | Secure Time Seeding (TLS timestamps) |
| Android | NITZ / GNSS / NTP | system server | – | the build time |
| RedoxOS | – | – | – | – |
| **DeSo OS** | NTS only | the time service, with a kernel right; the kernel checks the numbers and the LKG | two of three operators, envelope | the LKG / build date as the bound, then the full check of the same chain over T ± U |
