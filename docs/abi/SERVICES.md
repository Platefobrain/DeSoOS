# Service protocols

Ordinary programs talk to user-space services over channels ([SYSCALLS.md](SYSCALLS.md): `chan_send` /
`chan_recv`, a message of at most `MSG_MAX` bytes and `MSG_HANDLES` handles). Each service protocol here has **its
own version**, apart from the ABI: a change to netd raises "net", not the ABI, and the ELF note says nothing about
services. SERVICES TEST checks the versions and the rules below in QEMU (`[SERVICES TEST]`).

| Protocol | Version | Who serves it | How a program reaches it |
|---|---|---|---|
| `svc` – the service manager | 1.0 | init | the channel in slot 3 (`SVC`), when the starter gave one |
| `net` – the network | 1.0 | netd, one per card (`net0`, `net1`, …) | `connect net0` on the `svc` channel |
| `time` – the clock | 1.0 | the kernel | system calls `SYS_TIME` / `SYS_TIME_BOUND` – no channel |

Internal, without a promise (they may change in any version): the shell's program channel and administration
requests (`kill`), netd's administrator requests (`set`, `dns`, `renew`, `dhcp`, `rxrestart`), the time service's
channel to netd (timekeeper), usbd / blkd, `sysctl`, edud / echod (test services).

## Versions – the rules

1. A new request `version` answers `<protocol> <major>.<minor>` – exactly that text: the protocol's name, one space,
   two decimal numbers 0–65535 without leading zeros and a dot between them (netd adds its usual `\n`).
2. Within one major version a protocol only adds: an existing request and its answer never change; new abilities
   come as new requests (the minor goes up). A changed answer is a new major.
3. A service from before `version` answers it as any unknown request (below) – a client takes that as **1.0**.
4. A client never panics on an answer: an answer that is not what the protocol says is an error of that request
   (`libdeso`: `ERROR_IO`), a channel closed half-way is `ERROR_CLOSED`, no answer within its own limit is
   `ERROR_TIMED_OUT`.

`libdeso`: `svc_version()` / `svc_version_via(svc, timeout_ms)`, `net_version(connection, timeout_ms)`,
`parse_version(answer, protocol)` – each gives `(major, minor)`.

## svc 1.0 – the service manager (init)

Every request is one message on the `svc` channel carrying **exactly one handle** – the channel end the answer goes
to; a message without a handle (or with more) is dropped. The `svc` end a program holds can only send (`R_SEND`,
`R_DUP`).

| Request (text, no `\n`) | Answer | Then |
|---|---|---|
| `version` | `svc 1.0` on the reply handle | the reply handle is closed |
| `connect NAME` | none: the handle is passed to the service `NAME` as the client's channel end (netd gets with it the text `net0 client [listen] [udp]` – the rights) | an unknown or stopped service, or a right the channel lacks: the handle is closed, the first operation on the client's end gives `ERROR_CLOSED` |
| `narrow TOKENS` | `narrowed` + one handle: a new `svc` channel that only connects to the network – `TOKENS` from `net`, `listen`, `udp`; never more than the channel asking has | the reply handle is closed; nothing to give: closed without an answer |
| `list` | lines `NAME STATE pid N restarts N (PROGRAM)\n` | the reply handle is closed |
| anything else – an unknown request, or a known one with extra words (`version 2`) | `unknown request` | the reply handle is closed; the `svc` channel stays as it was |

A manager from before `version` (DeSo OS before v0.81) closed the reply handle without an answer for any unknown
request: `svc_version_via` takes "closed without an answer, while the `svc` channel itself is still open" as 1.0 (it
checks the channel with an empty message without a handle, which every manager drops).

Limits: a request at most 128 bytes (longer: dropped, its handles closed); init answers at once, so a client's own
limit of a few seconds (`svc_version`: 2 s) is plenty. When init's end of the channel is gone, `chan_send` gives
`ERROR_CLOSED`.

## net 1.0 – the network (netd)

The channel end from `connect net0` is one connection. Every request is one message of text (spaces separate the
words); every answer is one message of one or more lines, each ending with `\n`. One request at a time per
connection – a request while one runs gets `netd: busy - one request at a time per connection`. A program may hold
many connections.

| Request | Answer |
|---|---|
| `version` | `net 1.0\n` |
| `status` | the first line `NAME: CHIP (VVVV:DDDD), MAC xx:xx:xx:xx:xx:xx, link up\|down`, then more lines for people |
| `resolve NAME` | `NAME is a.b.c.d[, a.b.c.d…] (…)\n`; any other line is a failure (its text for people) |
| `ping HOST [COUNT]` | one line per answer, as they come, a summary, then `ping-end` |
| `arp a.b.c.d` | `arp a.b.c.d is-at xx:xx:xx:xx:xx:xx in N ms` or `arp: …` |
| `tcp HOST PORT` | `connected a.b.c.d:port from a.b.c.d:port in N ms` – from then on the connection **is the socket**: every message to netd is data to send, every message from netd is received data; closing the channel closes the connection; the peer's end is `ERROR_CLOSED`; a reset or timeout sends one empty message first (data never comes as an empty message). A failure: a line starting `tcp: ` and the connection stays a request channel |
| `udp HOST PORT` (the `udp` right) | `udp a.b.c.d:port from a.b.c.d:port` – from then on every message is one datagram (at most `UDP_MAX` = 1472 bytes) to / from exactly that peer. A failure: a line starting `udp: ` |
| `listen PORT` (the `listen` right; 0 = any) | `listening on port N`; each accepted connection then comes as a message `accepted a.b.c.d:port to port N` carrying a new channel – that connection's socket (as after `tcp`) |
| anything else – an unknown request, or a known one with extra words (`status x`) | `netd: unknown request "…" (…list of requests…)\n`; the connection stays usable |
| an administrator request without the right | `netd: "set" is an administrator request - not allowed for this program\n` |

The text of lines "for people" (the rest of `status`, the reasons after `tcp: ` …) is not part of the protocol – a
program relies on the forms in the table. netd from before `version` answers it with `netd: unknown request` – 1.0.
netd closing the connection (it ended – init restarts it) is `ERROR_CLOSED` on the next operation; a client
reconnects with `connect net0`.

## time 1.0 – the clock

Not a channel: `SYS_TIME` (`time_unix()` – the seconds since 1970 and whether the clock is trusted) and
`SYS_TIME_BOUND` (`time_bound()` – the lowest time the system can prove, the last known good time) are system calls
of ABI 1.0 ([SYSCALLS.md](SYSCALLS.md)). The time service (timekeeper) that sets the clock (NTS / NTP through netd) is
internal; its version is the version of these calls.

## Tests

SERVICES TEST runs `/bin/prototest` through the real init (`init test /bin/prototest`, net0 on the test card):

| Case | Expected |
|---|---|
| an old client → the new services | `list`, `connect net0`, `status` as before |
| a new client → the new services | `svc 1.0`, `net 1.0`; the connection still works after `version` |
| an unknown request | `svc`: `unknown request`, the reply handle closed, the `svc` channel alive; `net`: `netd: unknown request "bogus"`, the connection alive |
| an unknown field | `version 2` → `unknown request`; `connect net0 extra` → closed without an answer; `status extra` → `netd: unknown request`; the channels alive |
| a new client → an old service (a fake) | `svc`: the reply closed without an answer → 1.0; `net`: `netd: unknown request` → 1.0 |
| newer services (fakes) | `svc 1.7`, `net 1.3`, `2.0` read as they are – the client decides |
| garbage, `svc 01.0`, `net 1.x`, an answer with a handle | `ERROR_IO` (the handle closed), no panic |
| the service closes the channel half-way | `ERROR_CLOSED` |
| the service never answers | `ERROR_TIMED_OUT` after the client's limit |

## Compared with other systems

| | Service protocols | Versions |
|---|---|---|
| Linux | D-Bus interfaces, sockets with their own formats | per interface (`org.foo.Bar1`), none on most sockets |
| Windows | RPC / COM interfaces | interface GUIDs; a new version = a new interface |
| Redox | schemes (`tcp:`, `udp:`) – paths and `read` / `write` | none |
| **DeSo OS** | channels + text requests, handles in messages | `version` per protocol; only additions within a major; old service = 1.0 |
