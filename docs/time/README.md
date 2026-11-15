# Time in DeSoOS

How DeSoOS knows what time it is, how far it trusts that, and which sources may change it. The details of the
protocols are in `NTS.md` (this folder); the last known good time (LKG) – the lower bound kept on the system volume – in
`LKG.md`.

## The clocks

| Clock | What it is | Who changes it |
|---|---|---|
| RTC (CMOS) | the hardware clock, read once at boot (kept in UTC – a Windows-style local-time RTC cannot be detected) | nobody: DeSoOS never writes it |
| the wall clock (syscall 59, `date`) | the RTC at boot + uptime, whole seconds; under QEMU TCG it drifts with uptime (seconds within minutes) | nothing yet – the time service (stage D) will keep a correction for it |
| uptime / monotonic time | the LAPIC / TSC tick count since boot | nothing; timers, timeouts and the scheduler use only this |
| the build date | the lower bound everything starts from (minus 24 h for certificates) | a new image |
| the last known good time (LKG) | a lower bound kept in `/disk/.desoos/lkg` (`LKG.md`); without a system volume in memory only | only an authenticated time (stage D) – never lowered |

**Plausible** (syscall 59's verdict) is a heuristic over the RTC: battery (VRT), readings that agree, valid fields, not
after 2099, the LKG file readable (reason 8), not before the build date (5), not before the LKG (7, margin 0 s). https
(`netget`) and NTS-KE refuse when the clock is not plausible – a certificate cannot be checked without a time.

## Sources and trust

| Source | Authenticated? | What it may do |
|---|---|---|
| RTC | no | gives the boot time; judged by the plausibility heuristic |
| plain NTP (`nettime`, v0.78) | no – anyone on the path can answer | shows the difference, changes nothing |
| NTS (`nettime --nts`, v0.79 stage B) | yes – the answer comes from the holder of keys agreed over TLS 1.3 with a checked certificate | shows the difference, changes nothing (yet) |
| NTS through the time service (v0.79 stage D) | yes, plus at least two independent operators agreeing | the only source that will raise the LKG and correct the wall clock |
| certificate dates, HTTP `Date`, a program's claim | – | nothing |

NTS proves **where** an answer came from, not that the server's time is right: an authenticated server can still be
wrong. That is why stage D needs two operators that agree and raises the lower bound only by what is certain
(`V079` plan: intervals, margin, never down).

## Tools

- `date` (and sysinfo `date`) – the wall clock, whether it is plausible, and the last known good time with its source
  and file state.
- `nettime [-t ms] [server[:port] ...]` – plain NTP, read only (`../ARCHITECTURE.md`, "Time from the network").
- `nettime --nts [--anchor ca.pem] [server[:port] ...]` – NTS: NTS-KE to port 4460, then NTP with NTS; read only
  (`NTS.md`).

## Compared with other systems

| | Authenticated time | Lower bound | Sets the clock from |
|---|---|---|---|
| Linux (systemd-timesyncd / chrony) | chrony: NTS optional | systemd: build time + a file | every NTP sync (timesyncd: unauthenticated) |
| Windows (w32time) | no NTS (MS-SNTP inside a domain) | Secure Time Seeding from TLS | NTP / SNTP |
| RedoxOS | no NTP client found in the base system | – | – |
| **DeSoOS** | NTS (v0.79) – plain NTP only shows | build date + LKG on the system volume | nothing yet; from stage D only NTS through the time service |
