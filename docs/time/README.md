# Time in DeSo OS

How DeSo OS knows what time it is, how far it trusts that, and which sources may change it. The details of the
protocols are in `NTS.md` (this folder); the last known good time (LKG) – the lower bound kept on the system volume – in
`LKG.md`; the time service that sets the clock (`/bin/timekeeper`) in `TIMEKEEPER.md`.

## The clocks

| Clock | What it is | Who changes it |
|---|---|---|
| RTC (CMOS) | the hardware clock, read once at boot (kept in UTC – a Windows-style local-time RTC cannot be detected) | nobody: DeSo OS never writes it |
| the wall clock (syscall 59, `date`) | the RTC at boot + uptime + the time service's correction (one atomic value, ms) | only the time service (`SYS_TIME_SET`), to max(T, LKG); without it the RTC's clock, which under QEMU TCG drifts with uptime (seconds within minutes) |
| uptime / monotonic time | the LAPIC / TSC tick count since boot | nothing; timers, timeouts and the scheduler use only this |
| the build date | the lower bound everything starts from (minus 24 h for certificates) | a new image |
| the last known good time (LKG) | a lower bound kept in `/disk/.deso/lkg` (`LKG.md`); without a system volume in memory only | only the time service: ⌊T − U − 2 s⌋ of a time agreed by two operators – never lowered |

**Plausible** (syscall 59's verdict) is a heuristic over the RTC: battery (VRT), readings that agree, valid fields, not
after 2099, the LKG file readable (reason 8), not before the build date (5), not before the LKG (7, margin 0 s). Once the
time service has set the clock, the RTC's own reasons (1–6) no longer count – 8 and 7 still do. https (`netget`) and
`nettime --nts` refuse when the clock is not plausible – a certificate cannot be checked without a time. Only the time
service has a way out (a bootstrap with the LKG or the build date as the bound, then the full check of the same chain
over the measured time – `TIMEKEEPER.md`).

## Sources and trust

| Source | Authenticated? | What it may do |
|---|---|---|
| RTC | no | gives the boot time; judged by the plausibility heuristic |
| plain NTP (`nettime`, v0.78) | no – anyone on the path can answer | shows the difference, changes nothing |
| NTS (`nettime --nts`, v0.79) | yes – the answer comes from the holder of keys agreed over TLS 1.3 with a checked certificate | shows the difference, changes nothing |
| NTS through the time service (`/bin/timekeeper`, v0.79) | yes, plus at least two operators agreeing (servers of the built-in list) | the only source that raises the LKG and corrects the wall clock |
| certificate dates, HTTP `Date`, a program's claim | – | nothing |

NTS proves **where** an answer came from, not that the server's time is right: an authenticated server can still be
wrong. That is why the time service needs two operators that agree and raises the lower bound only by what is certain
(intervals, the envelope, a 2 s margin, never down – `TIMEKEEPER.md`).

## Tools

- `date` (and sysinfo `date`) – the wall clock, whether it is plausible, the last known good time with its source
  and file state, and when the time service last set the clock (T ± U, from how many operators, the correction).
- the `time` service (`services`, `dcp`) – `/bin/timekeeper`: at start and every hour; its lines on the console.
- `nettime [-t ms] [server[:port] ...]` – plain NTP, read only (`../ARCHITECTURE.md`, "Time from the network").
- `nettime --nts [--anchor ca.pem] [server[:port] ...]` – NTS: NTS-KE to port 4460, then NTP with NTS; read only
  (`NTS.md`).

## Compared with other systems

| | Authenticated time | Lower bound | Sets the clock from |
|---|---|---|---|
| Linux (systemd-timesyncd / chrony) | chrony: NTS optional | systemd: build time + a file | every NTP sync (timesyncd: unauthenticated) |
| Windows (w32time) | no NTS (MS-SNTP inside a domain) | Secure Time Seeding from TLS | NTP / SNTP |
| RedoxOS | no NTP client found in the base system | – | – |
| **DeSo OS** | NTS (v0.79) – plain NTP only shows | build date + LKG on the system volume | only NTS through the time service, two of three operators agreeing |
