// Network self-tests – the network card and the /bin/netd user-space service (only
// in builds with --cfg selftest).  QEMU: `-device e1000e` with `-netdev user`
// (a virtual router 10.0.2.2 answering ARP) – test.sh.  The test runs the real
// init (`init test /bin/nettest`); the kernel then checks that the card and
// everything netd held came back.

use alloc::string::String;

use super::*;
use crate::drivers::pci;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[NET TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

fn run(path: &str, args: &[&str], ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    wait_exit(id, ms)
}

fn wait_exit(id: TaskId, ms: u64) -> Option<(ExitKind, String)> {
    let end = crate::time::ticks() + ms;
    while sched::task_info(id).is_some() {
        if crate::time::ticks() > end {
            let _ = sched::request_exit(id);
            return None;
        }
        crate::time::sleep_ms(5);
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn run_init(program: &str, ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", program], "/", &opts).ok()?;
    wait_exit(id, ms)
}

pub fn self_test() {
    serial_println!("[NET TEST] Starting network tests (card driver in the netd service)...");
    crate::selftest::begin();
    let nic = pci::devices().iter().position(|d| d.class == 0x02 && d.subclass == 0x00);
    check!(nic.is_some(), "no network card (QEMU needs -device e1000e)");
    let nic = nic.unwrap();
    let dev = &pci::devices()[nic];
    check!(pci::owner(nic) == pci::OWNER_FREE, "network card {} must not be owned by a kernel driver", dev.address);

    // 1. Packet parsers without hardware – valid frames, malicious cases, 20 000
    // mutations; panic = process exit = FAIL.
    let r = run("/bin/netparse", &["netparse"], 60_000);
    check!(r.is_some(), "netparse did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("netparse:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "netparse: {:?} {:?}", kind, out.trim());
    serial_println!("[NET TEST] 1/6 packet parsers on hostile frames (no hardware): {} PASS", line);

    // 2. DHCP client state machine with a simulated clock: a day of lease,
    // lost answers, renewal, rebinding, NAK, lease end.
    let r = run("/bin/dhcptest", &["dhcptest"], 60_000);
    check!(r.is_some(), "dhcptest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("dhcptest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "dhcptest: {:?} {:?}", kind, out.trim());
    serial_println!("[NET TEST] 2/6 DHCP client with a simulated clock (no network): {} PASS", line);

    // 3. DNS answers without a network: names, malicious answers, cache, mutations.
    let r = run("/bin/dnstest", &["dnstest"], 60_000);
    check!(r.is_some(), "dnstest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("dnstest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "dnstest: {:?} {:?}", kind, out.trim());
    serial_println!("[NET TEST] 3/6 DNS resolver on hostile answers (no network): {} PASS", line);

    // 4. TCP connection state machine against a simulated peer.
    let r = run("/bin/tcptest", &["tcptest"], 60_000);
    check!(r.is_some(), "tcptest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("tcptest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "tcptest: {:?} {:?}", kind, out.trim());
    serial_println!("[NET TEST] 4/6 TCP with a simulated peer and clock (no network): {} PASS", line);

    // 5. init finds the card by class and starts net0; frames out and in (ARP to
    // QEMU's router), counters, kill + restart by init.
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let free0 = crate::selftest::settled_free_frames();
    // The heap returns pages lazily (as in the stress test) – its growth is not a leak.
    let heap0 = crate::memory::heap::mapped_bytes() as u64;
    let r = run_init("/bin/nettest", 120_000);
    check!(r.is_some(), "init test /bin/nettest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("nettest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "nettest: {:?} {:?}", kind, out.trim());
    check!(out.contains("= network card") && out.contains("init: service net0 started"), "init did not start net0: {:?}", out.trim());
    check!(out.contains("net0: address 10.0.2.15/24 from DHCP server 10.0.2.2 in "), "netd did not report its DHCP address: {:?}", out.trim());
    serial_println!("[NET TEST] 5/6 init finds the card by class and starts net0 (netd): reset, MAC, rx/tx rings, MSI; DHCP address and renewal, DNS against tests/dns-stub.py, TCP and netget against tests/http-stub.py, user and narrowed rights, listen + loopback, sandboxed netweb reached from the host, concurrent clients, ARP and ping to 10.0.2.2, unreachable address; killed netd restarted by init: {} PASS", line);

    // 6. After init stopped the services: the card is free, bus mastering off,
    // MSI vector and DMA frames returned.
    check!(pci::owner(nic) == pci::OWNER_FREE, "network card still claimed after netd ended");
    check!(dev.command() & pci::CMD_BUS_MASTER == 0, "network card bus mastering still on after netd ended");
    check!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked by netd");
    // init also ran usb0 – its USB disks (and their DMA buffers) go away a moment
    // after usbd exits (the usb-disks monitor).
    let end = crate::time::ticks() + 5_000;
    while super::ublk::count() != 0 && crate::time::ticks() < end {
        crate::time::sleep_ms(5);
    }
    let free1 = crate::selftest::settled_free_frames();
    let heap = (crate::memory::heap::mapped_bytes() as u64).saturating_sub(heap0) / 4096;
    check!(free1 + heap >= free0, "frames leaked by netd ({} -> {}, heap +{} pages)", free0, free1, heap);
    serial_println!("[NET TEST] 6/6 after netd: card free, bus mastering off, MSI vector and DMA buffers returned (frames {} -> {}, heap +{} pages) PASS", free0, free1, heap);

    serial_println!("[NET TEST] All network tests passed!");
    crate::selftest::pass();
}
