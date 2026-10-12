// M19: samotesty usług w user space – czekanie na wiele uchwytów, urządzenia,
// przerwania, DMA, menedżer usług (tylko build z --cfg selftest).  Testy
// biegną w programach z /bin (prawdziwe syscalle z ring 3); kernel sprawdza
// kod wyjścia i wyjście.

use alloc::string::String;

use super::*;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[SVC TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

/// Program z /bin z przechwyconym wyjściem; (sposób zakończenia, wyjście).
fn run(path: &str, args: &[&str], ms: u64, hw_root: bool) -> Option<(ExitKind, String)> {
    run_ex(path, args, ms, hw_root, false)
}

/// Jak `run`; `sysctl` – także uchwyt SYSCTL (slot 4), jak prawdziwy init.
fn run_ex(path: &str, args: &[&str], ms: u64, hw_root: bool, sysctl: bool) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, hw_root, sysctl, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

pub fn self_test() {
    serial_println!("[SVC TEST] Starting user-space service tests (wait_many, devices, interrupts, DMA, edud service, service manager, measurement)...");
    crate::selftest::begin();
    let frames0 = crate::selftest::settled_free_frames();

    // 1. M19.b: wait_many – błędy listy, limit czasu, kanały i potoki (odczyt /
    // zapis / zamknięcie), pobudka od dziecka, serwer 4 klientów, pełna
    // kolejka, kill procesu czekającego w wait_many.
    let r = run("/bin/waittest", &["waittest"], 60_000, false);
    check!(r.is_some(), "waittest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "waittest: {:?} {:?}", kind, out.trim());
    serial_println!("[SVC TEST] 1/7 wait_many: errors, timeout, channels + pipes, wake-up, 4-client server, full queue, kill while waiting: {} PASS", out.trim());

    // 2. M19.c: HW_ROOT (tylko z jądra, bez praw kopiowania), dev_claim –
    // odmowa dla urządzeń jądra / dysków / grafiki / mostków, EBUSY; dev_map
    // rejestrów `edu` (UC, NX), prawa, przejęcie trzymane przez mapowanie,
    // kill procesu z zamapowanym urządzeniem.
    use crate::drivers::pci;
    let edu = pci::index_of(pci::Address { bus: 0, device: 6, function: 0 });
    check!(edu.is_some(), "no edu device at 00:06.0 (QEMU needs -device edu,addr=06)");
    let virtio = pci::devices().iter().position(|d| d.vendor == 0x1af4 && d.class == 0x01);
    check!(virtio.map(pci::owner) == Some(pci::OWNER_KERNEL), "virtio-blk must be owned by the kernel driver");
    let r = run("/bin/devtest", &["devtest"], 30_000, true);
    check!(r.is_some(), "devtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "devtest: {:?} {:?}", kind, out.trim());
    check!(pci::owner(edu.unwrap()) == pci::OWNER_FREE, "edu still claimed after devtest");
    serial_println!("[SVC TEST] 2/7 devices: HW_ROOT only from the kernel, dev_claim refuses kernel/disk/display/bridge devices, EBUSY, edu registers via dev_map (UC, NX), claim held by the mapping, released on kill: {} PASS", out.trim());

    // 3. M19.d: przerwania – irq_bind (prawa, EBUSY), przerwanie edu budzi
    // wait_many, licznik, 10 przerwań = jedna pobudka z licznikiem, silnia
    // zakończona przerwaniem, lista z kanałem, wektor zwalniany (20 razy),
    // kill procesu z przypiętym przerwaniem.
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let r = run("/bin/irqtest", &["irqtest"], 30_000, true);
    check!(r.is_some(), "irqtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "irqtest: {:?} {:?}", kind, out.trim());
    check!(pci::owner(edu.unwrap()) == pci::OWNER_FREE, "edu still claimed after irqtest");
    let vectors1 = crate::arch::x86_64::msi::free_count();
    check!(vectors1 == vectors0, "MSI vectors leaked ({} free before, {} after)", vectors0, vectors1);
    let d = &pci::devices()[edu.unwrap()];
    check!(d.command() & pci::CMD_BUS_MASTER == 0, "edu bus mastering still on after the service ended");
    serial_println!("[SVC TEST] 3/7 interrupts: irq_bind rights + EBUSY, edu MSI wakes wait_many, counter, coalescing, factorial by interrupt, mixed list, vectors freed ({} free), bus mastering off after kill: {} PASS", vectors1, out.trim());

    // 4. M19.e: DMA – dma_alloc (prawa, rozmiary, szyna 28 bitów, limit 16 MiB
    // na urządzenie), dma_phys, edu czyta i zapisuje bufor usługi, koniec
    // transferu przerwaniem, kill procesu z buforem DMA.
    let free0 = crate::selftest::settled_free_frames();
    let r = run("/bin/dmatest", &["dmatest"], 30_000, true);
    check!(r.is_some(), "dmatest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "dmatest: {:?} {:?}", kind, out.trim());
    check!(pci::owner(edu.unwrap()) == pci::OWNER_FREE, "edu still claimed after dmatest");
    check!(d.command() & pci::CMD_BUS_MASTER == 0, "edu bus mastering still on after dmatest");
    let free1 = crate::selftest::settled_free_frames();
    check!(free1 == free0, "DMA buffers not returned ({} free frames before, {} after)", free0, free1);
    serial_println!("[SVC TEST] 4/7 DMA: dma_alloc rights / sizes / 28-bit bus / 16 MiB per device, dma_phys, edu reads and writes the service buffer, interrupts, buffers and bus mastering released after kill: {} PASS", out.trim());

    // 5. M19.f: usługa edud – sterownik edu w user space (rejestry, przerwania,
    // DMA), klienci przez kanały, 4 klientów naraz, kill usługi i restart,
    // samodzielny koniec, gdy nikt nie może jej już wywołać.
    let free0 = crate::selftest::settled_free_frames();
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let r = run("/bin/edutest", &["edutest"], 60_000, true);
    check!(r.is_some(), "edutest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "edutest: {:?} {:?}", kind, out.trim());
    check!(pci::owner(edu.unwrap()) == pci::OWNER_FREE, "edu still claimed after edutest");
    check!(d.command() & pci::CMD_BUS_MASTER == 0, "edu bus mastering still on after edutest");
    check!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked by edud");
    let free1 = crate::selftest::settled_free_frames();
    check!(free1 == free0, "frames leaked by edud ({} -> {})", free0, free1);
    serial_println!("[SVC TEST] 5/7 edud service: user-space edu driver (MMIO, IRQ, DMA) over channels, 4 clients, kill + restart, exits when unreachable, nothing leaked: {} PASS", out.trim());

    // 6. M19.g: menedżer usług w init – prawdziwy /bin/init w trybie testowym
    // (`init test /bin/svctest`): init sam uruchamia edud i echod, restartuje
    // je po awarii / kill, łączy klientów po nazwie, `services` przez shell,
    // 5 awarii -> broken; po teście init zamyka usługi i kończy się kodem
    // svctest.  Potem: edu wolne, wektory i ramki wróciły.
    let free0 = crate::selftest::settled_free_frames();
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let r = run_ex("/bin/init", &["init", "test", "/bin/svctest"], 60_000, true, true);
    check!(r.is_some(), "init test /bin/svctest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("svctest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "svctest via init: {:?} {:?}", kind, out.trim());
    check!(out.contains("init: service edu started") && out.contains("init: service echo started"), "init did not report service start: {:?}", out.trim());
    check!(pci::owner(edu.unwrap()) == pci::OWNER_FREE, "edu still claimed after init stopped its services");
    check!(d.command() & pci::CMD_BUS_MASTER == 0, "edu bus mastering still on after init stopped edud");
    check!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked by init services");
    let free1 = crate::selftest::settled_free_frames();
    check!(free1 == free0, "frames leaked by init services ({} -> {})", free0, free1);
    serial_println!("[SVC TEST] 6/7 service manager in init: edud + echod started by init, restart with backoff after crash / kill, connect by name, 'services' via sh, broken after 5 failures, services stopped cleanly, sysinfo / SYSCTL: {} PASS", line);

    // 7. M19.h: pomiar – ta sama praca w jądrze i w user space na edu:
    // przerwanie -> obudzony sterownik, silnia zakończona przerwaniem; w user
    // space także przez usługę (klient -> edud -> urządzenie -> odpowiedź) i
    // czas restartu usługi.  Wynik: linia [RESULT-SVC] (test.sh ją pokazuje).
    let free0 = crate::selftest::settled_free_frames();
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let kb = kernel_edu_bench(pci::Address { bus: 0, device: 6, function: 0 });
    check!(kb.is_ok(), "kernel edu driver: {:?}", kb.err());
    let (irq_k, fact_k) = kb.unwrap_or((0, 0));
    check!(pci::owner(edu.unwrap()) == pci::OWNER_FREE, "edu still claimed after the kernel measurement");
    check!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vector leaked by the kernel measurement");
    let r = run("/bin/svcbench", &["svcbench"], 60_000, true);
    check!(r.is_some(), "svcbench did not finish");
    let (kind, out) = r.unwrap();
    let res = out.lines().find(|l| l.starts_with("svcbench-result ")).unwrap_or("");
    check!(kind == ExitKind::Exit(0) && !res.is_empty(), "svcbench: {:?} {:?}", kind, out.trim());
    let field = |k: &str| -> u64 {
        res.split(' ').find_map(|kv| kv.strip_prefix(k).and_then(|v| v.strip_prefix('='))).and_then(|v| v.parse().ok()).unwrap_or(0)
    };
    let (irq_u, fact_u, ping_s, fact_s, restart) =
        (field("irq_user_ns"), field("fact_user_ns"), field("ping_svc_ns"), field("fact_svc_ns"), field("restart_us"));
    check!(irq_u > 0 && fact_u > 0 && ping_s > 0 && fact_s > 0 && restart > 0, "svcbench result incomplete: {:?}", res);
    check!(pci::owner(edu.unwrap()) == pci::OWNER_FREE, "edu still claimed after svcbench");
    check!(d.command() & pci::CMD_BUS_MASTER == 0, "edu bus mastering still on after svcbench");
    check!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked by svcbench");
    let free1 = crate::selftest::settled_free_frames();
    check!(free1 == free0, "frames leaked by the measurement ({} -> {})", free0, free1);
    let us = |ns: u64| alloc::format!("{}.{}", ns / 1000, ns % 1000 / 100);
    serial_println!(
        "[SVC TEST] 7/7 measurement on edu: interrupt -> woken driver: kernel {} us, user space {} us; 12! by interrupt: kernel {} us, user space {} us, client via edud {} us; PING via edud {} us; edud restart {} us PASS",
        us(irq_k), us(irq_u), us(fact_k), us(fact_u), us(fact_s), us(ping_s), restart
    );
    serial_println!(
        "[RESULT-SVC] ver={} irq_kernel_ns={} irq_user_ns={} fact_kernel_ns={} fact_user_ns={} fact_svc_ns={} ping_svc_ns={} restart_us={}",
        crate::shell::VERSION, irq_k, irq_u, fact_k, fact_u, fact_s, ping_s, restart
    );

    crate::sched::reap();
    check!(
        wait_for(2_000, || {
            crate::sched::reap();
            crate::sched::stack::free_frames_flushed() == frames0
        }),
        "frames leaked ({} -> {})",
        frames0,
        crate::sched::stack::free_frames_flushed()
    );
    crate::selftest::pass();
}

// ------------------------------------------------------------
// M19.h: edu obsługiwane przez jądro – punkt odniesienia dla pomiaru usługi.
// Ten sam przebieg co w /bin/svcbench: zapis rejestru, sterownik (tu zadanie
// jądra) śpi w kolejce, budzi go handler MSI, sprawdza status, potwierdza.
// ------------------------------------------------------------

static KEDU_IRQS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static KEDU_WAIT: crate::sched::sync::WaitQueue = crate::sched::sync::WaitQueue::new();

fn kedu_irq(_vector: u8) {
    KEDU_IRQS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    KEDU_WAIT.wake_all();
}

/// Powtarza `round` przez co najmniej 200 ms; ns na rundę.
fn timed_kernel(mut round: impl FnMut() -> bool) -> Result<u64, &'static str> {
    let t0 = ticks();
    let mut n = 0u64;
    loop {
        if !round() {
            return Err("interrupt lost (1 s timeout)");
        }
        n += 1;
        let e = ticks() - t0;
        if e >= 200 {
            return Ok(e * 1_000_000 / n);
        }
    }
}

/// (ns przerwanie -> obudzony sterownik, ns silnia przez przerwanie).
fn kernel_edu_bench(addr: crate::drivers::pci::Address) -> Result<(u64, u64), &'static str> {
    use core::ptr::{read_volatile, write_volatile};
    use core::sync::atomic::Ordering::SeqCst;
    use crate::arch::x86_64::msi;
    use crate::drivers::pci::Bar;
    let claim = super::device::DevClaim::claim(addr).map_err(|_| "claim edu")?;
    let d = claim.dev();
    let Some(&Bar::Memory { base, .. }) = d.bars.first() else { return Err("edu BAR0") };
    let m = crate::memory::map_mmio(base, 0x1000).ok_or("map edu registers")?;
    let rd = |r: u64| unsafe { read_volatile((m + r) as *const u32) };
    let wr = |r: u64, v: u32| unsafe { write_volatile((m + r) as *mut u32, v) };
    let vector = msi::alloc(kedu_irq).ok_or("no free MSI vector")?;
    KEDU_IRQS.store(0, SeqCst);
    d.set_bus_master(true);
    let result = (|| {
        d.enable_msi(vector).map_err(|_| "enable MSI")?;
        let wait_bit = |bit: u32| -> bool {
            while rd(0x24) & bit == 0 {
                if !KEDU_WAIT.wait_until(|| KEDU_IRQS.load(SeqCst) > 0, Some(1000)) {
                    return false;
                }
                KEDU_IRQS.swap(0, SeqCst);
            }
            wr(0x64, bit);
            true
        };
        let irq = timed_kernel(|| {
            wr(0x60, 0x100);
            wait_bit(0x100)
        })?;
        wr(0x20, 0x80);
        let fact = timed_kernel(|| {
            wr(0x08, 12);
            wait_bit(0x1) && rd(0x08) == 479_001_600
        })?;
        wr(0x20, 0);
        Ok((irq, fact))
    })();
    d.disable_msi();
    let _ = d.command();
    msi::free(vector);
    d.set_bus_master(false);
    drop(claim);
    result
}
