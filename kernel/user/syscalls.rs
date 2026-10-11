// M14: wywołania systemowe.
//
// Numery (RAX), argumenty RDI, RSI, RDX, R10, R8, R9, wynik w RAX;
// błąd = ujemny kod (jak -errno w Linuksie).
//
//   0  exit(code)                       kończy proces
//   1  write(fd, buf, len) -> n         fd 1/2 = konsola, 3+ = plik
//   2  read(fd, buf, len) -> n          fd 0 = konsola (cała linia), 3+ = plik
//   3  open(path, path_len, flags) -> fd
//   4  close(fd)
//   5  getpid() -> id
//   6  sleep(ms)
//   7  yield()
//   8  uptime() -> ms
//
// M16 (init + shell w user space):
//
//   9  spawn(path, len, argv, argv_len, flags, fds) -> pid
//        argv = argumenty oddzielone bajtem 0 (argv[0] = nazwa programu),
//        flags: 1 FOREGROUND (Ctrl+C kończy dziecko),
//        fds = in | out << 16 | err << 32 – deskryptory rodzica, które
//        dziecko dostaje jako 0, 1, 2 (kopie)
//  10  wait(pid, status_ptr, flags) -> pid
//        pid = -1 (u64::MAX) dowolne dziecko; flags: 1 WNOHANG (0 = jeszcze
//        nikt się nie skończył); status: kod 0..255 albo 0x100 | powód
//        (9 = kill/Ctrl+C, inaczej numer wyjątku CPU)
//  11  getppid() -> pid
//  12  kill(pid)                         tylko procesy; init chroniony
//  13  chdir(path, len)
//  14  getcwd(buf, len) -> n
//  15  readdir(path, len, buf, buflen) -> n   linie "d|f\t<rozmiar>\t<nazwa>\n"
//  16  stat(path, len, out)              out = [typ (0 plik, 1 katalog), rozmiar]
//  17  mkdir(path, len)
//  18  unlink(path, len)                 plik albo pusty katalog
//  19  readkey(line, len) -> klawisz     surowe klawisze dla edytora linii;
//        line = prompt + tekst do odrysowania, gdy w trakcie czekania coś
//        wypisze proces w tle; 0 = koniec wejścia
//  20  tasks(buf, len) -> n              linie "pid\tppid\tstan\tms\tprzełączenia\ttyp\tnazwa\n"
//  21  kcmd(line, len, fd)               komenda shella kernela (diagnostyka:
//        mem, lspci, mkfs...) – wyjście na deskryptor fd; tymczasowy most do czasu
//        właściwych syscalli
//
// M17b (obiekty plików): deskryptor wskazuje wspólny obiekt (OpenFile:
// ścieżka, prawa, pozycja) – kopie (dup, dup2, spawn) dzielą pozycję.
//
//  22  dup(fd) -> nowy fd                najniższy wolny
//  23  dup2(old, new) -> new             new zamknięty i wskazuje obiekt old
//  24  seek(fd, offset, whence) -> pozycja   whence 0 SET, 1 CUR, 2 END;
//        konsola – ESPIPE
//  25  pipe(out) -> 0                    out = [fd odczytu, fd zapisu]; read czeka
//        na dane (0 = nikt już nie pisze), write – na miejsce (EPIPE, gdy nikt
//        nie czyta); bufor 64 KiB
//
// M17b.d (pamięć procesu – strony przydzielane przy pierwszym dostępie):
//
//  26  brk(addr) -> koniec sterty        0 = zapytanie; błąd – dotychczasowy koniec
//  27  mmap(len, prot) -> adres          anonimowy, wyzerowany; prot 1 READ, 2 WRITE
//  28  munmap(addr, len)                 tylko obszary z mmap (także części)
//
// Flagi open: 1 READ, 2 WRITE, 4 CREATE, 8 TRUNC, 16 APPEND.
//
// Pamięć procesu: wskaźnik + długość są sprawdzane (dolna połowa, strony
// obecne z bitem USER, przy zapisie WRITABLE), a samo kopiowanie odbywa się
// przez adresy procesu między `stac` i `clac` (SMAP: poza tym oknem kernel
// nie ma dostępu do stron użytkownika).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use alloc::sync::Arc;

use super::process::{rights, Fd, Handle, OpenFile, Process};
use crate::sched::sync::Mutex;
use super::space::USER_SPACE_END;
use super::{exit_current, record_exit, ExitKind};
use crate::arch::x86_64::interrupts::{self, without_interrupts};
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::fs::{self, FileType, FsError};
use crate::memory::{USER, WRITABLE};
use crate::sched;

pub const SYS_EXIT: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_READ: u64 = 2;
pub const SYS_OPEN: u64 = 3;
pub const SYS_CLOSE: u64 = 4;
pub const SYS_GETPID: u64 = 5;
pub const SYS_SLEEP: u64 = 6;
pub const SYS_YIELD: u64 = 7;
pub const SYS_UPTIME: u64 = 8;
pub const SYS_SPAWN: u64 = 9;
pub const SYS_WAIT: u64 = 10;
pub const SYS_GETPPID: u64 = 11;
pub const SYS_KILL: u64 = 12;
pub const SYS_CHDIR: u64 = 13;
pub const SYS_GETCWD: u64 = 14;
pub const SYS_READDIR: u64 = 15;
pub const SYS_STAT: u64 = 16;
pub const SYS_MKDIR: u64 = 17;
pub const SYS_UNLINK: u64 = 18;
pub const SYS_READKEY: u64 = 19;
pub const SYS_TASKS: u64 = 20;
pub const SYS_KCMD: u64 = 21;
pub const SYS_DUP: u64 = 22;
pub const SYS_DUP2: u64 = 23;
pub const SYS_SEEK: u64 = 24;
pub const SYS_PIPE: u64 = 25;
pub const SYS_BRK: u64 = 26;
pub const SYS_MMAP: u64 = 27;
pub const SYS_MUNMAP: u64 = 28;
/// M18.b: kopia uchwytu z prawami `stare & maska` (wymaga DUP).
pub const SYS_HANDLE_DUP: u64 = 29;
/// M18.b: (rodzaj << 32) | prawa.
pub const SYS_HANDLE_INFO: u64 = 30;
/// M18.c: channel_create(out) – out = [koniec 0, koniec 1] (2 × u64).
pub const SYS_CHANNEL_CREATE: u64 = 31;
/// M18.c: chan_send(h, dane, len, uchwyty, n_uchwytów, flagi).
pub const SYS_CHAN_SEND: u64 = 32;
/// M18.c: chan_recv(h, bufor, cap, uchwyty, hcap | flagi << 32, info) -> len;
/// info = [len, n_uchwytów, nadawca] (3 × u64).
pub const SYS_CHAN_RECV: u64 = 33;
/// M18.c: nie czekaj (pełna / pusta kolejka – EAGAIN).
pub const CHAN_NONBLOCK: u64 = 1;
/// M18.d: spawn_ex(ścieżka, len, argv, len, mapa, n | flagi << 32) – dziecko
/// dostaje TYLKO uchwyty z mapy [(uchwyt rodzica, numer u dziecka)] (2 × u64).
pub const SYS_SPAWN_EX: u64 = 36;
/// M18.e: shm_create(rozmiar) -> uchwyt (MAP_READ|MAP_WRITE|DUP|TRANSFER).
pub const SYS_SHM_CREATE: u64 = 34;
/// M18.e: shm_map(h, prot) -> adres; PROT_WRITE wymaga MAP_WRITE.  Odmapowanie
/// – munmap całego obszaru.
pub const SYS_SHM_MAP: u64 = 35;
/// M18.e: shm_size(h) -> rozmiar obiektu w bajtach.
pub const SYS_SHM_SIZE: u64 = 37;
/// M18.d: najwięcej wpisów w mapie spawn_ex.
pub const SPAWN_EX_MAX: u64 = 16;

pub const SPAWN_FOREGROUND: u64 = 1;

pub const O_READ: u64 = 1;
pub const O_WRITE: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;
pub const O_APPEND: u64 = 16;

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EIO: i64 = -5;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
/// M18.c: komunikat za duży / bufor odbiorcy za mały.
pub const EMSGSIZE: i64 = -90;
pub const ECHILD: i64 = -10;
pub const E2BIG: i64 = -7;
pub const ENOEXEC: i64 = -8;
pub const ENOMEM: i64 = -12;
#[allow(dead_code)]
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;
pub const ENOSPC: i64 = -28;
pub const ESPIPE: i64 = -29;
pub const EPIPE: i64 = -32;
pub const EROFS: i64 = -30;
pub const ERANGE: i64 = -34;
pub const ENOTEMPTY: i64 = -39;
pub const ENOSYS: i64 = -38;

/// Największy pojedynczy write/read (dłuższe – kilka wywołań).
const MAX_IO: u64 = 64 * 1024;
/// M18.b: uchwytów na proces (było 16 deskryptorów).
const MAX_FDS: usize = 64;

type SysResult = Result<u64, i64>;

fn fs_error(e: FsError) -> i64 {
    match e {
        FsError::NotFound => ENOENT,
        FsError::NotADirectory => ENOTDIR,
        FsError::IsADirectory => EISDIR,
        FsError::AlreadyExists => EEXIST,
        FsError::NoSpace => ENOSPC,
        FsError::InvalidName => EINVAL,
        FsError::NotEmpty => ENOTEMPTY,
        FsError::ReadOnly => EROFS,
        _ => EIO,
    }
}

// ------------------------------------------------------------
// Pamięć procesu
// ------------------------------------------------------------

static SMAP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn set_smap(on: bool) {
    SMAP.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Czy [ptr, ptr+len) to pamięć procesu z odpowiednimi prawami.  M17b.d:
/// nieobecne strony z obszarów procesu (sterta, mmap, stos) najpierw
/// dociągane – kernel kopiuje do nich jak proces by do nich pisał.
fn user_range_ok(p: &mut Process, ptr: u64, len: u64, write: bool) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = ptr.checked_add(len) else { return false };
    if end > USER_SPACE_END {
        return false;
    }
    let mut page = ptr & !0xfff;
    while page < end {
        if p.space.translate(page).is_none() && p.mem.covers(page) {
            p.mem.fault_in(&mut p.space, page, write, true);
        }
        match p.space.translate(page) {
            Some((_, flags)) if flags & USER != 0 && (!write || flags & WRITABLE != 0) => {}
            _ => return false,
        }
        page += 4096;
    }
    true
}

/// Dostęp do pamięci procesu: STAC/CLAC (gdy jest SMAP), bez przerwań w
/// środku (flaga AC nie wycieka do handlerów).
fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    without_interrupts(|| {
        let smap = SMAP.load(core::sync::atomic::Ordering::Relaxed);
        if smap {
            unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xcb", options(nomem, nostack)) }; // stac
        }
        let r = f();
        if smap {
            unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xca", options(nomem, nostack)) }; // clac
        }
        r
    })
}

pub fn copy_from_user(p: &mut Process, ptr: u64, len: u64) -> Result<Vec<u8>, i64> {
    if !user_range_ok(p, ptr, len, false) {
        return Err(EFAULT);
    }
    let mut buf = vec![0u8; len as usize];
    with_user_access(|| unsafe {
        core::ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), len as usize)
    });
    Ok(buf)
}

pub fn copy_to_user(p: &mut Process, ptr: u64, data: &[u8]) -> Result<(), i64> {
    if !user_range_ok(p, ptr, data.len() as u64, true) {
        return Err(EFAULT);
    }
    with_user_access(|| unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len())
    });
    Ok(())
}

// ------------------------------------------------------------
// Wywołania
// ------------------------------------------------------------

fn sys_write(p: &mut Process, fd: u64, ptr: u64, len: u64) -> SysResult {
    let len = len.min(MAX_IO);
    let data = copy_from_user(p, ptr, len)?;
    write_fd(p, fd, &data)
}

/// Zapis gotowych danych na deskryptor procesu (write, kcmd).
fn write_fd(p: &mut Process, fd: u64, data: &[u8]) -> SysResult {
    // M18.b: bez prawa WRITE – EBADF (jak deskryptor tylko do odczytu w POSIX).
    if p.handle(fd)?.rights & rights::WRITE == 0 {
        return Err(EBADF);
    }
    if p.is_console(fd) {
        if fd == 0 {
            return Err(EBADF);
        }
        if let Some(out) = p.stdout.as_ref() {
            out.lock().extend_from_slice(data);
        } else {
            crate::console::write_from_process(&String::from_utf8_lossy(data));
        }
        return Ok(data.len() as u64);
    }
    match p.fd(fd)? {
        // Kanał nie ma READ / WRITE (komunikaty – chan_send / chan_recv).
        Fd::Console | Fd::Channel(_) | Fd::Shm(_) => Err(EBADF),
        Fd::Pipe(e) => {
            if !e.write {
                return Err(EBADF);
            }
            let e = e.clone();
            e.write(data).map(|n| n as u64)
        }
        Fd::File(f) => {
            if !f.write {
                return Err(EBADF);
            }
            let f = f.clone();
            let mut offset = f.offset.lock();
            if f.append {
                *offset = fs::stat(&f.path).map_err(fs_error)?.size;
            }
            let n = fs::write(&f.path, *offset, data).map_err(fs_error)?;
            *offset += n as u64;
            Ok(n as u64)
        }
    }
}

/// Linia z konsoli (echo, Backspace, Enter kończy).  Ctrl+C / kill -> EINTR.
fn read_console_line(max: usize) -> Result<Vec<u8>, i64> {
    use crate::console::{self, Key};
    let mut line = String::new();
    loop {
        if sched::should_exit() {
            return Err(EINTR);
        }
        match console::poll_key() {
            Some(Key::Char(c)) => {
                if line.len() + c.len_utf8() < max {
                    line.push(c);
                    let mut b = [0u8; 4];
                    console::write_str(c.encode_utf8(&mut b));
                }
            }
            Some(Key::Backspace) => {
                if line.pop().is_some() {
                    console::write_str("\x08 \x08");
                }
            }
            Some(Key::Enter) => {
                console::write_str("\n");
                line.push('\n');
                return Ok(line.into_bytes());
            }
            Some(Key::Ctrl('d')) => return Ok(line.into_bytes()),
            Some(Key::Ctrl('c')) => {
                console::write_str("^C\n");
                sched::request_exit(sched::current_id());
                return Err(EINTR);
            }
            Some(_) => {}
            None => {
                console::INPUT_WAIT.wait_until(|| console::input_pending() || sched::should_exit(), None);
            }
        }
    }
}

fn sys_read(p: &mut Process, fd: u64, ptr: u64, len: u64) -> SysResult {
    let len = len.min(MAX_IO);
    if !user_range_ok(p, ptr, len, true) {
        return Err(EFAULT);
    }
    // M18.b: bez prawa READ – EBADF.
    if p.handle(fd)?.rights & rights::READ == 0 {
        return Err(EBADF);
    }
    let data = if p.is_console(fd) {
        if fd != 0 {
            return Err(EBADF);
        }
        match p.stdin.as_ref() {
            Some(input) => {
                let mut input = input.lock();
                let n = (len as usize).min(input.len());
                input.drain(..n).collect()
            }
            None => read_console_line(len as usize)?,
        }
    } else {
        match p.fd(fd)? {
            Fd::Console | Fd::Channel(_) | Fd::Shm(_) => return Err(EBADF),
            Fd::Pipe(e) => {
                if e.write {
                    return Err(EBADF);
                }
                let e = e.clone();
                e.read(len as usize)?
            }
            Fd::File(f) => {
                if !f.read {
                    return Err(EBADF);
                }
                let f = f.clone();
                let mut offset = f.offset.lock();
                let mut buf = vec![0u8; len as usize];
                let n = fs::read(&f.path, *offset, &mut buf).map_err(fs_error)?;
                *offset += n as u64;
                buf.truncate(n);
                buf
            }
        }
    };
    copy_to_user(p, ptr, &data)?;
    Ok(data.len() as u64)
}

fn sys_open(p: &mut Process, ptr: u64, len: u64, flags: u64) -> SysResult {
    if len == 0 || len > 255 {
        return Err(EINVAL);
    }
    if flags & (O_READ | O_WRITE) == 0 || flags & !(O_READ | O_WRITE | O_CREATE | O_TRUNC | O_APPEND) != 0 {
        return Err(EINVAL);
    }
    let raw = copy_from_user(p, ptr, len)?;
    let name = core::str::from_utf8(&raw).map_err(|_| EINVAL)?;
    let path = fs::normalize(&p.cwd, name);
    let write = flags & O_WRITE != 0;
    match fs::stat(&path) {
        Ok(m) if m.kind == FileType::Directory => return Err(EISDIR),
        Ok(_) => {
            if write && flags & O_TRUNC != 0 {
                fs::truncate(&path, 0).map_err(fs_error)?;
            }
        }
        Err(FsError::NotFound) if flags & O_CREATE != 0 && write => {
            fs::create(&path).map_err(fs_error)?;
        }
        Err(e) => return Err(fs_error(e)),
    }
    let file = Fd::File(Arc::new(OpenFile {
        path,
        read: flags & O_READ != 0,
        write,
        append: flags & O_APPEND != 0,
        offset: Mutex::new(0),
    }));
    install_fd(p, 3, file)
}

/// Najniższy wolny deskryptor >= `from` dostaje `fd` (prawa wg obiektu).
fn install_fd(p: &mut Process, from: usize, fd: Fd) -> SysResult {
    install_handle(p, from, Handle::new(fd))
}

/// M18.b: najniższy wolny numer >= `from` dostaje uchwyt `h` (z jego prawami).
fn install_handle(p: &mut Process, from: usize, h: Handle) -> SysResult {
    let slot = (from..MAX_FDS).find(|&i| p.fds.get(i).map_or(true, |f| f.is_none())).ok_or(EMFILE)?;
    if p.fds.len() <= slot {
        p.fds.resize_with(slot + 1, || None);
    }
    p.fds[slot] = Some(h);
    Ok(slot as u64)
}

/// M18.b: uchwyt do skopiowania (dup, dup2, spawn, handle_dup) – wymaga DUP.
fn handle_for_copy(p: &Process, fd: u64) -> Result<Handle, i64> {
    let h = p.handle(fd)?;
    if h.rights & rights::DUP == 0 {
        return Err(EACCES);
    }
    Ok(h.clone())
}

/// M18.b: handle_dup(h, maska) – nowy uchwyt (najniższy wolny) na ten sam
/// obiekt z prawami `stare & maska`.  Prawa nigdy nie rosną.
fn sys_handle_dup(p: &mut Process, fd: u64, mask: u64) -> SysResult {
    let mut h = handle_for_copy(p, fd)?;
    h.rights &= mask as u32 & rights::ALL;
    install_handle(p, 0, h)
}

/// M18.c: koniec kanału spod uchwytu z prawem `right` (EACCES bez prawa,
/// EBADF – to nie kanał).
fn chan_end(p: &Process, h: u64, right: u32) -> Result<Arc<super::channel::ChanEnd>, i64> {
    let hd = p.handle(h)?;
    let Fd::Channel(e) = &hd.obj else { return Err(EBADF) };
    if hd.rights & right == 0 {
        return Err(EACCES);
    }
    Ok(e.clone())
}

/// M18.c: channel_create(out) – dwa końce kanału (najniższe wolne numery).
fn sys_channel_create(p: &mut Process, out: u64) -> SysResult {
    if !user_range_ok(p, out, 16, true) {
        return Err(EFAULT);
    }
    let (a, b) = super::channel::new();
    let ha = install_fd(p, 0, Fd::Channel(a))?;
    let hb = match install_fd(p, 0, Fd::Channel(b)) {
        Ok(h) => h,
        Err(e) => {
            p.fds[ha as usize] = None;
            return Err(e);
        }
    };
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&ha.to_le_bytes());
    bytes[8..].copy_from_slice(&hb.to_le_bytes());
    copy_to_user(p, out, &bytes)?;
    Ok(0)
}

/// M18.c: chan_send – dane kopiowane do jądra przed jakąkolwiek blokadą.
/// M18.d: uchwyty z listy są PRZENOSZONE (znikają z tablicy nadawcy, wymagają
/// TRANSFER); błąd wysyłki – wracają na swoje miejsca.
fn sys_chan_send(p: &mut Process, f: &SyscallFrame) -> SysResult {
    use super::channel::MSG_HANDLES;
    let (h, buf, len, hptr, nh, flags) = (f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9);
    if flags & !CHAN_NONBLOCK != 0 || nh as usize > MSG_HANDLES {
        return Err(EINVAL);
    }
    if len as usize > super::channel::MSG_MAX {
        return Err(EMSGSIZE);
    }
    let end = chan_end(p, h, rights::SEND)?;
    let data = copy_from_user(p, buf, len)?;
    // Lista uchwytów: istnieją, mają TRANSFER, bez powtórzeń, żaden nie jest
    // końcem tego kanału.  Sprawdzenie całej listy przed zdjęciem czegokolwiek.
    let mut nums: Vec<usize> = Vec::new();
    if nh > 0 {
        let raw = copy_from_user(p, hptr, nh * 8)?;
        for c in raw.chunks_exact(8) {
            let n = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
            let hd = p.handle(n)?;
            if hd.rights & rights::TRANSFER == 0 {
                return Err(EACCES);
            }
            if let Fd::Channel(e) = &hd.obj {
                if e.same_channel(&end) {
                    return Err(EINVAL);
                }
            }
            if nums.contains(&(n as usize)) {
                return Err(EINVAL);
            }
            nums.push(n as usize);
        }
    }
    let handles: Vec<Handle> = nums.iter().map(|&n| p.fds[n].take().unwrap()).collect();
    let msg = super::channel::Message { data, handles, sender: sched::current_id() };
    match end.send(msg, flags & CHAN_NONBLOCK != 0) {
        Ok(()) => Ok(0),
        Err((e, msg)) => {
            // Proces jest jednowątkowy – miejsca są nadal wolne.
            for (n, hd) in nums.into_iter().zip(msg.handles) {
                p.fds[n] = Some(hd);
            }
            Err(e)
        }
    }
}

/// M18.c: chan_recv – komunikat zdejmowany pod blokadą kanału, kopiowany do
/// procesu po jej zwolnieniu.  Za mały bufor: EMSGSIZE, info = wymagany
/// rozmiar, komunikat zostaje.
fn sys_chan_recv(p: &mut Process, f: &SyscallFrame) -> SysResult {
    use super::channel::RecvError;
    let (h, buf, cap, hptr, hcap_flags, info) = (f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9);
    let hcap = (hcap_flags & 0xFFFF) as usize;
    let flags = hcap_flags >> 32;
    if flags & !CHAN_NONBLOCK != 0 || hcap_flags & 0xFFFF_0000 != 0 {
        return Err(EINVAL);
    }
    let cap = cap.min(super::channel::MSG_MAX as u64);
    let hcap = hcap.min(super::channel::MSG_HANDLES);
    if !user_range_ok(p, buf, cap, true)
        || (info != 0 && !user_range_ok(p, info, 24, true))
        || (hcap > 0 && !user_range_ok(p, hptr, hcap as u64 * 8, true))
    {
        return Err(EFAULT);
    }
    // M18.d: wolne miejsca w tablicy – komunikat z większą liczbą uchwytów
    // zostaje w kolejce (EMFILE), nic nie ginie.
    let room = (0..MAX_FDS).filter(|&i| p.fds.get(i).map_or(true, |x| x.is_none())).count();
    let end = chan_end(p, h, rights::RECV)?;
    let write_info = |p: &mut Process, len: u64, nh: u64, sender: u64| -> Result<(), i64> {
        if info == 0 {
            return Ok(());
        }
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&len.to_le_bytes());
        b[8..16].copy_from_slice(&nh.to_le_bytes());
        b[16..].copy_from_slice(&sender.to_le_bytes());
        copy_to_user(p, info, &b)
    };
    match end.recv(cap as usize, hcap, room, flags & CHAN_NONBLOCK != 0) {
        Ok(m) => {
            let (len, nh, sender) = (m.data.len() as u64, m.handles.len() as u64, m.sender);
            copy_to_user(p, buf, &m.data)?;
            // Uchwyty – najniższe wolne numery (miejsce sprawdzone wyżej).
            let mut nums = [0u8; 8 * super::channel::MSG_HANDLES];
            for (i, hd) in m.handles.into_iter().enumerate() {
                let n = install_handle(p, 0, hd)?;
                nums[i * 8..i * 8 + 8].copy_from_slice(&n.to_le_bytes());
            }
            if nh > 0 {
                copy_to_user(p, hptr, &nums[..nh as usize * 8])?;
            }
            write_info(p, len, nh, sender)?;
            Ok(len)
        }
        Err(RecvError::TooSmall(len, nh)) => {
            write_info(p, len as u64, nh as u64, 0)?;
            Err(EMSGSIZE)
        }
        Err(RecvError::Code(e)) => Err(e),
    }
}

/// M18.e: obiekt pamięci współdzielonej spod uchwytu z prawem `right`.
fn shm_obj(p: &Process, h: u64, right: u32) -> Result<Arc<super::shm::ShmObj>, i64> {
    let hd = p.handle(h)?;
    let Fd::Shm(o) = &hd.obj else { return Err(EBADF) };
    if hd.rights & right != right {
        return Err(EACCES);
    }
    Ok(o.clone())
}

/// M18.e: shm_create(rozmiar) – nowy obiekt (wyzerowany) pod najniższym
/// wolnym numerem.
fn sys_shm_create(p: &mut Process, size: u64) -> SysResult {
    let obj = super::shm::ShmObj::new(size)?;
    install_fd(p, 0, Fd::Shm(obj))
}

/// M18.e: shm_map(h, prot) – cały obiekt w obszarze mmap procesu; zawsze NX,
/// zapis tylko z MAP_WRITE.
fn sys_shm_map(p: &mut Process, h: u64, prot: u64) -> SysResult {
    use super::vm::{PROT_READ, PROT_WRITE};
    if prot & !(PROT_READ | PROT_WRITE) != 0 {
        return Err(EINVAL);
    }
    let write = prot & PROT_WRITE != 0;
    let need = rights::MAP_READ | if write { rights::MAP_WRITE } else { 0 };
    let obj = shm_obj(p, h, need)?;
    super::vm::count_call();
    p.mem.map_shared(&mut p.space, obj, write)
}

/// M18.b: handle_info(h) -> (rodzaj << 32) | prawa.
fn sys_handle_info(p: &mut Process, fd: u64) -> SysResult {
    let h = p.handle(fd)?;
    Ok(h.kind() << 32 | h.rights as u64)
}

/// M17b.b: pipe(out) – out = [fd do odczytu, fd do zapisu] (2 × u64).
fn sys_pipe(p: &mut Process, out: u64) -> SysResult {
    if !user_range_ok(p, out, 16, true) {
        return Err(EFAULT);
    }
    let (r, w) = super::pipe::new();
    let rfd = install_fd(p, 0, Fd::Pipe(r))?;
    let wfd = match install_fd(p, 0, Fd::Pipe(w)) {
        Ok(fd) => fd,
        Err(e) => {
            p.fds[rfd as usize] = None;
            return Err(e);
        }
    };
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&rfd.to_le_bytes());
    bytes[8..].copy_from_slice(&wfd.to_le_bytes());
    copy_to_user(p, out, &bytes)?;
    Ok(0)
}

/// M17b.a: dup(fd) – nowy deskryptor (najniższy wolny) na ten sam obiekt.
fn sys_dup(p: &mut Process, fd: u64) -> SysResult {
    let h = handle_for_copy(p, fd)?;
    install_handle(p, 0, h)
}

/// M17b.a: dup2(old, new) – `new` wskazuje obiekt `old` (poprzedni obiekt
/// `new` zamknięty).  old == new – nic (o ile old otwarty).
fn sys_dup2(p: &mut Process, old: u64, new: u64) -> SysResult {
    let f = handle_for_copy(p, old)?;
    let new = new as usize;
    if new >= MAX_FDS {
        return Err(EBADF);
    }
    if old as usize != new {
        if p.fds.len() <= new {
            p.fds.resize_with(new + 1, || None);
        }
        p.fds[new] = Some(f);
    }
    Ok(new as u64)
}

pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

/// M17b.a: seek(fd, offset, whence) -> nowa pozycja.  Konsola – ESPIPE.
fn sys_seek(p: &mut Process, fd: u64, offset: u64, whence: u64) -> SysResult {
    let Fd::File(f) = p.fd(fd)? else { return Err(ESPIPE) };
    let f = f.clone();
    let mut pos = f.offset.lock();
    let base: i64 = match whence {
        SEEK_SET => 0,
        SEEK_CUR => *pos as i64,
        SEEK_END => fs::stat(&f.path).map_err(fs_error)?.size as i64,
        _ => return Err(EINVAL),
    };
    let new = base.checked_add(offset as i64).ok_or(EINVAL)?;
    if new < 0 {
        return Err(EINVAL);
    }
    *pos = new as u64;
    Ok(new as u64)
}

fn sys_close(p: &mut Process, fd: u64) -> SysResult {
    match p.fds.get_mut(fd as usize) {
        Some(slot @ Some(_)) => {
            *slot = None;
            Ok(0)
        }
        _ => Err(EBADF),
    }
}

// ------------------------------------------------------------
// M16: procesy, katalogi, klawisze
// ------------------------------------------------------------

/// Ścieżka z pamięci procesu (1..=255 bajtów UTF-8), znormalizowana
/// względem katalogu bieżącego.
fn user_path(p: &mut Process, ptr: u64, len: u64) -> Result<String, i64> {
    if len == 0 || len > 255 {
        return Err(EINVAL);
    }
    let raw = copy_from_user(p, ptr, len)?;
    let name = core::str::from_utf8(&raw).map_err(|_| EINVAL)?;
    Ok(fs::normalize(&p.cwd, name))
}

fn exec_error(e: super::ExecError) -> i64 {
    use super::elf_loader::LoadError;
    match e {
        super::ExecError::Fs(e) => fs_error(e),
        super::ExecError::TooBig => E2BIG,
        super::ExecError::Load(LoadError::NoMemory) => ENOMEM,
        super::ExecError::Load(LoadError::TooManyArgs) => E2BIG,
        super::ExecError::Load(_) => ENOEXEC,
    }
}

fn sys_spawn(p: &mut Process, f: &SyscallFrame) -> SysResult {
    let (flags, fds) = (f.r8, f.r9);
    if flags & !SPAWN_FOREGROUND != 0 {
        return Err(EINVAL);
    }
    // M18.b: dziecko dostaje kopie uchwytów z ich prawami (wymaga DUP).
    let child_fd = |shift: u32| -> Result<Option<Handle>, i64> { handle_for_copy(p, (fds >> shift) & 0xFFFF).map(Some) };
    let child_fds = alloc::vec![child_fd(0)?, child_fd(16)?, child_fd(32)?];
    spawn_common(p, f, flags, child_fds)
}

/// M18.d: spawn_ex – dziecko dostaje tylko uchwyty z mapy (kopie, wymagają
/// DUP); numery u dziecka < 64, bez powtórzeń.  Brak stdio, jeśli rodzic go
/// nie da.
fn sys_spawn_ex(p: &mut Process, f: &SyscallFrame) -> SysResult {
    let (map, n, flags) = (f.r8, f.r9 & 0xFFFF_FFFF, f.r9 >> 32);
    if flags & !SPAWN_FOREGROUND != 0 || n > SPAWN_EX_MAX {
        return Err(EINVAL);
    }
    let raw = if n > 0 { copy_from_user(p, map, n * 16)? } else { Vec::new() };
    let mut child_fds: Vec<Option<Handle>> = Vec::new();
    for c in raw.chunks_exact(16) {
        let word = |i: usize| u64::from_le_bytes([c[i], c[i + 1], c[i + 2], c[i + 3], c[i + 4], c[i + 5], c[i + 6], c[i + 7]]);
        let (from, to) = (word(0), word(8) as usize);
        if to >= MAX_FDS || child_fds.get(to).map_or(false, |x| x.is_some()) {
            return Err(EINVAL);
        }
        let hd = handle_for_copy(p, from)?;
        if child_fds.len() <= to {
            child_fds.resize_with(to + 1, || None);
        }
        child_fds[to] = Some(hd);
    }
    spawn_common(p, f, flags, child_fds)
}

/// Wspólna część spawn / spawn_ex: ścieżka (rdi, rsi), argumenty (rdx, r10).
fn spawn_common(p: &mut Process, f: &SyscallFrame, flags: u64, child_fds: Vec<Option<Handle>>) -> SysResult {
    let (path_ptr, path_len, argv_ptr, argv_len) = (f.rdi, f.rsi, f.rdx, f.r10);
    if argv_len > 4096 {
        return Err(EINVAL);
    }
    let path = user_path(p, path_ptr, path_len)?;
    let raw = copy_from_user(p, argv_ptr, argv_len)?;
    let text = core::str::from_utf8(&raw).map_err(|_| EINVAL)?;
    let mut args: Vec<&str> = text.split('\0').collect();
    if text.ends_with('\0') {
        args.pop();
    }
    if args.is_empty() {
        args.push(path.rsplit('/').next().unwrap_or(&path));
    }
    let me = sched::current_id();
    let t_load = super::prof::start();
    let pid = super::spawn_child(me, p, &path, &args, flags & SPAWN_FOREGROUND != 0, child_fds)
        .map_err(exec_error)?;
    super::prof::stop(super::prof::LOAD_ELF, t_load);
    Ok(pid)
}

fn sys_wait(p: &mut Process, pid: u64, status_ptr: u64, flags: u64) -> SysResult {
    if flags & !super::procs::WNOHANG != 0 {
        return Err(EINVAL);
    }
    if status_ptr != 0 && !user_range_ok(p, status_ptr, 8, true) {
        return Err(EFAULT);
    }
    let (child, status) = super::procs::wait(sched::current_id(), pid, flags)?;
    if child != 0 {
        crate::console::remove_foreground(child);
        if status_ptr != 0 {
            copy_to_user(p, status_ptr, &status.to_le_bytes())?;
        }
    }
    Ok(child)
}

pub(super) fn sys_kill(pid: u64) -> SysResult {
    if !sched::with_process(pid, |_| ()).is_some() {
        return Err(ESRCH); // brak procesu (zadań kernela kill z procesu nie dotyka)
    }
    if pid == super::procs::init_pid() {
        return Err(EPERM);
    }
    if sched::request_exit(pid) { Ok(0) } else { Err(ESRCH) }
}

fn sys_chdir(p: &mut Process, ptr: u64, len: u64) -> SysResult {
    let path = user_path(p, ptr, len)?;
    match fs::stat(&path) {
        Ok(m) if m.kind == FileType::Directory => {
            p.cwd = path;
            Ok(0)
        }
        Ok(_) => Err(ENOTDIR),
        Err(e) => Err(fs_error(e)),
    }
}

/// Tekst do bufora procesu: całość albo ERANGE (nic nie jest ucinane).
fn text_to_user(p: &mut Process, ptr: u64, len: u64, text: &str) -> SysResult {
    if text.len() as u64 > len.min(MAX_IO) {
        return Err(ERANGE);
    }
    copy_to_user(p, ptr, text.as_bytes())?;
    Ok(text.len() as u64)
}

fn sys_readdir(p: &mut Process, f: &SyscallFrame) -> SysResult {
    use core::fmt::Write;
    let path = user_path(p, f.rdi, f.rsi)?;
    let entries = fs::read_dir(&path).map_err(fs_error)?;
    let mut text = String::new();
    for e in entries {
        let kind = if e.kind == FileType::Directory { 'd' } else { 'f' };
        let _ = writeln!(text, "{}\t{}\t{}", kind, e.size, e.name);
    }
    text_to_user(p, f.rdx, f.r10, &text)
}

fn sys_stat(p: &mut Process, ptr: u64, len: u64, out: u64) -> SysResult {
    let path = user_path(p, ptr, len)?;
    let m = fs::stat(&path).map_err(fs_error)?;
    let kind: u64 = if m.kind == FileType::Directory { 1 } else { 0 };
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&kind.to_le_bytes());
    buf[8..].copy_from_slice(&m.size.to_le_bytes());
    copy_to_user(p, out, &buf)?;
    Ok(0)
}

/// Klawisz -> liczba dla readkey (bez zera: 0 = koniec wejścia).
pub fn encode_key(k: crate::console::Key) -> u64 {
    use crate::console::Key;
    const SPECIAL: u64 = 0x11_0000;
    const CTRL: u64 = 0x12_0000;
    match k {
        Key::Char(c) => c as u64,
        Key::Ctrl(c) => CTRL + c as u64,
        Key::Enter => SPECIAL + 1,
        Key::Backspace => SPECIAL + 2,
        Key::Delete => SPECIAL + 3,
        Key::Tab => SPECIAL + 4,
        Key::Escape => SPECIAL + 5,
        Key::Left => SPECIAL + 6,
        Key::Right => SPECIAL + 7,
        Key::Up => SPECIAL + 8,
        Key::Down => SPECIAL + 9,
        Key::Home => SPECIAL + 10,
        Key::End => SPECIAL + 11,
    }
}

fn sys_readkey(p: &mut Process, ptr: u64, len: u64) -> SysResult {
    use crate::console;
    // Testy: klawisze z bufora (bajty jak z terminala).
    if let Some(input) = p.stdin.clone() {
        let mut input = input.lock();
        while let Some(b) = input.pop_front() {
            if let Some(k) = p.key_decoder.feed(b) {
                return Ok(encode_key(k));
            }
        }
        return Ok(0);
    }
    let line = if len > 0 {
        let raw = copy_from_user(p, ptr, len.min(1024))?;
        Some(String::from_utf8_lossy(&raw).into_owned())
    } else {
        None
    };
    // Linia do odrysowania, gdyby w trakcie czekania przyszedł komunikat
    // z innego zadania (np. koniec procesu w tle) – jak w shellu kernela.
    loop {
        if sched::should_exit() {
            return Err(EINTR);
        }
        if let Some(k) = console::poll_key() {
            return Ok(encode_key(k));
        }
        console::set_input_line(line.clone());
        console::INPUT_WAIT.wait_until(|| console::input_pending() || sched::should_exit(), None);
        console::set_input_line(None);
    }
}

fn sys_tasks(p: &mut Process, ptr: u64, len: u64) -> SysResult {
    use core::fmt::Write;
    let mut text = String::new();
    for t in sched::tasks() {
        let _ = writeln!(
            text,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            t.id,
            t.ppid,
            t.state.name(),
            t.cpu_ticks, // 1 tick = 1 ms (PIT 1000 Hz)
            t.switches,
            if t.user { "user" } else { "kernel" },
            t.name,
            // M17: CPU, na którym działa teraz (albo ostatnio, z '~').
            match t.cpu {
                Some(c) => alloc::format!("{}", c),
                None => alloc::format!("~{}", t.last_cpu),
            }
        );
    }
    text_to_user(p, ptr, len, &text)
}

fn sys_kcmd(p: &mut Process, ptr: u64, len: u64, fd: u64) -> SysResult {
    if len == 0 || len > 255 {
        return Err(EINVAL);
    }
    let raw = copy_from_user(p, ptr, len)?;
    let line = core::str::from_utf8(&raw).map_err(|_| EINVAL)?;
    let out = crate::shell::kernel_command(line, &p.cwd).ok_or(ENOENT)?;
    if !out.is_empty() {
        write_fd(p, fd, out.as_bytes())?;
    }
    Ok(0)
}

// ------------------------------------------------------------
// M17a.d/e: syscalle bez Big Kernel Lock
// ------------------------------------------------------------
//
// Bez BKL działają: getpid, uptime (d), write (konsola, stdout, pliki) oraz
// pliki i katalogi: open, close, read z pliku / bufora stdin, readkey z bufora,
// stat, readdir, mkdir, unlink, chdir, getcwd (e).  Dotykają tylko: własnego procesu (jednowątkowy –
// deskryptory, cwd i pamięć zmienia tylko on, sched::current_unlocked),
// licznika ticków, heapa, konsoli, bufora stdout (SpinLock) i VFS / warstwy
// block (własne blokady FS_LOCK / block::LOCK – KMutex z compare_exchange).
// Czekanie na dysk (WaitQueue) – od f2 tylko blokada schedulera.
// Procesy (e2): spawn, wait, kill, getppid – tablica zombie pod własną
// blokadą.  Sleep i yield (f2) – tylko blokada schedulera.  Pod BKL
// zostają: exit (koniec zadania), read / readkey z klawiatury, tasks, kcmd.

static FAST: [crate::arch::x86_64::percpu::PerCpuCounter; 6] = [const { crate::arch::x86_64::percpu::PerCpuCounter::new() }; 6];
static SLOW: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();

/// (getpid, uptime, write, pliki/katalogi, procesy, sleep/yield – bez BKL;
/// pozostałe pod BKL) – `cpus`, testy.
pub fn syscall_stats() -> ([u64; 6], u64) {
    let mut fast = [0u64; 6];
    for (i, f) in FAST.iter().enumerate() {
        fast[i] = f.get();
    }
    (fast, SLOW.get())
}

/// Czy syscall może iść bez BKL; Some(licznik).  Z IF = 0 (przed BKL).
fn bkl_free_slot(frame: &SyscallFrame) -> Option<usize> {
    if !sched::active() || frame.rip >= USER_SPACE_END {
        return None;
    }
    let (_, p) = sched::current_unlocked()?;
    match frame.rax {
        SYS_GETPID => Some(0),
        SYS_UPTIME => Some(1),
        SYS_WRITE => Some(2),
        // Odczyt z pliku albo z bufora stdin (testy, stress) – bez BKL;
        // z klawiatury (stan wspólny z przerwaniem, linia shella) – pod BKL.
        SYS_READ => (matches!(p.fds.get(frame.rdi as usize), Some(Some(Handle { obj: Fd::File(_) | Fd::Pipe(_), .. }))) || p.stdin.is_some())
            .then_some(3),
        SYS_READKEY => p.stdin.is_some().then_some(3),
        SYS_DUP | SYS_DUP2 | SYS_SEEK | SYS_PIPE | SYS_HANDLE_DUP | SYS_HANDLE_INFO => Some(3),
        // M18.c: kanały – własne blokady, bez BKL.
        SYS_CHANNEL_CREATE | SYS_CHAN_SEND | SYS_CHAN_RECV => Some(3),
        // M18.e: pamięć współdzielona – jak brk / mmap (zmienia ją tylko proces).
        SYS_SHM_CREATE | SYS_SHM_MAP | SYS_SHM_SIZE => Some(4),
        // M17b.d: pamięć procesu – zmienia ją tylko on sam, ramki bez BKL.
        SYS_BRK | SYS_MMAP | SYS_MUNMAP => Some(4),
        SYS_OPEN | SYS_CLOSE | SYS_STAT | SYS_READDIR | SYS_MKDIR | SYS_UNLINK | SYS_CHDIR | SYS_GETCWD => Some(3),
        // M17a.e2: procesy – tablica zombie pod własną blokadą
        // (lista zadań: od f2 pod blokadą schedulera).
        SYS_SPAWN | SYS_SPAWN_EX | SYS_WAIT | SYS_KILL | SYS_GETPPID => Some(4),
        // M17a.g3: koniec procesu bez BKL (exit_current – własne blokady).
        SYS_EXIT => Some(4),
        // M17a.f2: scheduler na własnej blokadzie – sleep i yield bez BKL.
        SYS_SLEEP | SYS_YIELD => Some(5),
        _ => None,
    }
}

/// Wołane z syscall_entry (asembler) – na stosie kernela zadania.
#[unsafe(no_mangle)]
extern "sysv64" fn syscall_dispatch(frame: &mut SyscallFrame) {
    // M17b.f: profil (od wejścia, z czekaniem na BKL, do SYSRET).
    let t0 = super::prof::start();
    let nr = frame.rax as usize;
    // M17a.d/e: część syscalli bez BKL; reszta – wejście do kernela pod
    // Big Kernel Lock (przy IF = 0, jak w M17).
    match bkl_free_slot(frame) {
        Some(slot) => {
            FAST[slot].add(1);
        }
        None => {
            SLOW.add(1);
            crate::sched::bkl::acquire_tagged(&crate::sched::bkl::tag::SYSCALL);
        }
    }
    // Syscalle działają z włączonymi przerwaniami (SFMASK wyłączył IF).
    interrupts::enable();
    let Some(p) = sched::current_process() else {
        panic!("syscall from a task without a process");
    };
    let (a0, a1, a2) = (frame.rdi, frame.rsi, frame.rdx);
    let result: SysResult = match frame.rax {
        SYS_EXIT => {
            record_exit(ExitKind::Exit(a0 as i64), frame.rip, frame.rax, frame.rbx);
            exit_current();
        }
        SYS_WRITE => sys_write(p, a0, a1, a2),
        SYS_READ => sys_read(p, a0, a1, a2),
        SYS_OPEN => sys_open(p, a0, a1, a2),
        SYS_CLOSE => sys_close(p, a0),
        SYS_GETPID => Ok(sched::current_id()),
        SYS_SLEEP => {
            crate::time::sleep_ms(a0.min(3_600_000));
            Ok(0)
        }
        SYS_YIELD => {
            sched::yield_now();
            Ok(0)
        }
        SYS_UPTIME => Ok(crate::time::uptime_ms()),
        SYS_SPAWN => sys_spawn(p, frame),
        SYS_SPAWN_EX => sys_spawn_ex(p, frame),
        SYS_WAIT => sys_wait(p, a0, a1, a2),
        SYS_GETPPID => Ok(p.ppid()),
        SYS_KILL => sys_kill(a0),
        SYS_CHDIR => sys_chdir(p, a0, a1),
        SYS_GETCWD => {
            let cwd = p.cwd.clone();
            text_to_user(p, a0, a1, &cwd)
        }
        SYS_READDIR => sys_readdir(p, frame),
        SYS_STAT => sys_stat(p, a0, a1, a2),
        SYS_MKDIR => user_path(p, a0, a1).and_then(|path| fs::mkdir(&path).map(|_| 0).map_err(fs_error)),
        SYS_UNLINK => user_path(p, a0, a1).and_then(|path| fs::remove(&path).map(|_| 0).map_err(fs_error)),
        SYS_READKEY => sys_readkey(p, a0, a1),
        SYS_TASKS => sys_tasks(p, a0, a1),
        SYS_KCMD => sys_kcmd(p, a0, a1, a2),
        SYS_DUP => sys_dup(p, a0),
        SYS_DUP2 => sys_dup2(p, a0, a1),
        SYS_SEEK => sys_seek(p, a0, a1, a2),
        SYS_PIPE => sys_pipe(p, a0),
        SYS_HANDLE_DUP => sys_handle_dup(p, a0, a1),
        SYS_HANDLE_INFO => sys_handle_info(p, a0),
        SYS_CHANNEL_CREATE => sys_channel_create(p, a0),
        SYS_CHAN_SEND => sys_chan_send(p, frame),
        SYS_CHAN_RECV => sys_chan_recv(p, frame),
        SYS_SHM_CREATE => sys_shm_create(p, a0),
        SYS_SHM_MAP => sys_shm_map(p, a0, a1),
        SYS_SHM_SIZE => shm_obj(p, a0, 0).map(|o| o.len()),
        SYS_BRK => {
            super::vm::count_call();
            Ok(p.mem.set_brk(&mut p.space, a0))
        }
        SYS_MMAP => {
            super::vm::count_call();
            p.mem.mmap(a0, a1)
        }
        SYS_MUNMAP => p.mem.munmap(&mut p.space, a0, a1).map(|_| 0),
        _ => Err(ENOSYS),
    };
    frame.rax = match result {
        Ok(v) => v,
        Err(e) => e as u64,
    };
    p.syscalls += 1;

    // kill / Ctrl+C w trakcie syscalla (np. czekanie na klawiaturę).
    if sched::should_exit() {
        record_exit(ExitKind::Killed, frame.rip, frame.rax, frame.rbx);
        exit_current();
    }
    // SYSRET z niekanonicznym RIP = #GP w ring 0 na stosie użytkownika.
    if frame.rip >= USER_SPACE_END {
        record_exit(ExitKind::BadReturn, frame.rip, frame.rax, frame.rbx);
        exit_current();
    }
    // Do procesu wracają tylko flagi arytmetyczne i DF; IF zawsze 1.
    frame.rflags = (frame.rflags & 0xED5) | 0x202;
    interrupts::disable();
    if nr < super::prof::SYSCALLS {
        super::prof::stop(nr, t0);
    }
    // M17: SYSRET do procesu – wyjście z kernela (bez BKL, jeśli był wzięty;
    // ścieżki bez BKL go nie mają).
    if crate::sched::bkl::held() {
        crate::sched::bkl::release();
    }
}
