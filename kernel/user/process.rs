// M14: proces użytkownika – przestrzeń adresowa + deskryptory plików.
// M16: rodzic (ppid) i dziedziczenie wejścia/wyjścia przez dzieci.
//
// Należy do zadania schedulera (Task.process).  Pola zwykłe zmienia tylko
// to zadanie (syscalle), więc bez blokad.  `ppid` i `exiting` są atomowe –
// zmienia je też kończący się rodzic (przekazanie dzieci do init) pod
// blokadą tablicy zombie (procs.rs).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::space::AddressSpace;
use super::syscalls::EBADF;
use crate::console::SerialDecoder;
use crate::sched::sync::Mutex;
use crate::sched::TaskId;

/// Testy: wejście procesu z bufora zamiast z klawiatury (wspólne z dziećmi,
/// jak terminal).
pub type InBuf = Arc<Mutex<VecDeque<u8>>>;
/// Testy: wyjście procesu do bufora zamiast na ekran (wspólne z dziećmi).
/// M17a.d: SpinLock (nie usypiający Mutex) – `write` działa bez BKL.
pub type OutBuf = Arc<crate::sched::spin::IrqSpinLock<Vec<u8>>>;

/// M17b.a: otwarty plik – obiekt wspólny dla wszystkich deskryptorów, które
/// na niego wskazują (dup, dup2, deskryptory dziecka przy spawn): jedna
/// pozycja, jak w Uniksie (`echo a > f; echo b >> f` w jednym skrypcie,
/// `(cmd1; cmd2) > f`).  Pozycja pod Mutexem (usypiającym) – trzymana przez
/// cały odczyt / zapis, więc dwa procesy piszące przez wspólny obiekt nie
/// nadpisują sobie danych.
pub struct OpenFile {
    pub path: String,
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub offset: Mutex<u64>,
}

/// M18.b: prawa uchwytu (bity).  Prawa można tylko zmniejszyć (handle_dup);
/// brak READ / WRITE przy read / write = EBADF (jak w POSIX), brak
/// pozostałych = EACCES.  Projekt: ARCHITEKTURA.md, „IPC”.
pub mod rights {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const SEND: u32 = 4;
    pub const RECV: u32 = 8;
    pub const MAP_READ: u32 = 16;
    pub const MAP_WRITE: u32 = 32;
    pub const DUP: u32 = 64;
    pub const TRANSFER: u32 = 128;
    pub const ALL: u32 = 0xFF;
}

/// M18.b: rodzaj obiektu w `handle_info`.
pub mod kind {
    pub const CONSOLE: u64 = 1;
    pub const FILE: u64 = 2;
    pub const PIPE: u64 = 3;
    pub const CHANNEL: u64 = 4;
    pub const SHM: u64 = 5;
    /// M19.c: dostęp do sprzętu (tylko init) i przejęte urządzenie PCI.
    pub const HW_ROOT: u64 = 6;
    pub const DEVICE: u64 = 7;
    /// M19.d: przerwanie urządzenia przypięte do usługi.
    pub const IRQ: u64 = 8;
    /// M19.i: akcje systemowe (reboot, halt, sync, stress) – syscall sysctl.
    pub const SYSCTL: u64 = 9;
}

/// M18.b: wpis tablicy uchwytów procesu – obiekt + prawa.
#[derive(Clone)]
pub struct Handle {
    pub obj: Fd,
    pub rights: u32,
}

impl Handle {
    /// Uchwyt z prawami wynikającymi z obiektu (zachowanie sprzed M18).
    pub fn new(obj: Fd) -> Handle {
        use rights::*;
        let io = match &obj {
            Fd::Console => READ | WRITE,
            Fd::File(f) => (if f.read { READ } else { 0 }) | (if f.write { WRITE } else { 0 }),
            Fd::Pipe(e) => {
                if e.write {
                    WRITE
                } else {
                    READ
                }
            }
            Fd::Channel(_) => SEND | RECV,
            Fd::Shm(_) => MAP_READ | MAP_WRITE,
            Fd::Device(_) => MAP_READ | MAP_WRITE,
            Fd::Irq(_) => RECV,
            // M19.c: bez DUP i TRANSFER – nie da się go skopiować, przekazać
            // dziecku ani wysłać; zostaje tam, gdzie dało go jądro (init).
            Fd::HwRoot => return Handle { obj, rights: 0 },
            // M19.i: tylko DUP – init daje kopię shellowi (spawn_ex), ale nie
            // da się go wysłać w komunikacie.
            Fd::Sysctl => return Handle { obj, rights: DUP },
        };
        Handle { obj, rights: io | DUP | TRANSFER }
    }

    pub fn kind(&self) -> u64 {
        match self.obj {
            Fd::Console => kind::CONSOLE,
            Fd::File(_) => kind::FILE,
            Fd::Pipe(_) => kind::PIPE,
            Fd::Channel(_) => kind::CHANNEL,
            Fd::Shm(_) => kind::SHM,
            Fd::HwRoot => kind::HW_ROOT,
            Fd::Device(_) => kind::DEVICE,
            Fd::Irq(_) => kind::IRQ,
            Fd::Sysctl => kind::SYSCTL,
        }
    }
}

#[derive(Clone)]
pub enum Fd {
    /// Konsola (0 = wejście, 1/2 = wyjście).
    Console,
    /// Plik z VFS – obiekt wspólny dla kopii deskryptora (M17b.a).
    File(Arc<OpenFile>),
    /// M17b.b: koniec potoku (do odczytu albo zapisu).
    Pipe(Arc<super::pipe::PipeEnd>),
    /// M18.c: koniec kanału (komunikaty w obie strony).
    Channel(Arc<super::channel::ChanEnd>),
    /// M18.e: obiekt pamięci współdzielonej.
    Shm(Arc<super::shm::ShmObj>),
    /// M19.c: dostęp do sprzętu – z niego dev_claim; ma go tylko init.
    HwRoot,
    /// M19.c: urządzenie PCI przejęte przez usługę.
    Device(Arc<super::device::DevClaim>),
    /// M19.d: przerwanie urządzenia (licznik + pobudka w wait_many).
    Irq(Arc<super::device::IrqObj>),
    /// M19.i: prawo do akcji systemowych (sysctl) – tworzy je tylko jądro dla init.
    Sysctl,
}

pub struct Process {
    pub space: AddressSpace,
    /// M17b.d: obszary pamięci (sterta, mmap, stos) – leniwy przydział stron.
    pub mem: super::vm::ProcMem,
    /// M18.b: tablica uchwytów (dawniej deskryptory) – numer = indeks.
    pub(super) fds: Vec<Option<Handle>>,
    pub(super) stdin: Option<InBuf>,
    pub(super) stdout: Option<OutBuf>,
    /// M17a.e: ten proces utworzył bufor stdout (dzieci go tylko dziedziczą) –
    /// tylko on (albo ostatni właściciel) zapisuje wyjście do dziennika.
    pub(super) stdout_creator: bool,
    pub syscalls: u64,
    /// M15: RSP na starcie (ELF: wskazuje argc) i katalog bieżący
    /// (ścieżki względne w open).
    pub initial_rsp: u64,
    pub cwd: String,
    /// Proces na pierwszym planie: Ctrl+C go kończy; normalny koniec bez
    /// komunikatu kernela.
    pub foreground: bool,
    /// M16: rodzic (0 = kernel – shell kernela, testy, nadzorca init).
    pub ppid: AtomicU64,
    /// M16: proces się kończy (dzieci przekazane dalej) – nowe zombie już
    /// nie trafiają do niego.
    pub exiting: AtomicBool,
    /// M17a.g11: proces miał (albo dostał od kończącego się rodzica) dzieci –
    /// bez tego koniec procesu pomija przegląd listy zadań (reparent).
    pub has_children: AtomicBool,
    /// M17a.g15: żywe dzieci (spawn +1, koniec dziecka −1, przejęte w
    /// reparent +n).  Koniec dziecka zmienia go pod blokadą `zombies`
    /// rodzica razem z wpisem zombie – `wait` czyta go pod tą blokadą.
    pub live_children: core::sync::atomic::AtomicU32,
    /// P1: zakończone dzieci czekające na `wait` (dawniej jedna globalna
    /// tablica ZOMBIES pod usypiającą blokadą – na Legionie 168 s czekania w
    /// minucie pełnego obciążenia).  Teraz każdy rodzic ma swoją listę
    /// (procs::ChildList – lekka blokada, patrz asercja niżej).
    pub(super) zombies: super::procs::ChildList,
    /// P1: rośnie przy każdym nowym zombie dla tego procesu (warunek czekania
    /// w `wait` bez blokady).
    pub child_gen: AtomicU64,
    /// M16: dekoder klawiszy dla readkey z bufora stdin (testy).
    pub(super) key_decoder: SerialDecoder,
}

/// M18.e: mapowania pamięci współdzielonej zdejmowane, ZANIM pola się zwolnią
/// – Drop przestrzeni adresowej oddaje każdą zamapowaną ramkę, a ramki
/// obiektu należą do obiektu (inne procesy mogą jej jeszcze używać).
impl Drop for Process {
    fn drop(&mut self) {
        self.mem.release_shared(&mut self.space);
    }
}

// P1 (v0.20.2): Process idzie szybką ścieżką heapa (klasy do 2 KiB, wyrównanie
// do 16 B) – pole z wyrównaniem 64 (np. IrqSpinLock) przeniosłoby każdy
// proces na wolną, globalną listę bloków.
const _: () = assert!(core::mem::align_of::<Process>() <= 16 && core::mem::size_of::<Process>() <= 2048);

impl Process {
    pub fn new(space: AddressSpace) -> Self {
        let mut fds = Vec::new();
        fds.push(Some(Handle::new(Fd::Console))); // 0 stdin
        fds.push(Some(Handle::new(Fd::Console))); // 1 stdout
        fds.push(Some(Handle::new(Fd::Console))); // 2 stderr
        Process {
            space,
            // Programy asm (testy): sterta za stroną danych; ELF – za obrazem
            // (spawn ustawia `mem` na nowo).
            mem: super::vm::ProcMem::new(super::USER_DATA + 4096),
            fds,
            stdin: None,
            stdout: None,
            stdout_creator: false,
            syscalls: 0,
            initial_rsp: super::USER_STACK_TOP,
            cwd: String::from("/"),
            foreground: false,
            ppid: AtomicU64::new(0),
            exiting: AtomicBool::new(false),
            has_children: AtomicBool::new(false),
            live_children: core::sync::atomic::AtomicU32::new(0),
            zombies: super::procs::ChildList::new(),
            child_gen: AtomicU64::new(0),
            key_decoder: SerialDecoder::new(),
        }
    }

    pub fn ppid(&self) -> TaskId {
        self.ppid.load(Ordering::SeqCst)
    }

    pub(super) fn fd(&self, fd: u64) -> Result<&Fd, i64> {
        self.handle(fd).map(|h| &h.obj)
    }

    /// M18.b: uchwyt (obiekt + prawa).
    pub(super) fn handle(&self, fd: u64) -> Result<&Handle, i64> {
        self.fds.get(fd as usize).and_then(|f| f.as_ref()).ok_or(EBADF)
    }

    pub(super) fn is_console(&self, fd: u64) -> bool {
        matches!(self.fds.get(fd as usize), Some(Some(Handle { obj: Fd::Console, .. })))
    }

    /// Liczba otwartych plików (3+).
    #[allow(dead_code)]
    pub fn open_files(&self) -> usize {
        self.fds.iter().skip(3).filter(|f| f.is_some()).count()
    }
}
