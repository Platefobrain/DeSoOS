# Architektura DeSoOS

Opis tego, jak system jest zbudowany i jak działa (stan: v0.22.0, M19 gotowe, poprawki wydajności w toku). Historia zmian: `CHANGELOG.md`,
plan etapów: `roadmapa`.

## W skrócie

DeSoOS to jądro x86_64 w Rust, startujące z UEFI (własny bootloader DSB), na wiele rdzeni (do 16).

**Modularny monolit teraz, hybryda docelowo. Priorytet: szybkość.**

- W jądrze zostaje wszystko, przez co przechodzi prawie każdy syscall albo co musi zdążyć z przerwaniem
  (pamięć, scheduler, IPC, VFS, podstawowe sterowniki).
- Do user space trafia to, co duże, ryzykowne i poza ścieżką krytyczną (sieć, USB, audio, GUI).
- Każdy sterownik stoi za wspólnym interfejsem (`BlockDevice`, `input`, `console`, `FileSystem`), więc
  przeniesienie do user space to wymiana implementacji, nie przepisywanie systemu.
- **Najpierw mierzyć, potem zmieniać.** Każda decyzja wydajnościowa opiera się na profilu i stressie
  na prawdziwym sprzęcie (Lenovo Legion, 16 CPU).
- **W jądrze nic „pod AI”.** Jądro pilnuje uprawnień (uchwyty); agent będzie zwykłym programem (patrz
  „Kierunek: agent DeSo AI”).

Dlaczego nie czyste mikrojądro: wszystko zależy od IPC, a bez IOMMU sterownik z DMA i tak może zapisać
dowolną pamięć. Dlaczego nie monolit na zawsze: błąd w dużym, opcjonalnym sterowniku wywraca cały system.

## Podział

```
                              DeSoOS
                                │
        ┌───────────────────────┴───────────────────────┐
     KERNEL                                         USER SPACE
        │                                               │
   syscalle + uchwyty ────────── granica ─────── init, shell, programy (/bin)
        │                                               │
  ┌─────┼──────────┬──────────┬────────────┐       usługi (M19+)
  MM   Scheduler  IPC        VFS       sterowniki   ┌────┼─────┐
  │    + blokady  kanały,     │        (konsola,    USB  NET  AUDIO
  │               pamięć   page cache   PS/2, PCI,       │
  │               wspólna     │         NVMe, virtio)    │
  │                  ╚════════╪══════ dane: wspólna pamięć ══╡
  │                         block                         │
  │     delegacja sprzętu: MMIO, IRQ→kanał, DMA, (IOMMU) ═╛  sterowanie
  │
  └──────── arch / SMP: per-CPU, APIC, IPI, spinlocki, TLB shootdown ────────
```

| Komponent | Gdzie | Dlaczego / warunek |
|---|---|---|
| pamięć, scheduler, syscalle, IPC | kernel | rdzeń systemu |
| przerwania, zegary, SMP | kernel | muszą zdążyć na czas |
| konsola, serial, framebuffer, PS/2 | kernel | potrzebne do startu i diagnostyki |
| PCI, dyski (virtio, NVMe), GPT | kernel | ścieżka każdego odczytu pliku |
| VFS, page cache, FAT32, przyszły natywny FS | **kernel na stałe** | każde `open`/`read`/`write` |
| init, shell, narzędzia | user space | od M16 |
| sieć | user space | tylko z kolejkami (jak virtio/io_uring), nigdy IPC na pakiet |
| USB + HID | do decyzji po M19 | klawiatura laptopa jest na USB – padnięta usługa = brak klawiatury |
| audio, GUI, egzotyczne FS | user space | ring buffery / powierzchnie we wspólnej pamięci; FS przez VFS (jak FUSE) |

**System plików zostaje w jądrze:** FS w user space to droga proces → kernel → serwer FS → kernel → dysk
przy każdym wywołaniu – to spowolniło wczesne mikrojądra. Linux, Windows i macOS trzymają VFS w kernelu.

**Zasada IPC: komunikat to sterowanie, dane idą przez wspólną pamięć** – ring buffer u obu stron, wiele
żądań w paczce, powiadomienie tylko gdy kolejka była pusta. Wywołanie w jądrze kosztuje ns, rozmowa z usługą
µs (Legion: ping-pong 6,6 µs) – klawiaturze to nie przeszkadza, dyskowi i sieci tak.

## Pamięć

**Przestrzeń adresowa:**

| Adres | PML4 | Co |
|---|---|---|
| `0x0000_0000_0000_0000 ..` | 0..255 | proces (własny PML4): ELF od `0x40_0000`, sterta (brk), obszary mmap od `0x1000_0000_0000`, stos pod `0x7fff_ffff_0000` (rośnie do 8 MiB) |
| `0xffff_8000_0000_0000` | 256..383 | direct map: fizyczny X pod tym adresem + X |
| `0xffff_c000_0000_0000` | 384 | heap jądra (max 64 MiB) |
| `0xffff_d000_0000_0000` | 416 | obszar on-demand |
| `0xffff_e000_0000_0000` | 448 | stosy zadań: slot 1 MiB, zamapowane górne 64 KiB, reszta = strażnik |
| `0xffff_ff00_0000_0000` | 510 | mapowanie rekurencyjne |
| `0xffff_ffff_8000_0000` | 511 | obraz jądra (kod tylko do odczytu), potem strażnik + stos 256 KiB |

Górna połowa jest wspólna (wpisy 256..511 alokowane od startu), więc zmiana CR3 podmienia tylko proces.
Ochrona: NX, SMEP, SMAP, CR0.WP, W^X dla programów.

- **Ramki** – bitmapa, ramki 4 KiB i ciągłe (DMA); `IrqSpinLock`. Od v0.22.0 każdy CPU ma zapas do 64 wolnych
  ramek (paczki po 32 spod blokady, IF = 0) – pojedyncze `alloc_frame` / `free_frame` bez blokady. Druga,
  atomowa bitmapa „wydana” pilnuje bez blokady, że oddawana ramka naprawdę była wydana (double-free,
  rezerwacje, adresy spoza RAM-u – odmowa). Ramki w zapasach liczą się jako wolne. Ciągłe przedziały – spod
  blokady, jak dotąd.
- **Heap jądra** – bloki do 32 KiB (wyrównanie ≤ 16) w klasach 16 B..32 KiB (potęgi 2; od v0.21.0 także
  4–32 KiB): każdy CPU ma własną listę wolnych bloków na klasę (bez blokady, IF = 0; duże klasy po 2–8
  bloków), z heapem wymienia paczki. Większe bloki i wyrównanie > 16 (np. struktury z `SpinLock`, linia
  cache 64 B) – wspólna lista po adresie (first-fit, scalanie) pod jedną blokadą: tego trzeba unikać w
  gorących ścieżkach.
  Heap rośnie i oddaje strony od końca. Zasada (M17b: jedna blokada heapa zjadała 83% CPU Legiona):
  **gorący alokator nie ma globalnej blokady na każdą operację.**
- **Stosy zadań** – 64 KiB ze stroną-strażnikiem; stos zakończonego zadania zostaje zamapowany i wraca przy
  następnym spawn (bez zerowania i TLB shootdown).
- **Pamięć procesu** (`kernel/user/vm.rs`) – lista obszarów (sterta, mmap, stos, wspólne). Strona powstaje
  wyzerowana przy pierwszym dostępie (#PF z ring 3 albo `copy_from_user`/`copy_to_user`). `brk` do 1 GiB,
  `mmap`/`munmap` anonimowe, razem do 4 GiB. Proces jest jednowątkowy, więc jego obszary i tablice zmienia
  tylko on – bez blokad. #PF z ring 3 działa na stosie zadania (bez IST), przepełnienie stosu jądra → #DF (IST).
- **Obszary wspólne** – strony obiektu pamięci współdzielonej, mapowane od razu, zawsze NX; ramki należą do
  obiektu, nie do procesu (patrz IPC).

## Procesy i programy

```
kernel ── uruchamia ──> /bin/init ──> /bin/sh ──> programy (ls, primes &, a | b ...)
                            ^                         |
                            └── sieroty ──────────────┘
```

- Jądro uruchamia tylko `/bin/init` (pada → start od nowa; 3 razy w 10 s → awaryjny shell jądra). Init
  uruchamia shell i usługi (menedżer usług, 19.g), zbiera sieroty; `kill(init)` → EPERM.
- **`spawn` zamiast `fork`/`exec`** – nowy obraz ELF, kopia cwd, wskazane uchwyty. `spawn_ex` daje dziecku
  **tylko** wymienione uchwyty (podstawa sandboxa).
- Zakończony proces zostaje zombie (sam kod wyjścia) do `wait` rodzica. Status: kod 0..255 albo
  `0x100 | powód` (9 = kill, 14 = #PF). Od v0.20.0 zombie leżą **w procesie-rodzicu** (`Process.zombies`,
  spinlock na rodzica) zamiast w jednej globalnej tablicy: dziecko dopisuje się pod blokadą schedulera
  (`with_process` na rodzicu – sprawdza, że rodzic się nie kończy i wciąż jest jego rodzicem), kończący się
  rodzic w jednej sekcji ustawia `exiting`, zabiera swoje zombie i oddaje żywe dzieci (`reparent_with`), a
  zombie przekazuje init; `wait` bierze tylko blokadę własnej listy. Lista ma 4 wpisy w samym procesie
  (bez heapa), dalsze w `Vec`. Blokada listy to jeden bajt (nie `IrqSpinLock` – ten ma wyrównanie 64 B i
  zepchnąłby każdy `Process` na wolną ścieżkę heapa; pilnuje tego asercja w czasie kompilacji: `Process`
  ≤ 2 KiB, wyrównanie ≤ 16). Rodzic czeka w jednej z 64 kolejek,
  warunek: własny licznik `child_gen`.
- **Ctrl+C** kończy proces z wierzchu stosu pierwszego planu, nie shell.
- **Programy** – statyczne ELF64 w Rust (`user/bin/*.rs`, biblioteka `user/lib/desoos.rs`), wbudowane w obraz
  jądra i rozpakowane do ramfs jako `/bin/<nazwa>`. Loader: tylko dolna połowa od 1 MiB, W^X, stos jak
  System V (argc, argv). Alokator biblioteki na `brk` (małe bloki) i `mmap` (duże).
- Shell: potoki `a | b | c`, `>`, `>>`, `<`, cudzysłowy, historia, `&`.

## Syscalle i uchwyty

`SYSCALL`/`SYSRET`; numer w RAX, argumenty RDI, RSI, RDX, R10, R8, R9; wynik w RAX (ujemny = errno jak
w Linuksie). Pamięć procesu tylko przez `copy_from_user`/`copy_to_user` (sprawdzenie stron + SMAP).
Prawie wszystkie syscalle działają bez Big Kernel Lock (99% w stressie).

| Nr | Wywołania |
|---|---|
| 0–8 | `exit`, `write`, `read`, `open`, `close`, `getpid`, `sleep`, `yield`, `uptime` |
| 9–12 | `spawn`, `wait`, `getppid`, `kill` |
| 13–18 | `chdir`, `getcwd`, `readdir`, `stat`, `mkdir`, `unlink` |
| 19–20 | `readkey` (edytor linii), `tasks` (ps); 21 wolny (do v0.19.6 `kcmd`) |
| 22–25 | `dup`, `dup2`, `seek`, `pipe` |
| 26–28 | `brk`, `mmap`, `munmap` |
| 29–30 | `handle_dup`, `handle_info` |
| 31–33 | `channel_create`, `chan_send`, `chan_recv` |
| 34, 35, 37 | `shm_create`, `shm_map`, `shm_size` |
| 36 | `spawn_ex` |
| 38 | `wait_many` (M19.b) |
| 39–41 | `dev_claim`, `dev_info`, `dev_map` (M19.c) |
| 42–43 | `irq_bind`, `irq_read` (M19.d) |
| 44–45 | `dma_alloc`, `dma_phys` (M19.e) |
| 46–47 | `sysinfo` (tylko odczyt), `sysctl` (reboot, halt, sync, stress – z uchwytem SYSCTL) (M19.i) |

**Uchwyty.** Tablica procesu (64 wpisy; 0/1/2 = wejście/wyjście/błędy) – każdy wpis to obiekt + prawa.
Obiekty: konsola, plik (`OpenFile` – pozycja wspólna dla kopii, jak w Uniksie), koniec potoku (bufor 64 KiB),
koniec kanału, obiekt pamięci współdzielonej. Obiekty liczone przez `Arc` – żyją, dopóki ktoś je widzi.

| Prawo | Dla | Znaczenie |
|---|---|---|
| `READ`, `WRITE` | konsola, plik, potok | brak → `EBADF` (jak POSIX) |
| `SEND`, `RECV` | kanał | brak → `EACCES` |
| `MAP_READ`, `MAP_WRITE` | pamięć współdzielona | brak → `EACCES` |
| `DUP` | wszystkie | wolno skopiować (`dup`, `handle_dup`, uchwyt dla dziecka) |
| `TRANSFER` | wszystkie | wolno przekazać w komunikacie |

**Prawa można tylko zmniejszyć** (`handle_dup(h, maska)`); nie ma operacji, która je dodaje.

## IPC

Procesy rozmawiają przez **kanały** (małe komunikaty, sterowanie) i **pamięć współdzieloną** (dane).

**Kanał** (`kernel/user/channel.rs`) – para końców, dwukierunkowy, każdy koniec ma swoją kolejkę.

- Komunikat: do 4 KiB danych + do 8 uchwytów; kolejka do 64 komunikatów. **Nadawcę (pid) wpisuje jądro** –
  nie do podrobienia.
- Uchwyty w komunikacie są **przenoszone** (znikają u nadawcy, wymagają `TRANSFER`); lista sprawdzana w
  całości przed zdjęciem czegokolwiek, przy błędzie wracają na miejsce. Żaden koniec kanału nie może podróżować
  przez ten sam kanał (cykl, który nigdy by się nie zwolnił).
- Pełna kolejka / pusta kolejka: czekanie albo `EAGAIN` (`CHAN_NONBLOCK`). Za mały bufor (`EMSGSIZE`) albo
  brak miejsca na uchwyty (`EMFILE`) – komunikat **zostaje** w kolejce, w `info` wymagany rozmiar. Druga strona
  zamknięta: `EPIPE`. Kill / Ctrl+C przerywa czekanie.
- Zamknięcie ostatniego uchwytu końca zwalnia komunikaty z jego kolejki (z uchwytami w środku) i budzi drugą
  stronę.

**Pamięć współdzielona** (`kernel/user/shm.rs`) – obiekt do 16 MiB, ramki brane od razu i zerowane.

- `shm_map(h, prot)` mapuje cały obiekt od razu w obszarze mmap; **nigdy wykonywalny**, zapis tylko z
  `MAP_WRITE`. `munmap` tylko w całości.
- **Ramki należą do obiektu.** Koniec procesu najpierw zdejmuje mapowania wspólne (`release_shared`), dopiero
  potem zwalnia swoją przestrzeń; ramki wracają, gdy znika ostatni uchwyt i ostatnie mapowanie.
- „Dane gotowe” sygnalizuje krótki komunikat w kanale (dzwonek). Futex i ring buffery w bibliotece – gdy
  pomiar pokaże potrzebę.

**Zasady w kodzie IPC:** każdy kanał ma własną blokadę (poziom PROCESS), żadnej globalnej blokady IPC; dane
z procesu kopiowane przed wzięciem blokady, do procesu po jej zwolnieniu; pod blokadą tylko kolejka, bez snu.

**Pomiar (Legion, 16 CPU):** ping-pong 6,6 µs, kanał 165–190 tys. komunikatów 4 KiB/s (645–744 MB/s),
16 MiB kanałem 21–25 ms / wspólną pamięcią 5 ms. Stress z ciągłą komunikacją procesów (zabijanych w trakcie
czekania) nie spowalnia reszty systemu.

Znane ograniczenie: cykl uchwytów przez kolejki kilku kanałów zostaje w pamięci (opisany, nie wykrywany).

## Wiele rdzeni

```
BSP (CPU 0)                         AP (CPU 1..15)
PIT 1000 Hz: czas, pobudki          timer LAPIC 100 Hz: kwant
I/O APIC + MSI: przerwania urządzeń IPI: resched, TLB shootdown, halt (panic)
```

- **Start AP**: INIT-SIPI-SIPI → trampolina < 1 MiB → od razu 64 bity → własna GDT/TSS/IST, IDT, FPU,
  SMEP/SMAP, SYSCALL, LAPIC. Numer CPU: `rdtscp` (TSC_AUX), bo GS należy do procesu.
- **Scheduler**: kolejka gotowych (FIFO), per CPU `current` i kwant 10 ms. Zadanie gotowe → bezczynny CPU
  (IPI) albo wywłaszczenie. Listy (gotowe, kanały WaitQueue, śpiący z terminem) są wbudowane w `Task` –
  **pod blokadą schedulera nic nie alokuje**. `WaitQueue` sprawdza warunek i usypia pod blokadą schedulera,
  więc pobudka z innego CPU nie przepada.
- **Blokady**:
  - *Big Kernel Lock* – już tylko rzadkie ścieżki (wyjątki z ring 3, klawiatura PS/2, `tasks`, zwolnienie
    przestrzeni procesu w reap).
  - *Blokada schedulera* – rekurencyjna na CPU, trzymana przez przełączenie zadań, zawsze z IF = 0.
  - *SpinLock / IrqSpinLock* – krótkie sekcje; blokada brana i z BKL, i bez niego musi być `IrqSpinLock`.
  - *RwSpinLock* – czytane często, sekcje µs (drzewo ramfs).
  - *KMutex / KRwLock* – usypiające (tablica procesów, VFS), krótkie kręcenie przed snem, pobudka jednego
    czekającego.
- **Kolejność blokad** (sprawdzana – złamanie = panic z nazwami i miejscami):

| Poziom | Blokada |
|---|---|
| — | Big Kernel Lock (zawsze zewnętrzna) |
| 20 | VFS |
| 30 | warstwa block, sterowniki dysków |
| 40 | procesy (deskryptory), potoki, kanały |
| 45 | obserwatorzy `wait_many` (`IrqSpinLock`) |
| 50 | scheduler (poza lockdep, rekurencyjna) |
| (52) | zombie dzieci w procesie-rodzicu – własna jednobajtowa blokada z IF = 0, poza lockdep (pod schedulerem albo sama; nigdy dwie naraz) |
| 55 | tablice stron, strony stosów zadań |
| 100 | wyjście procesów (przechwycone stdout, linia shella) |
| 230 / 240 | heap / alokator ramek (wolno alokować zewsząd, także z przerwania) |
| 250 / 255 | TLB shootdown / konsola (logować wolno zawsze) |

  Trzymając spinlock nie wolno spać, czekać na BKL ani robić `hlt`.
- **TLB shootdown** (górna połowa): wyczyść PTE → IPI do pozostałych CPU + czekanie na potwierdzenie →
  dopiero zwolnij ramkę. CPU czekający z IF = 0 obsługuje żądanie sam. Dolna połowa bez shootdownu – proces
  działa naraz na jednym CPU (wątki – później).
- **Czas**: HPET to jedyny wspólny licznik – **TSC rdzeni nie są zgrane** (Legion), więc pomiary liczy się na
  jednym CPU (czas CPU zadania). Ticki PIT doganiają HPET, zegar ścienny = RTC przy starcie + uptime.
- **Dane per CPU** w osobnych liniach cache (`PerCpu`, `PerCpuCounter`) – gęste tablice atomików dawały
  false sharing (7–15% przepustowości).
- **Watchdog**: zegar stoi 10 s → NMI do wszystkich CPU i raport (właściciel BKL, RIP, IF, spinlocki).
  Detektor zakleszczeń spinlocków (HPET): raport po 2 s, panic po 10 s.
- **FPU/SSE**: zapis i odtworzenie przy każdym przełączeniu – migracja procesu nic więcej nie wymaga.

## Pliki

- **VFS** (`kernel/fs/`) z punktami montowania; `/` = ramfs, `/disk` = FAT32, `/esp` = partycja EFI.
- `FS_LOCK` to blokada czytelnicy–pisarz; systemy z własnymi blokadami (ramfs) działają pod nią współbieżnie,
  FAT32 (bufory, dysk) – pod blokadą do zapisu. ramfs: drzewo pod `RwSpinLock`, zawartość pliku pod jego
  Mutexem (usunięty plik żyje, dopóki ktoś go czyta).
- FAT32: długie nazwy (także polskie), `mkfs`, kontrola wycieku klastrów.

## Sprzęt i ochrona danych

- **ACPI** – tylko tablice (bez AML): MADT (rdzenie, I/O APIC), MCFG (PCIe ECAM), HPET.
- **PCI** – porty, potem ECAM (gdy zgodny z portami). Przerwania urządzeń przez **MSI/MSI-X** (INTx wymaga AML).
  Linie ISA (zegar, klawiatura, serial, mysz) przez I/O APIC; PIC 8259 zamaskowany.
- **Dyski** – virtio-blk, NVMe (kolejka admin + I/O), partycje GPT jako osobne dyski.
- **Wejście/wyjście** – framebuffer z UEFI (konsola tekstowa z polskimi znakami, scrollback), serial, PS/2 (klawiatura, mysz).
  USB dopiero w M20 (klawiatura Legiona jest na USB).

**Ochrona danych na prawdziwym sprzęcie** – dwie niezależne bariery:

1. sterownik NVMe zapisuje tylko do kontrolera emulowanego przez QEMU; prawdziwy SSD jest tylko do odczytu,
2. warstwa block odrzuca każdy zapis na dysk tylko do odczytu (partycje, `mkfs`, pliki → EROFS).

Pendrive startowy jest dla DeSoOS niewidoczny (brak USB).

## Usługi w user space (M19 – projekt 19.a)

Cel: sterownik urządzenia jako zwykły proces. Jądro daje mu dostęp do **jednego** urządzenia – przez uchwyty,
jak wszystko od M18. Awaria usługi nie rusza jądra ani innych procesów, init uruchamia ją ponownie.

```
 jądro                                   init (ma HW_ROOT)                usługa /bin/edud
 ──────                                  ─────────────────                ────────────────
 tablica PCI, właściciel urządzenia ◄── dev_claim(root, 00:06.0) ──► uchwyt DEVICE ─spawn_ex─► slot 3
 MSI → obiekt IRQ (licznik, pobudka) ─────────────────────────────────────────► wait_many: IRQ
 ramki DMA (ciągłe, < limit adresu)  ◄── dma_alloc(dev, rozmiar) ─────────────── mapuje, wpisuje adres
 rejestry BAR (UC, NX) ──────────────────── dev_map(dev, bar) ─────────────────► MMIO w procesie
                                         klient ── "edu" + koniec kanału ──► init ──► usługa
```

### Czekanie na wiele uchwytów – `wait_many` (19.b)

Usługa czeka naraz na prośby wielu klientów (każdy ma własny kanał) i na przerwanie. `wait_many(lista, n,
timeout_ms)` – lista do 16 par [uchwyt, sygnały]; zwraca maskę gotowych (bit i = wpis i), 0 = timeout.

| Sygnał | Gotowy, gdy |
|---|---|
| `READABLE` | kanał: jest komunikat albo druga strona zamknięta; potok: dane albo brak piszących |
| `WRITABLE` | kanał / potok: jest miejsce albo druga strona zamknięta |
| `IRQ` | obiekt przerwania: licznik > 0 |

Wymaga prawa `RECV` / `SEND` / `READ` (jak operacja, na którą czekamy). Kill / Ctrl+C przerywa (EINTR).
**Jak działa:** każdy obiekt, na który da się czekać (koniec kanału, potok, IRQ), ma listę obserwatorów (do 16
zadań) pod swoją blokadą. `wait_many` zapisuje zadanie u każdego obiektu, sprawdza warunki i śpi na własnym
kanale WaitQueue (numer zadania); zmiana stanu obiektu budzi obserwatorów. Po pobudce – wypisanie się ze
wszystkich. Bez przeglądania wszystkich zadań, bez globalnej blokady. Pobudka nie ginie, bo zapis do listy
następuje przed sprawdzeniem warunku (jak w KMutex).
Kod: `kernel/user/waitset.rs` (`Observers`, `IrqSpinLock` poziom `WAITERS` = 45), `syscalls.rs`
(`sys_wait_many`). Licznik obserwatorów w atomiku – obiekt bez czekających nie bierze blokady listy.

### Urządzenie jako uchwyt (19.c)

- **`HW_ROOT`** (rodzaj 6) – jedyny obiekt, z którego można wyjąć urządzenie. Jądro tworzy go raz i daje
  **tylko** `/bin/init` (slot 3). Init nie przekazuje go dalej; usługi dostają pojedyncze urządzenia.
- **`dev_claim(root, adres PCI)`** → uchwyt `DEVICE` (rodzaj 7; prawa `MAP_READ|MAP_WRITE|DUP|TRANSFER`).
  Jedno urządzenie – jeden właściciel naraz (`EBUSY`). Odmowa (`EACCES`):
  - urządzenie ma sterownik w jądrze (dysk virtio, NVMe, karta grafiki z framebufferem),
  - klasa pamięci masowej (0x01) – **zawsze**, także bez sterownika (ochrona dysków na prawdziwym sprzęcie),
  - mostki (0x06) i kontroler przerwań – zmiana ich ustawień psuje cały system.
- **`dev_info(dev, out)`** – vendor, device, klasa, rozmiary BAR-ów, czy jest MSI.
- **`dev_map(dev, bar)`** → adres w obszarze mmap procesu: rejestry BAR-u pamięci, **bez cache (UC), nigdy
  wykonywalne**. Strony z tablicą MSI-X / PBA są pomijane – zapis tam mógłby skierować przerwanie na dowolny
  wektor (np. IPI jądra). Porty I/O (BAR typu I/O) – później, bitmapa w TSS.
- Przestrzeni konfiguracyjnej PCI usługa nie zapisuje (BAR-y, MSI, bus mastering ustawia jądro).
- Kod (19.c): `kernel/user/device.rs` (`DevClaim`, strony BAR-u), `drivers/pci.rs` (`OWNERS`, `claim_user`,
  `msix_regions`), `vm.rs` (`map_mmio`, `SharedRef`). BAR musi mieć ≥ 4 KiB i być wyrównany do strony.
  Mapowanie trzyma przejęcie; koniec procesu zdejmuje mapowania wspólne już w `exit_current` – urządzenie jest
  wolne, zanim rodzic (menedżer usług) dostanie status z `wait`. Syscalle `dev_*` pod BKL (konfiguracja PCI
  przez porty). `lspci` pokazuje właściciela urządzenia.

### Przerwania (19.d)

- **`irq_bind(dev)`** → uchwyt `IRQ` (rodzaj 8). Jądro bierze wektor MSI (0x30–0x3F; teraz z
  **zwalnianiem** – usługa może się restartować), wpisuje go w urządzenie, włącza MSI.
- Handler w jądrze: licznik +1 i pobudka obserwatorów – nic więcej (bez blokad poza listą obserwatorów,
  `IrqSpinLock`, poziom wysoki). MSI jest zboczowe, więc nie trzeba maskować linii.
- `irq_read(irq)` → ile przerwań od ostatniego odczytu (zeruje). Kilka przerwań przed obsługą = jedna pobudka
  z licznikiem; nic się nie piętrzy. Licznik to „co najmniej jedno” – przerwania tego samego wektora, które
  przyjdą, zanim procesor obsłuży poprzednie, APIC łączy w jedno (licznik bywa mniejszy niż liczba zgłoszeń).
  Usługa po pobudce zawsze czyta status urządzenia, jak każdy sterownik.
- INTx (przerwania liniowe) – nie: na prawdziwym sprzęcie wymagają ACPI AML.
- Kod (19.d): `device.rs` – statyczne sloty wektor ↔ licznik + `Observers` (handler nie dotyka pamięci, którą
  ktoś mógłby zwolnić), `IrqObj` (trzyma przejęcie; Drop: MSI off → odczyt rejestru → `msi::free`). `irq_bind`
  włącza urządzeniu bus mastering (MSI to zapis do pamięci); Drop przejęcia wyłącza MSI i bus mastering, zanim
  urządzenie wróci. Uchwyt IRQ: rodzaj 8, prawo `RECV`; `irq_bind` wymaga `MAP_WRITE` na urządzeniu.

### DMA (19.e)

- **`dma_alloc(dev, rozmiar, bity_adresu)`** → uchwyt pamięci współdzielonej (mapowany przez `shm_map`) +
  adres fizyczny (`dma_phys`). Ramki **ciągłe**, wyzerowane, poniżej `2^bity_adresu` (urządzenia 32-bitowe;
  `edu` domyślnie 28 bitów) – alokator ramek dostaje szukanie poniżej limitu. Do 2 MiB na bufor, 16 MiB na
  urządzenie. Pierwszy `dma_alloc` włącza urządzeniu bus mastering.
- **Bufor DMA żyje tak długo jak przejęcie urządzenia** – zamknięcie uchwytu bufora go nie zwalnia. Inaczej
  usługa mogłaby zwolnić bufor, do którego urządzenie wciąż pisze, a ramka trafiłaby do jądra albo innego
  procesu.
- **Bez IOMMU** urządzenie z bus masteringiem może pisać w całą pamięć – sterownik w user space jest więc
  izolowany przed błędami w kodzie (wskaźniki, panika), nie przed złośliwym zaprogramowaniem urządzenia.
  Dlatego `HW_ROOT` ma tylko init, a dyski są wyłączone z `dev_claim`. IOMMU (Intel VT-d / AMD-Vi) – później.
- Kod (19.e): `DevClaim::dma_alloc` (lista buforów w przejęciu, limit 16 MiB), `ShmObj::new_dma` (ciągłe ramki,
  `dma_phys`), `frame::alloc_frames_below`. Bufory zwalnia Drop przejęcia – po wyłączeniu MSI i bus masteringu
  (pole `dma` zwalnia się po treści `Drop`).

### Sprzątanie po usłudze (kill w dowolnym momencie)

Ostatni uchwyt `DEVICE` znika (koniec procesu, zamknięcie) → jądro w tej kolejności:

1. wyłącza bus mastering i MSI w urządzeniu, odczytuje rejestr z powrotem (zapisy PCI są buforowane – odczyt
   gwarantuje, że dotarły),
2. odmapowuje BAR-y z procesu (już zrobione przez koniec procesu albo `munmap`),
3. zwalnia wektor MSI i obiekt IRQ (budzi obserwatorów – `wait_many` zwraca błąd),
4. dopiero teraz zwalnia ramki DMA,
5. zwalnia przejęcie – urządzenie może wziąć nowa instancja usługi.

### Menedżer usług w init (19.g)

- Init ma tabelę usług (w kodzie init, `SERVICES`): `edu` → `/bin/edud` z urządzeniem 00:06.0, `echo` →
  `/bin/echod` bez urządzenia. Dla każdej: `dev_claim` z `HW_ROOT` → `spawn_ex` (slot 1 konsola, 3 urządzenie,
  4 kanał połączeń). Brak urządzenia (`ENODEV`, np. Legion) → stan „no device”, bez prób.
- **Restart:** po końcu procesu odstęp 100 ms, podwajany do 5 s (po 10 s stabilnej pracy znowu 100 ms);
  5 awarii w 30 s → „broken”, bez restartów. `EBUSY` przy starcie (stara instancja jeszcze sprzątana) →
  ponowna próba za 100 ms.
- **Łączenie po nazwie:** shell i jego programy mają w slocie 3 (`SVC`) koniec kanału do init z prawami tylko
  `SEND | DUP` (odbierać może tylko init). Klient tworzy własny kanał i wysyła `"connect edu"` + jeden koniec;
  init przekazuje ten koniec do kanału połączeń usługi (bez czekania); dalej klient i usługa rozmawiają
  bezpośrednio. Usługa nieznana / niedziałająca → init zamyka koniec, klient dostaje `EPIPE`.
  `"list"` + koniec → init odsyła wiersze „nazwa stan pid N restarts N (program)” i zamyka.
  Biblioteka: `svc_connect("edu")`, `svc_list(buf)`; komenda `services`.
- Usługa padła → klienci dostają `EPIPE` i łączą się ponownie (po restarcie).
- Shell sprawdza na starcie, czy slot 3 to kanał, i wtedy uruchamia programy przez `spawn_ex` z
  `[(we,0), (wy,1), (2,2), (3,3)]`; bez kanału – jak dotąd `spawn`.
- Pętla init: restarty, których czas minął → `wait_many` na kanale svc (najwyżej 100 ms) → zbieranie dzieci
  (`wait` z `WNOHANG`): shell, usługi, sieroty.
- `init test <program>` – tryb samotestu: zamiast shella `<program>`, po jego końcu init zamyka kanały
  połączeń, zabija usługi, czeka na nie i kończy się kodem programu (SVC TEST 6/6 z `/bin/svctest`).
- **Wariant B (na później, decyzja 2026-10-11):** menedżer usług jako osobny program `/bin/svcmgr`, a init
  zostaje minimalny (shell, `svcmgr`, sieroty). Zaleta: błąd w menedżerze nie restartuje init i shella. Koszt:
  po awarii menedżera usługi działają bez nadzoru, a nowy menedżer musi je odnaleźć (ich urządzenia są wciąż
  przejęte – `EBUSY`). Teraz wariant A (wszystko w init), bo prościej; przejście na B to przeniesienie kodu w
  user space, bez zmian w jądrze – gdy menedżer urośnie albo jego awarie zaczną przeszkadzać.

### Pierwsza usługa – `edu` (19.f)

`edu` (PCI 1234:11e8) to urządzenie QEMU zrobione do nauki sterowników: rejestr identyfikacji, liczenie silni
w rejestrze, przerwanie na żądanie i po silni, DMA do bufora. Testy (`test.sh`, `stress-qemu.sh`,
`run-qemu.sh`) mają `-device edu,addr=06`. Na prawdziwym sprzęcie `edu` nie ma – tam działa `/bin/echod`
(usługa bez sprzętu) do testu menedżera, restartu i `wait_many`.

**`/bin/edud` (19.f)** – sterownik edu jako zwykły proces:

- uchwyty na starcie: 1 konsola, 3 urządzenie, 4 kanał połączeń (daje je ten, kto uruchamia usługę – menedżer
  w init od 19.g); rejestry `dev_map`, przerwanie `irq_bind`, bufor `dma_alloc`,
- jedna pętla `wait_many`: kanał połączeń + przerwanie + do 14 klientów; prośby po kolei (urządzenie jest
  jedno), odpowiedź bez czekania (klient, który nie odbiera, nie zatrzyma usługi); o końcu operacji decyduje
  status urządzenia, przerwanie tylko budzi,
- protokół `user/lib/edu_proto.rs`: nagłówek 16 B (`op`, `arg` / `status`, `wartość`) + dane; `PING`, `FACT`,
  `COPY` (DMA, do 4000 B), `STATS`; zła prośba – EINVAL, usługa działa dalej,
- połączenie: klient tworzy kanał i wysyła jeden koniec przez kanał połączeń; usługa zabita → klienci dostają
  `EPIPE`, urządzenie wraca od razu, nowa instancja może je przejąć,
- koniec: kanał połączeń zamknięty i żadnego klienta – kod 0.

### Koniec `kcmd` (19.i)

Most `kcmd` (syscall 21: dowolna komenda shella jądra z user space) zniknął. Zamiast niego:

- **`sysinfo(temat, bufor)`** (46) – tylko odczyt, tekst: `ver`, `uptime`, `date`, `mem`, `irq`, `cpus`,
  `lspci` (`-v`), `acpi`, `disk` (sama lista), `mount`, `df`. Każdy program może pytać. Shell uruchamia to po
  nazwie (`mem`, `lspci -v > plik`).
- **`sysctl(uchwyt, akcja, arg, fd)`** (47) – `reboot`, `halt`, `sync`, `stress [s]`; działa tylko z
  uchwytem `SYSCTL` (rodzaj 9, prawo tylko `DUP`: można dać dziecku przez `spawn_ex`, nie można wysłać w
  komunikacie). Jądro tworzy go tylko dla init (slot 4, obok `HW_ROOT` w slocie 3); init daje kopię shellowi
  (slot 4), shell **nie** przekazuje go programom – program z shella nie zrestartuje komputera. Decyzja Dawida
  (2026-10-11): akcje za uchwytem, zgodnie z modelem uprawnień.
- **Zmiany na dyskach** (`mkfs`, `disk read/write`) i programy testowe w asm (`run`) – tylko w awaryjnym
  shellu jądra; `/bin/sh` odpowiada „only in the kernel emergency shell”. Później: usługa z uchwytem do dysku.

### Numery syscalli (robocze)

38 `wait_many`, 39 `dev_claim`, 40 `dev_info`, 41 `dev_map`, 42 `irq_bind`, 43 `irq_read`, 44 `dma_alloc`,
45 `dma_phys`, 46 `sysinfo`, 47 `sysctl`; 21 wolny. Nowe błędy: `EBUSY` (-16), `ENODEV` (-19). Profil
(`prof.rs`) – 48 numerów. Rodzaje uchwytów: 6 `HW_ROOT`, 7 `DEVICE`, 8 `IRQ`, 9 `SYSCTL`; bufor DMA to `SHM` (5).

### Pomiar (19.h)

Ta sama praca na `edu` w jądrze i w user space (SVC TEST 7/7, linia `[RESULT-SVC]`, którą pokazuje `test.sh`):

- **przerwanie → obudzony sterownik:** zapis rejestru „raise”, sterownik śpi (jądro: `WaitQueue`, usługa:
  `wait_many` z `W_IRQ`), budzi go handler MSI, sprawdza status, potwierdza,
- **silnia zakończona przerwaniem:** w jądrze, w procesie ze sterownikiem, oraz przez usługę (klient → `edud`
  → urządzenie → odpowiedź) i sam `PING` przez usługę (koszt IPC bez czekania na urządzenie),
- **restart usługi:** kill → urządzenie wraca → nowa instancja → pierwsza odpowiedź (bez odstępu 100 ms
  menedżera).

Każdy pomiar trwa ≥ 200 ms (zegar ms, średnia z wielu rund).

Wynik u Dawida (v0.19.6, QEMU KVM, 4 CPU): przerwanie → sterownik **32,6 µs jądro / 31,9 µs usługa**; silnia
53,1 / 55,5 µs (w procesie), 84,4 µs klient przez `edud`; PING przez usługę 22,6 µs; restart 1,2 ms. Wniosek:
sterownik w user space nie dokłada mierzalnie nic do obsługi przerwania – w KVM czas dominuje budzenie
uśpionego (`hlt`) wirtualnego CPU przez hosta (w TCG, gdzie CPU nie śpi, ~3 µs). Pośrednik (klient → usługa)
kosztuje ~2 przełączenia procesów (+29 µs w KVM). Na prawdziwym sprzęcie pomiaru brak (Legion nie ma `edu`). Jądro: `kernel_edu_bench` w `test_svc.rs`
(przejęcie edu na czas pomiaru); user space: `/bin/svcbench` (z HW_ROOT – wszystko; z shella – tylko przez
usługę `edu` z init). Pomiaru nie ma w autostressie: tam `edu` trzyma `edud` uruchomiony przez init, a na
Legionie edu nie ma.

## Pomiar i testy

- `./test.sh` – 27 zestawów samotestów w QEMU (TCG albo `ACCEL=kvm`, 1–4 CPU): wyjątki, pamięć, scheduler,
  ring 3, FPU, urządzenia, FS, syscalle, ELF, procesy, SMP, blokady, TLB, alokatory, pliki, IPC, stress.
  Każda poprawka bezpieczeństwa ma test, który bez niej się wywraca.
- **Autostress** (`DESOOS_AUTOSTRESS=60`) – skrypty shella, liczenie liczb pierwszych, zadania IPC (para
  procesów: wspólna pamięć + kanał, dziecko zabijane w trakcie czekania), na wszystkich CPU. Tryb porównawczy
  (domyślny) i pełnego obciążenia (`DESOOS_STRESS_POOL=P`). Raport: blokady per miejsce, profil czasu CPU
  wejść do jądra (`prof.rs`), kręcenie na spinlockach, wycieki.
- Ostatnia linia – **`[RESULT]`** do automatycznego porównywania wersji (ludzie – zdjęcie, program – ta linia):
  `ver mode cpus ms scripts primes ipc idle pingpong_ns chan_msgs chan_mbs chan16_ms shm16_ms pass`.
- Legion v0.18.4 (60 s, 16 CPU): 392 943 skryptów (porównawczy), 448 079 (pełne obciążenie).

## Kierunek: agent DeSo AI

Długoterminowa wizja: system, w którym agent pomaga utrzymywać i rozwijać oprogramowanie, a komputery
wymieniają się poprawkami. Trzy warstwy:

```
DeSoOS Core   jądro + sterowniki         zmienia tylko człowiek (po przejrzeniu diffu)
DeSoOS Apps   aplikacje .eso             instalowane z manifestem, w sandboxie z uchwytów
Sieć agentów  agent DeSo AI na każdym    wymiana poprawek i aplikacji między komputerami
              komputerze
```

**Zasady (ustalone):**

- **W jądrze nic AI-specyficznego.** Jądro daje ogólne mechanizmy – uchwyty z prawami, kanały, pamięć
  współdzieloną, `spawn_ex` – z których korzysta każdy program, agent też.
- **Agent to zwykły program w user space**, który ma tylko uchwyty, jakie dostał (od init / użytkownika).
  Nie ma „trybu administratora” w jądrze; czego nie dostał, tego nie dotknie.
- **Aplikacja `.eso` = ELF + manifest**: wersja, wymagane uchwyty (np. „kanał do usługi sieci”, „katalog
  /home/x tylko do odczytu”), skrót źródeł. Instalator pokazuje uprawnienia, `spawn_ex` daje dokładnie te.
- **Powtarzalne budowanie** – te same źródła dają ten sam plik binarny, więc poprawkę z innego komputera
  można sprawdzić (zbudować samemu i porównać skrót), zamiast ufać binarce.
- **Zmiany jądra zatwierdza człowiek** po przejrzeniu diffu; agent może proponować i testować (QEMU,
  `[RESULT]`), nie wdrażać sam.

**Co już jest (M18):** uchwyty z prawami tylko do zmniejszania, przekazywanie uchwytów w komunikatach,
nadawca wpisywany przez jądro, dziecko z wybranymi uchwytami, wynik testów jako linia maszynowa.
**Czego brakuje:** usług w user space (M19), sieci, izolacji VFS (dziś proces widzi całe drzewo plików przez
ścieżki – sandbox wymaga katalogów jako uchwytów), podpisów i formatu `.eso`.

## Grafika

Framebuffer z UEFI → virtio-gpu w QEMU → ewentualnie Intel (otwarta dokumentacja); NVIDIA odpada.
GUI jako usługa: okna rysują do wspólnej pamięci, przez kanał idą tylko powiadomienia.
