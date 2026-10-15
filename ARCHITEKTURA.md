# Architektura DeSoOS

Opis tego, jak system jest zbudowany i jak działa (stan: v0.26.0 – M20 USB w toku: klawiatura i pendrive tylko do odczytu działają). Historia zmian: `CHANGELOG.md`,
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
| USB + HID | user space (`/bin/usbd`, M20) | zdarzenia klawiatury do jądra syscallem `input_inject`; padnięty usbd = restart przez init |
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
  USB w user space (M20, `/bin/usbd`) – klawiatura Legiona działa od v0.25.1.

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

## USB (M20 – projekt 20.a, zaakceptowany 2026-10-12)

Cel: wbudowana klawiatura Legiona (USB HID, ITE 8910), mysz USB i odczyt pendrive'a – przez **usługę w user
space** `/bin/usbd`, na mechanizmach z M19. Jądro dostaje od USB tylko dwie rzeczy: **zdarzenia wejścia** i
**sektory dysku**. Nic z protokołu USB nie trafia do jądra.

```
 jądro                                    init (HW_ROOT, INPUT, BLK)          usbd (jeden na kontroler)
 ──────                                   ──────────────────────────          ─────────────────────────
 dev_find(klasa 0C03/30) ───────────────► BDF kontrolerów ─ spawn_ex ──────► slot 3 DEVICE, 4 INPUT, 5 BLK
 tablica PCI, MSI-X, ramki DMA  ◄──────── dev_claim / irq_bind / dma_alloc ─── pierścienie xHCI, TRB, konteksty
 kernel/input.rs ◄── input_inject(INPUT, zdarzenia) ─────────────────────────── raporty HID → zdarzenia
 ublk (BlockDevice) ◄─ kanał: żądanie / odpowiedź, dane w buforze DMA ────────── BOT + SCSI READ(10)
 FAT32 /usbN (tylko odczyt)                                    klient ── "usb0" ──► init ──► lsusb, stan
```

### Granica bezpieczeństwa – DMA bez IOMMU (zapisane wprost)

usbd sam wpisuje adresy fizyczne do struktur xHCI (DCBAA, pierścienie, TRB, konteksty). **Jądro nie ma jak
tych adresów sprawdzić** – kontroler czyta je bezpośrednio z pamięci. Bez IOMMU błędny albo złośliwy usbd może
zlecić kontrolerowi zapis w dowolne miejsce RAM, także w jądro.

- Izolacja procesu usbd chroni przed: paniką, błędnym wskaźnikiem, zawieszeniem, wyciekiem, złym stanem
  po awarii – to jądro sprząta i restartuje (M19).
- **Nie chroni przed dzikim DMA.** usbd jest więc zaufanym kodem systemu (jak sterownik w jądrze), tylko
  uruchomionym w procesie. Dlatego: `HW_ROOT` ma tylko init, usbd dostaje jedno urządzenie, a binarka usbd
  jest wbudowana w obraz (initrd), nie ładowana z dysku.
- Ograniczenia, które zostają: bufory tylko z `dma_alloc` (ciągłe, limit 16 MiB na urządzenie), żyją co
  najmniej tak długo jak przejęcie; po śmierci usbd bus mastering wyłączany przed zwolnieniem ramek (M19.e).
- Pełna izolacja DMA: **IOMMU (AMD-Vi na Legionie)** – osobny etap po M20 („Dalej”).

### Nowe syscalle i uchwyty

| Nr | Wywołanie | Uchwyt / prawa | Wynik, błędy |
|---|---|---|---|
| 48 | `dev_find(root, klasa, nr)` | `HW_ROOT` | BDF `nr`-tego urządzenia o klasie (24 bity: klasa, podklasa, prog-if); `ENOENT` – brak dalszych, `EBADF` |
| 49 | `input_inject(h, zdarzenia, n)` | `INPUT`, `WRITE` | stan diod (Caps/Num/Scroll) – usbd ustawia je w klawiaturze; `EINVAL` (n > 64, zły rodzaj), `EFAULT`, `EBADF` |
| 50 | `blk_attach(h, kanał, bufor, info)` | `BLK`, `WRITE`; kanał `SEND`+`RECV`+`TRANSFER`; bufor `MAP_READ` | numer dysku USB (0 = sda); `EINVAL` (blok ≠ 512/4096, 0 bloków, sloty spoza 1..8, bufor < sloty × 64 KiB), `ENOSPC` (8 dysków USB), `EACCES`, `EBADF`, `EFAULT` |

Rodzaje uchwytów: **10 `INPUT`**, **11 `BLK`**. Jądro daje je init przy starcie (slot 5 i 6, jak `SYSCTL`
w slocie 4), init przekazuje każdemu usbd kopię **bez `DUP`** (usbd nie puści ich dalej), shell ich nie dostaje.
`INPUT` to w praktyce klawiatura systemu (może pisać do shella) – stąd tak wąsko. Profil (`prof.rs`) – 51 numerów.

### Wejście – `input_inject` (49)

Zdarzenie 8 B: `rodzaj u8`, `wciśnięty u8`, `kod u16` (HID usage, strona 7 – klawiatura), `dx i16`, `dy i16`
(mysz: rodzaj 2, `kod` = przyciski, `wciśnięty` = kółko jako i8). Najwyżej 64 zdarzenia w wywołaniu.

- Jądro tłumaczy HID usage → `KeyCode` (tablica w `kernel/input.rs`, obok tłumaczenia z PS/2), dalej jak dziś:
  modyfikatory, Caps/Num, układ pl, konsola, `readkey`, `keys`.
- **Autorepeat w jądrze** dla źródła USB (klawiatura USB, w przeciwieństwie do PS/2, nie powtarza sama):
  500 ms, potem 30/s, z ticku zegara; kończy go puszczenie klawisza albo zniknięcie źródła.
- Każdy uchwyt `INPUT` to osobne **źródło**: jądro pamięta, co z niego jest wciśnięte. Zamknięcie ostatniej kopii
  (koniec usbd) = **puszczenie wszystkich klawiszy źródła** – po awarii nie zostaje wciśnięty Shift ani Ctrl.
- Mysz: przewijanie konsoli (jak PS/2 dziś); kursor – razem z GUI.

### Dysk – ublk (50) i protokół żądań

usbd tworzy kanał i bufor (`dma_alloc` – ten sam, do którego pendrive pisze przez DMA, bez kopii w usbd) i woła
`blk_attach(BLK, koniec_kanału, bufor, info)`; `info` = liczba sektorów, rozmiar sektora, nazwa (`usb0d1`).
Jądro bierze **własne referencje** do kanału i bufora i rejestruje dysk `ublk` (zawsze `read_only`), potem
skanuje partycje GPT / MBR jak przy NVMe.

Komunikaty (32 B, kanał – sterowanie; dane – bufor, zasada z M18):

| Kierunek | Pola |
|---|---|
| jądro → usbd | `id u32`, `op u32` (1 = READ; innych brak), `lba u64`, `sektory u32`, `slot u32` |
| usbd → jądro | `id u32`, `status i32` (0, `EIO`, `ENODEV` – nośnik wyjęty), `sektory u32` |

- **Sloty:** bufor dzielony na sloty po 64 KiB (domyślnie 4 = 256 KiB), jeden slot na żądanie; `id` rośnie
  monotonicznie (64-bitowy licznik w jądrze, w komunikacie 32 bity – nie zawinie się w czasie życia dysku).
- **Właściciel slotu w każdej chwili:** `wolny` (jądro) → `u usbd` (od wysłania żądania) → `wolny` po odpowiedzi
  z tym samym `id`, `sektory` = żądane i `status` = 0 (dopiero wtedy jądro kopiuje dane). Każda inna odpowiedź
  (nieznane `id`, zła liczba sektorów, za duży komunikat) = **odrzucona** + licznik błędów protokołu.
- **Timeout:** 5 s na żądanie (pendrive potrafi się budzić sekundami). Po timeoucie: `EIO` dla wywołującego,
  slot przechodzi w stan **kwarantanny** – nie wraca do puli, bo urządzenie może jeszcze do niego pisać. Wraca
  dopiero po spóźnionej odpowiedzi z tym `id` (którą jądro wyrzuca) albo po śmierci usbd.
- **3 timeouty pod rząd albo zamknięty kanał** (śmierć usbd) = dysk **znika**: kolejne operacje `ENODEV`/`EIO`,
  FS zamontowany na nim zwraca `EIO`; zadanie `usb-disks` odmontowuje go i usuwa dysk z partycjami (v0.26.0: numer
  w warstwie block wraca do puli dopiero po odmontowaniu – inaczej każdy restart usbd zostawiałby wpis na zawsze;
  nazwy `sdX` rosną i się nie powtarzają).
- **Śmierć usbd:** jądro najpierw wyłącza bus mastering (sprzątanie M19), ramki bufora żyją, dopóki ublk
  trzyma referencję – zwalniane dopiero przy usunięciu dysku. Nic nie pisze do zwolnionej ramki.
- **Dane z pendrive'a to dane z obcego źródła** – FAT32 i GPT już muszą być odporne na zepsute dyski (tak jak
  dziś dla NVMe); nowe: test FAT32 na celowo zepsutym obrazie w QEMU.

**Zmiany w jądrze, których to wymaga** (krok f):
- **blokada per dysk** w warstwie block – dziś jedna globalna (`block layer`); czekanie do 5 s na USB
  zatrzymałoby NVMe i virtio. Lista dysków: krótka blokada na wyszukanie, operacja pod blokadą dysku.
- usuwanie dysku (wpis „zniknął”), dziś jest tylko `register`,
- `ChanEnd::recv` z terminem (jądro czeka na odpowiedź z timeoutem).
- (v0.28.0, M20.g: już nie – FAT32 na dysku USB ma własną blokadę `fs::Locked` i działa pod FS_LOCK do odczytu;
  czekanie na pendrive zatrzymuje tylko ten system plików.) Pierwotnie: FAT32 zostaje pod `FS_LOCK` do zapisu: odczyt z `/usbN` blokuje na ten czas inne operacje na FAT32 (nie ramfs
  w trybie odczytu współdzielonego). Dlatego **usbd po starcie nie używa VFS** (dostaje tylko uchwyty z init) –
  inaczej czekałby na blokadę trzymaną w jego imieniu (zakleszczenie do timeoutu).

**Tylko odczyt – trzy niezależne zamki (v0.26.0: cztery – FAT32 na dysku read-only odrzuca zmiany od razu, `open` do
zapisu → EROFS):** usbd nie zawiera żadnej komendy zapisu SCSI (WRITE(6/10/12/16), FORMAT,
MODE SELECT, SYNCHRONIZE CACHE – test: brak tych kodów w binarce), protokół ublk nie ma operacji zapisu, dysk
`ublk` zgłasza `read_only`, warstwa block odrzuca zapis (EROFS).

### Enumeracja – maszyna stanów portu

```
 Wolny ─podłączenie─► Debounce(100 ms) ─► Reset(500 ms) ─► Adres(Enable Slot + Address Device, 1 s/komendę)
   ▲                                                                   │
   │                       Deskryptory(GET_DESCRIPTOR: 8 B, całe urządzenie, 9 B konfiguracji, całość)
   │                                                                   │
   └── Wyłączony ◄── Błąd(≤ 3 próby, potem do odłączenia) ◄── Konfiguracja(Set Configuration, Configure Endpoint)
                                                                       │
                                                         Działa (klasa: hub / HID / pamięć masowa / nieznana)
```

- **Każdy stan ma timeout**; po błędzie: Disable Slot, port wyłączony, powrót do `Wolny` (3 próby, potem port
  ignorowany do odłączenia). Odłączenie w dowolnym stanie → sprzątanie slotu i powrót do `Wolny`.
- **Limity:** 32 urządzenia na kontroler (i nie więcej niż MaxSlots), deskryptor konfiguracji ≤ 4 KiB,
  ≤ 8 zapamiętanych interfejsów (ustawienie alternatywne 0; ponad – pomijane, nie błąd), ≤ 64 deskryptory interfejsu
  razem z ustawieniami alternatywnymi (kamery mają ich dziesiątki), ≤ 16 endpointów na urządzenie, głębokość hubów ≤ 5, MaxPacketSize zgodny z prędkością.
- Komendy xHCI i transfery z timeoutem; STALL → Clear Halt raz, potem błąd urządzenia (nie całego usbd).
- Nieznana klasa: urządzenie widoczne w `lsusb`, bez sterownika.

### Parser deskryptorów i testy bez sprzętu

`user/lib/usb_desc.rs` – czysty parser (bez MMIO, bez alokacji powyżej limitów), zwraca błąd zamiast paniki.
`/bin/usbparse` (test w `test.sh`): tabela złośliwych przypadków – `bLength` 0, `bLength` większy niż reszta,
`wTotalLength` większy niż bufor, `bNumEndpoints` niezgodny z treścią, MaxPacketSize 0, pętla deskryptorów,
deskryptor HID z dziwnym raportem – plus 10 000 losowych mutacji z ustalonym ziarnem. Wymaganie: zero paniki,
każdy przypadek kończy się błędem albo poprawnym wynikiem w limitach.

### Restart usbd – co widzi użytkownik

- Init przy restarcie wypisuje na ekran i COM1: `init: service usb0 restarted (n) – USB input back shortly`;
  usbd po starcie: `usb0: xHCI <vendor:device>, N ports` i każde podłączone urządzenie.
- Klawisze źródła puszczone od razu (patrz wyżej); klawiatura wraca po ponownej enumeracji (~0,1–1 s + odstęp
  restartu 100 ms → 5 s).
- 5 awarii w 30 s → `broken`: komunikat `USB disabled after 5 failures – keyboard unavailable (PS/2 still works)`;
  potrzebny restart systemu (na Legionie przyciskiem zasilania); ręczne `services restart` – później.

### Kontroler – start i koniec

usbd: `dev_claim`, `dev_map` BAR0, **przejęcie od BIOS-u** (USB Legacy Support w rozszerzonych możliwościach xHCI:
bit OS Owned, czekanie ≤ 1 s na zwolnienie przez BIOS, wyłączenie SMI), reset (HCRST, ≤ 1 s), DCBAA, bufory
scratchpad, pierścień komend, jeden interrupter z pierścieniem zdarzeń, MSI-X (`irq_bind`), Run. 64-bitowe
adresy DMA, jeśli kontroler ma AC64, inaczej `dma_alloc` z limitem 32 bitów. usbd przydziela kilka większych
buforów DMA i dzieli je sam (limit 16 MiB na urządzenie, 2 MiB na bufor). Koniec: kill w dowolnym momencie →
sprzątanie M19 (bus mastering off → wektor → ramki → przejęcie); nowa instancja robi pełny reset kontrolera.

### Stan (v0.23.0, krok b)

`dev_find` w jądrze; init dodaje `usbN` dla każdego kontrolera (klasa 0C0330, najwyżej 4); `/bin/usbd`: przejęcie
od BIOS-u, reset, DCBAA (+ tablica segmentów zdarzeń w tej samej stronie, offset 0x400), scratchpad, pierścień
komend i zdarzeń, MSI, No-Op z czekaniem na przerwanie (co 10 ms także sprawdzenie pierścienia – licznik `polled`),
zdarzenia zmian portów, zasilanie portów. Klienci: `status`, `noop N`. Test: USB TEST 1/2, 2/2.

### Stan (v0.24.0, krok c)

usbd: maszyna stanów portu (`Free` → `Debounce` 100 ms → enumeracja → `Working`; błąd → `Failed` z ponowieniem za
500 ms, po 3 próbach `Ignored` do odłączenia; odłączenie albo CSC przy `Working` → Disable Slot). Enumeracja: reset portu
(USB 2; port USB 3 z PED pomijamy – łącze wytrenowane), Enable Slot, kontekst wejściowy (slot + EP0; 32/64 B wg CSZ),
Address Device, GET_DESCRIPTOR urządzenia 8 B → Evaluate Context, gdy rozmiar pakietu EP0 inny, 18 B, konfiguracja 9 B →
wTotalLength → całość, napisy (język z napisu 0, producent, produkt). Transfer sterujący: Setup (IDT) + Data (ISP) +
Status (IOC), zdarzenia transferu w kolejce 16; krótki pakiet → reszta z TRB danych. STALL / błąd → Reset Endpoint + Set
TR Dequeue. Strony urządzenia (kontekst wejściowy, wyjściowy, pierścień EP0) wracają do puli po odłączeniu; dane
deskryptorów w jednej stronie DMA kontrolera. **Do urządzeń idą tylko prośby o odczyt deskryptorów** – bez Set
Configuration (krok e/f, razem z Configure Endpoint). Klienci: `list` (lsusb). Parser: `user/lib/usb_desc.rs`.

### Stan (v0.25.0, krok e – przed d)

- Jądro: `Fd::Input` (rodzaj 10, prawa WRITE + DUP, bez TRANSFER), tworzony tylko w `exec` z `SpawnOptions.input`
  (init: slot 5). **Kopia uchwytu = nowe źródło** (`impl Clone` w `inputsrc.rs`) z własną mapą wciśniętych klawiszy;
  Drop (koniec usbd) przekazuje ją do `input::usb_release_all` – tylko atomiki, puszczenie robi zadanie jądra
  `input-repeat` pod BKL (v0.25.1; w v0.25.0 tick zegara). Puszczenie klawisza niewciśniętego przez źródło – pomijane.
- `input_inject` (pod BKL): najpierw walidacja wszystkich zdarzeń (zły rodzaj → EINVAL, nic nie przechodzi), potem
  `usb_key` (HID usage → KeyCode → `handle_key`, budzenie konsoli) albo `usb_mouse` (kółko → `mouse::add_wheel`).
  Wynik: diody (bit 0 Num, 1 Caps, 2 Scroll). Autorepeat: jeden klawisz naraz (ostatnio wciśnięty), modyfikatory i
  blokady się nie powtarzają; koniec źródła zatrzymuje jego powtarzanie.
- usbd: interfejs 03/01/01 albo 03/01/02 z endpointem przerwań IN → Configure Endpoint (DCI = numer·2+1, interwał:
  HS/SS bInterval−1, FS/LS log2(ms·8) w 3..10), Set Configuration, Set Protocol(boot) i Set Idle(0) (błąd = ignorowany),
  8 TRB Normal (bufor = indeks TRB % 16 w stronie danych). Zdarzenia transferu endpointów ≠ EP0 obsługiwane od razu w
  `poll_events` (także w trakcie transferu sterującego); błąd endpointu → Reset Endpoint + Set TR Dequeue + nowe TRB w
  pętli głównej (bez rekurencji komend). Raport klawiatury: ErrorRollOver pomijany, kolejność: modyfikatory, puszczenia,
  wciśnięcia. Diody: Set Report (OUT, 1 B) z pętli głównej. Odłączenie klawiatury → puszczenie jej klawiszy.
  `idle MS` – test potoku przerwań w QEMU. Pamięć masowa nadal bez konfiguracji.
- **Legion (v0.25.1): wbudowana klawiatura ITE działa w shellu**, stress compare 431 023 (bez spadku).

**Lockdep w przerwaniu (v0.25.1):** blokady wzięte w handlerze przerwania są oznaczone w tablicy trzymanych; w przerwaniu
kolejność poziomów sprawdzana tylko względem nich (blokada przerwanego kodu nie jest złamaniem – przerwany kod nie czeka
na handler), rekurencja zawsze. Wcześniej MSI usbd w trakcie stressu dawało fałszywy PANIC (`waiters` 45 przy
`stress-counter` 210).

### Stan (v0.26.0, krok f – przed d)

- `info` dla `blk_attach` (64 B): bloki u64, rozmiar bloku u32, sloty u32, timeout_ms u32 (0 = 5 s; test podaje
  krótszy, 100..30 000), 4 B zera, opis 40 B ASCII (producent + produkt z INQUIRY).
- Protokół jak wyżej, „sektory” = **bloki urządzenia** (512 albo 4096 B; jądro przelicza z sektorów 512 B, czyta
  pełne bloki i kopiuje fragment). Odczyt większy niż slot = kilka żądań po kolei (jedno w locie na dysk – i tak
  pod blokadą dysku). Odpowiedź ≥ 12 B: id, status (0 / EIO / ENODEV), bloki.
- Jądro: `ublk::Shared` (stan bez blokady dysku: zniknął, liczniki, punkty montowania) w rejestrze; `Ublk` w
  warstwie block. Zadanie `usb-disks` (od startu jądra): nowy dysk → `scan_partitions` → FAT32 na partycjach (albo
  na całym dysku / pierwszej partycji MBR) → `/usbN`; zamknięty kanał (sprawdzane co 200 ms przy obecnych dyskach)
  albo `gone` → odmontowanie bez zapisu (`unmount_lost`), usunięcie partycji i dysku → bufor i kanał zwolnione.
- Warstwa block: `Vec<Option<Arc<Disk>>>` pod SpinLockiem „block list” (poziom BLOCK), każdy `Disk` z własnym
  `KMutex`; partycja → dysk-rodzic zawsze w tej kolejności; `partitions_of` bez blokad dysków.
- usbd: `Storage` (bulk IN/OUT, pierścienie, strona komend: CBW 0, CSW 512, dane 1024), bufory DMA w puli
  (`stor_bufs`, wracają po odłączeniu – limit 16 MiB DMA na urządzenie). Rejestracja w jądrze dopiero z pętli
  głównej (`attach_pending`), bo jądro od razu czyta partycje, a usbd musi już odbierać żądania. Kanały dysków są
  w `wait_many` obok przerwania i klientów. Zdarzenia transferu: HID od razu, reszta (EP0, bulk) do kolejki.
- Granice: LUN 0, bez READ CAPACITY(16) (> 2 TiB – odmowa), bez UAS, MaxBurst 0 (SuperSpeed działa, bez serii).

### Stan (v0.27.0, krok d)

- `Dev.loc` (route string, głębokość, porty po drodze, TT) i `Dev.hub` (porty huba z tą samą maszyną stanów co porty
  kontrolera, mapa zmian `pending`, endpoint przerwań IN). Kontekst slotu zawsze z `slot_ctx` (route string, port
  kontrolera najwyższego huba, TT; dla huba bit Hub, liczba portów, TT think time) – Address Device i każdy
  Configure Endpoint.
- Konfiguracja huba: Configure Endpoint (endpoint mapy zmian, kontekst slotu jeszcze bez pól huba) + Set
  Configuration → Set Hub Depth (USB 3, głębokość = liczba hubów nad nim) → deskryptor huba (0x29 / 0x2A) → drugi
  Configure Endpoint tylko z kontekstem slotu (jak Linux `xhci_update_hub_device`) → SET_FEATURE(PORT_POWER) na
  każdym porcie, czekanie bPwrOn2PwrGood × 2 ms → 2 TRB na mapę zmian, wszystkie porty do sprawdzenia.
- Zdarzenie mapy zmian (z `poll_events`, także w trakcie innego transferu) tylko zaznacza porty; transfery do huba
  (GET_STATUS, CLEAR_FEATURE C_PORT_*, reset portu) robi `service_hubs` z pętli głównej. Bit 0 (zmiana samego huba:
  zasilanie / przeciążenie) – kasowany. Błąd endpointu → Reset Endpoint + Set TR Dequeue + wszystkie porty od nowa.
- Prędkość urządzenia za hubem: hub USB 3 → SuperSpeed; USB 2 → bit 9 (low), 10 (high), inaczej full. TT: low / full
  speed za hubem high speed → (slot huba, port); głębiej – TT dziedziczony po rodzicu.
- Odłączenie: `detach` huba najpierw (rekurencyjnie) odłącza urządzenia z jego portów – dyski znikają w jądrze jak
  przy wyjęciu pendrive'a. Hub na 5. poziomie – bez portów (route string ma 5 poziomów).
- Test w locie: `test.sh` uruchamia QEMU z monitorem na gnieździe unix i `qemu-hotplug.py`, który wysyła do monitora
  linie „[HOTPLUG] …” wypisane przez samotest jądra (`device_del` / `device_add`; dysk jako `-blockdev`, żeby
  przetrwał `device_del`).

### Stan (v0.28.0, krok g)

- `fs::Locked<F>` – opakowanie systemu plików bez własnych blokad w jeden `Mutex` (usypiający); implementuje
  `ConcurrentFs`, więc VFS woła go pod FS_LOCK do odczytu. `kind` / `source` / `read_only` kopiowane przy
  montowaniu (`mount`, `open` nie czekają na dysk), `df` (`mount_stats`) przez ścieżkę współbieżną. Montowanie i
  odmontowanie (FS_LOCK do zapisu) czeka na odczyt w toku – najwyżej timeout ublk (5 s).
- usbd: `Loc.parent` / `hub_port`; transfer bulk za hubem przerywany, gdy hub-rodzic zgłosi zmianę na tym porcie
  (`XferError::Interrupted` → EIO dla jądra, `needs_recovery` – reset recovery przed następną komendą, jeśli
  urządzenie zostało). Port kontrolera – jak dotąd (CCS w pętli czekania).
- init: komunikaty dla usbd – restart („USB keyboard and disks back in a moment”) i broken („USB controller usbN
  disabled after 5 failures – its USB keyboard and disks are unavailable until reboot (PS/2 still works)”).
- Autostress: zadanie `usb-stress` czyta w trakcie stressu największy plik (≤ 64 MiB) z pierwszego /usbN, sumy
  kontrolne przejść porównywane; wynik w linii `usb:` i w [RESULT] (pass=0 przy błędzie albo różnicy).
  `stress-qemu.sh` podłącza testowy pendrive (mkfat32.py).

### Stan (v0.29.0, krok h – M20 zamknięte)

- **FAT32 szybciej** (każde żądanie do pendrive'a to komenda SCSI, kilkaset µs – ms): FAT czytany blokami po 8
  sektorów; cache klastrów (≤ 512 KiB / 64 wpisy, zapis przez cache) – odczyt pliku nie czyta katalogów ścieżki za
  każdym razem; ciągłe klastry pliku jednym odczytem (≤ 1 MiB); odczyt z wyprzedzeniem 64 KiB dla małych odczytów
  (klaster 512 B – 4 KiB, `cat` po 512 B); zapamiętana pozycja w łańcuchu (odczyt po kolei bez przechodzenia
  łańcucha od początku; `fat_set` ją kasuje).
- **ublk potokiem**: odczyt dłuższy niż slot wysyła do 4 żądań naraz (usbd bierze następne z kanału zaraz po
  poprzednim); błąd odpowiedzi – nowe nie wychodzą, na wysłane czekamy (sloty wracają); timeout – wysłane sloty w
  kwarantannie. Ta sama walidacja odpowiedzi co dotąd (id, liczba bloków).
- **`df`**: wolne klastry liczone z FAT (raz, blokami po 64 KiB) na dysku tylko do odczytu – FSInfo bywa
  nieaktualny. Obraz testowy ma celowo zły główny FSInfo (kopia w sektorze 7 – prawdziwa).
- **usbd**: INQUIRY do 4 prób (przerwy 200 / 400 / 600 ms; licznik `stor_retries`); czas enumeracji urządzenia
  (reset portu → sterownik klasy gotowy) w linii urządzenia („ready in N ms”) i w statusie (`enum_count`,
  `enum_avg_ms`, `enum_max_ms`).
- **Opóźnienie klawiatury**: handler MSI zapisuje znacznik czasu (HPET) ostatniego przerwania wektora;
  `input_inject` przy wciśnięciu liczy czas od ostatniego przerwania urządzeń procesu do znaku w kolejce wejścia
  jądra (`input::hid_latency` – liczba, średnia, min, max; > 1 s pomijane).
- **Pomiary**: `[RESULT-USB]` w `test.sh` (+ `enum_avg_ms enum_max_ms kread_kbs kcat_kbs hid_n hid_avg_us
  hid_max_us`; klawisze przez `sendkey` z monitora QEMU) i w autostressie (Legion: odczyt przed stressem buforem
  256 KiB i 4 KiB, dane muszą być te same; klawiatura – wciśnięcia od startu).

### Testy (każdy krok) i ponowne użycie M19

- QEMU: `qemu-xhci` + `usb-kbd`, `usb-mouse`, `usb-hub`, drugi `usb-storage` z obrazem `readonly=on`; monitor QEMU:
  `sendkey`, `device_add` / `device_del` (podłączanie w locie).
- Te same sprawdzenia wycieków co w SVC TEST (ramki, uchwyty, wektory MSI, przejęcia) po każdym teście USB i po
  każdym kill usbd; kill w trakcie: enumeracji, pisania, odczytu z pendrive'a.
- Pełne kolejki: zalew zdarzeń HID (bufor wejścia pełny – licznik zgubionych, bez blokowania usbd), wszystkie sloty
  ublk zajęte, timeouty (usbd celowo nie odpowiada – tryb testowy), odpowiedź spóźniona i z cudzym `id`.
- Wynik: `[RESULT-USB]` (odczyt MB/s, przerwanie HID → znak w konsoli µs, czas enumeracji ms).

### Numery (robocze) – bez kolizji

Zajęte: 0–47 (21 = `ENOSYS`, dawne `kcmd`). Nowe: **48 `dev_find`** (od v0.23.0), **49 `input_inject`** (od v0.25.0),
**50 `blk_attach`** (od v0.26.0).
Uchwyty 1–9 zajęte; nowe **10 `INPUT`, 11 `BLK`**. Sloty init: 3 `HW_ROOT`, 4 `SYSCTL`, nowe 5 `INPUT`, 6 `BLK`.
Błędy – istniejące (`EIO`, `ENODEV`, `EBUSY`, `ENOSPC`, `EINVAL`, `EBADF`, `EROFS`); nowego kodu nie trzeba.

## Scheduler – P4 (projekt 2026-10-14)

**Dziś:** jedna globalna blokada schedulera (spinlock z właścicielem-CPU, rekurencyjna) chroni wszystko: listę zadań,
kubełki numerów, kolejkę gotowych, kubełki kanałów (uśpieni), listę terminów, `current[]`. Przełączenie (`schedule`)
dzieje się POD nią – blokadę zwalnia dopiero następne zadanie (po `sched_switch`, także `sched_new_task_start`).

**Pomiar (Legion v0.29.0, autostress 60 s, 16 CPU):** 40,1 mln wzięć, 41% czeka, 18,9 s czekania; łączny czas trzymania
~16 s na 60 s – blokada zajęta ~27% czasu, więc każdy dodatkowy rdzeń częściej trafia na zajętą.

| miejsce | wzięcia | czeka | trzyma | co robi |
|---|---|---|---|---|
| `with_process` | 11,1 mln | 37% | 1,3 s | odczyt procesu po numerze (rodzic dziecka, `wait`, `kill`) |
| `wait_event` | 10,6 mln | 48% | 6,3 s | warunek + uśpienie **+ przełączenie** |
| `wake_channel` | 7,6 mln | 44% | 1,8 s | pobudka z kubełka |
| `exit` | 3,3 mln | 37% | 3,4 s | Dead **+ przełączenie** |
| `spawn_in` / `reap` | 3,3 / 1,6 mln | 33–42% | 1,0 / 1,1 s | lista zadań |
| `task_exists` | 1,0 mln | 30% | 0,1 s | odczyt |

**Co znaleźliśmy (2026-10-14):** blokada schedulera czekała najgorszym sposobem – `compare_exchange` w każdym
obrocie (test-and-set): każdy czekający zabiera linię pamięci podręcznej z blokadą pozostałym i trzymającemu, koszt
przekazania rośnie z liczbą czekających (MIT, „Non-scalable locks are dangerous”). Zwykłe spinlocki DeSoOS już
czekały odczytem, BKL jest biletowy. BFS (Linux, jedna globalna kolejka) skalował się do ~16 CPU – Legion ma 16,
więc kolejki per CPU to zapas, nie pilna potrzeba.

**Wybór z innych systemów:** przełączanie bez globalnej blokady z flagą `on_cpu` – Linux; dostęp do procesów przez
`Arc` (zamiast RCU) – Redox; jeśli kiedyś kolejki per CPU: ULE (FreeBSD – bezczynny CPU zabiera pracę, rzadkie
wyrównanie), MuQSS (trylock przy wyborze), pobudka na cudzy CPU listą + IPI – Linux (`TTWU_QUEUE`, +26% w sembench).

**Plan (kolejność od najbezpieczniejszego):**

0. **Czekanie odczytem (P4.0, v0.30.0).** Pętla czekania czyta właściciela; `compare_exchange` dopiero, gdy blokada
   wygląda na wolną (test-and-test-and-set). To samo: blokada listy zombie procesu, inicjator TLB shootdown.
1. **Tablica zadań pod własną blokadą RW (P4.b, v0.31.0 – zrobione; `TABLE` w `sched/mod.rs`, test SMP 6/6).** `tasks` + `ids` – zapis: `spawn_in` (dodanie), `reap` (usunięcie),
   `reparent_with` (zmiana rodziców – musi wykluczać `with_process`, jak dziś). Odczyt równolegle: `with_process`,
   `task_exists`, `children_of`, `for_each_process`. Stan „Dead” dla czytających – lustro atomowe w zadaniu
   (`state` zmienia się pod blokadą schedulera). Kolejność blokad: scheduler → tablica (spawn / reap biorą obie);
   czytający biorą tylko tablicę. Zadanie żyje, dopóki jest w tablicy (reap usuwa pod zapisem), więc referencja w
   `with_process` jest ważna. Zamknięcie `with_process` bierze `zombies` (spinlock) – poziom tablicy niżej.
2. **Przełączenie poza blokadą (P4.c, v0.32.0 – zrobione; `on_cpu`, `finish_switch`, `SCHED_SKIP`, test SMP 7/7).** Zadanie ma flagę `on_cpu` (ustawiana przy wyborze, zdejmowana przez CPU
   po zejściu z zadania – pierwsze, co robi następne zadanie). Pod blokadą: wybór następnego, stany, kolejki,
   `current[]`; potem zwolnienie i dopiero FXSAVE/FXRSTOR, TSS / stos SYSCALL, CR3, `sched_switch`. CPU, który wybrał
   zadanie z `on_cpu` (np. obudzone, zanim poprzedni CPU z niego zszedł), czeka na zdjęcie flagi (kilkaset ns) –
   jak `on_cpu` w Linuksie. Reap pomija zadania z `on_cpu` (martwe zadanie jeszcze na swoim stosie). Pobudka bez
   zmian (stan i kubełki pod blokadą), więc uśpienie / pobudka nie mogą się minąć. Znika przenoszenie blokady przez
   przełączenie (`sched_depth`, zwalnianie w `sched_new_task_start`).
3. **Dalej według pomiarów (P4.d):** kolejki gotowych per CPU z kradzieżą zadań albo osobne blokady kubełków kanałów
   (protokół jak `try_to_wake_up`). Tylko jeśli po 1–2 blokada nadal wyraźnie czeka.

**Testy:** wszystkie 28 zestawów (1 i 4 CPU, TCG i KVM) po każdym kroku; nowe w SCHED TEST: (b) zadania pytające
`with_process` / `task_exists` w kółko w trakcie spawn / exit / reap (znacznik w zadaniu sprawdzany przy odczycie –
zwolnione zadanie = FAIL), (c) burza uśpień i pobudek między CPU z terminem bezpieczeństwa (pobudka po terminie =
zgubiona = FAIL), exit + reap w pętli (licznik czekań na `on_cpu`, asercja: reap nigdy nie zwalnia zadania z
`on_cpu`), mutacja: bez czekania na `on_cpu` test musi się wywrócić. Na końcu autostress KVM i Legion (compare, max6).

## Pomiar i testy

- `tests/test.sh` – 28 zestawów samotestów w QEMU (TCG albo `ACCEL=kvm`, 1–4 CPU): wyjątki, pamięć, scheduler,
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
