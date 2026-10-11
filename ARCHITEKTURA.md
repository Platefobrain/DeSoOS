# Architektura DeSoOS

Opis tego, jak system jest zbudowany i jak działa (stan: v0.18.4, po M18). Historia zmian: `CHANGELOG.md`,
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

- **Ramki** – bitmapa, ramki 4 KiB i ciągłe (DMA); `IrqSpinLock`.
- **Heap jądra** – bloki do 2 KiB w klasach 16..2048 B: każdy CPU ma własną listę wolnych bloków na klasę
  (bez blokady, IF = 0), z heapem wymienia paczki. Duże bloki – wspólna lista po adresie (first-fit, scalanie).
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
  uruchamia shell i zbiera sieroty; `kill(init)` → EPERM.
- **`spawn` zamiast `fork`/`exec`** – nowy obraz ELF, kopia cwd, wskazane uchwyty. `spawn_ex` daje dziecku
  **tylko** wymienione uchwyty (podstawa sandboxa).
- Zakończony proces zostaje zombie (sam kod wyjścia) do `wait` rodzica. Status: kod 0..255 albo
  `0x100 | powód` (9 = kill, 14 = #PF). Rodzina i zombie pod jedną blokadą (`procs.rs`), rodzic czeka w jednej
  z 64 kolejek.
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
| 19–21 | `readkey` (edytor linii), `tasks` (ps), `kcmd` (tymczasowy most do komend shella jądra – do M19) |
| 22–25 | `dup`, `dup2`, `seek`, `pipe` |
| 26–28 | `brk`, `mmap`, `munmap` |
| 29–30 | `handle_dup`, `handle_info` |
| 31–33 | `channel_create`, `chan_send`, `chan_recv` |
| 34, 35, 37 | `shm_create`, `shm_map`, `shm_size` |
| 36 | `spawn_ex` |

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
| 40 | procesy (zombie, rodzina), potoki, kanały |
| 50 | scheduler (poza lockdep, rekurencyjna) |
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

## Co jądro da usługom w user space (M19)

1. MMIO urządzenia zmapowane do procesu (bez cache) – jako uchwyt z prawami.
2. Przerwanie jako komunikat w kanale (+ potwierdzenie/EOI).
3. Bufory DMA o znanym adresie fizycznym (obiekt pamięci współdzielonej).
4. Porty I/O.
5. Później: IOMMU, żeby urządzenie nie widziało całej pamięci (do tego czasu izolacja sterownika z DMA jest
   częściowa).

Usługa pada → jądro i reszta działają, init może ją uruchomić ponownie. Most `kcmd` znika na rzecz usług.

## Pomiar i testy

- `./test.sh` – 26 zestawów samotestów w QEMU (TCG albo `ACCEL=kvm`, 1–4 CPU): wyjątki, pamięć, scheduler,
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
