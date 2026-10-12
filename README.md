# DeSoOS v0.22.0

Wlasny system operacyjny

Lancuch startowy:

UEFI/OVMF -> DSB -> DeSoOS kernel

## Budowanie

```bash
./build.sh              # zwykly kernel (bez samotestow)
./build.sh --selftest   # kernel z samotestami (27 zestawow, M1-M19 + etap P)
./test.sh               # build --selftest + testy w QEMU, wynik PASS/FAIL
```

Nie uruchamiaj `build.sh` przez sudo.

Kernel jest kompilowany z optymalizacja (`-O`) do `build/kernel.elf` (z symbolami, do gdb).
DSB ma w sobie kopie bez symboli (`build/kernel.boot.elf`), laduje jej segmenty ELF pod
`0xffffffff80000000` (kernel w gornej polowie), alokuje stos ze strona-straznikiem i skacze
do kernela. Rozmiar kernela nie jest juz ograniczony do 512 KiB.

Pamiec wirtualna (od v0.8): dolna polowa pusta (dla procesow), fizyczna pamiec pod
`0xffff800000000000 + adres` (direct map), heap `0xffffc00000000000`, kernel `0xffffffff80000000`,
stos `..0xffffffffc0041000`. Komenda `mem` pokazuje, gdzie fizycznie lezy kernel.

## QEMU

```bash
./run-qemu.sh
```

Po starcie kernel uruchamia `/bin/init`, a init - shell w user space (`desoos:/$`), na ekranie
QEMU i w terminalu jednoczesnie. Mozna pisac w oknie QEMU (klawiatura PS/2) albo w terminalu,
z ktorego odpalono `run-qemu.sh`. Wpisz `help`, zeby zobaczyc komendy.

Shell (M16, `user/bin/sh.rs`, ring 3):

- programy po nazwie: `ls /bin`, `primes 50000`, `args "jeden dwa" trzy`, albo sciezka: `cd /bin`, `./hello`
- `> plik`, `>> plik`, `< plik`, `&` na koncu = w tle (`ps`, `kill <pid>`, `wait`)
- wbudowane: `cd`, `pwd`, `echo`, `exit`, `help`, `history`, `clear`, `wait`, `sync`, `reboot`, `halt`, `stress`
- informacje od jadra (tylko odczyt): `mem`, `cpus`, `irq`, `lspci`, `acpi`, `disk`, `mount`, `df`, `date`, `ver`, `uptime`
- uslugi: `services` (stan uslug uruchomionych przez init)
- `mkfs`, zapis na dysk (`disk write`) i `run` - tylko w awaryjnym shellu kernela
- `exit` albo zabicie shella (`kill <pid sh>`) - init uruchamia nowy shell
- Ctrl+C konczy program na pierwszym planie, nie shell

Awaryjnie (brak `/bin/init` albo init ciagle pada) startuje shell kernela (`desoos>`).

QEMU dostaje (M16b) takze dysk NVMe `nvme.img` (tworzony przy pierwszym starcie). To jedyny NVMe,
do ktorego DeSoOS zapisuje - emulowany kontroler QEMU. Katalog `build/` QEMU widzi jak pendrive USB
tylko do odczytu (tak jak prawdziwy start z pendrive'a).

## Prawdziwy komputer (M16b) - start z pendrive'a

### Czy moje dane sa bezpieczne?

Tak - DeSoOS na prawdziwym komputerze **niczego nie zapisuje na dyski**:

1. **Sterownik NVMe** pozwala zapisywac tylko emulowanemu kontrolerowi QEMU (PCI `1b36:0010`). Kazdy
   prawdziwy SSD jest "tylko do odczytu": zapis konczy sie bledem, zanim cokolwiek trafi do dysku.
   Do SSD ida tylko polecenia odczytu i konfiguracji kolejek (zadnych Write, TRIM, Format, Sanitize,
   aktualizacji firmware).
2. **Warstwa dyskow** (`kernel/block.rs`) niezaleznie odrzuca kazdy zapis na dysk "tylko do odczytu" -
   takze `mkfs`, `disk write`, zapis plikow w `/esp`.
3. **Pendrive** jest dla DeSoOS niewidoczny (nie ma jeszcze sterownika USB - M20); czyta go tylko firmware
   przy starcie.
4. Sprawdzone w QEMU na kopii ukladu dysku Ubuntu (GPT: ESP + swap + ext4), z kontrolerem udajacym
   prawdziwy SSD i sledzeniem polecen NVMe: po starcie DeSoOS **0 polecen zapisu**, mimo prob
   `echo > /esp/...`, `rm`, `mkfs`, `disk write`.

Jedyna zmiana poza pendrive'em to ustawienie Secure Boot w BIOS-ie (patrz nizej).

### 1. Pendrive

Wystarczy dowolny pendrive z FAT32 (np. pusty, nowy). DeSoOS to jeden plik: `EFI/BOOT/BOOTX64.EFI`.

```bash
./make-usb.sh --list                    # pokazuje dyski USB (i ktore sa systemowe - tych nie rusza)
./make-usb.sh /media/$USER/NAZWA        # buduje i kopiuje DeSoOS na zamontowany pendrive
```

Skrypt **niczego nie formatuje**, sprawdza, ze cel to FAT32 na dysku USB (nie systemowym), i nie
nadpisze innego bootloadera (np. instalatora Ubuntu) bez `--overwrite`. Pendrive z exFAT/NTFS (czesto
duze, nowe) trzeba raz sformatowac na FAT32 - to KASUJE pendrive: `./make-usb.sh --format /dev/sdX`
(sprawdza USB i kaze przepisac nazwe urzadzenia) albo w programie "Dyski".

### 2. BIOS (Lenovo Legion 5: F2 przy logo, albo przycisk Novo z boku)

- **Secure Boot -> Disabled** (DSB nie jest podpisany). Ubuntu startuje tak samo z wylaczonym Secure Boot.
  Po testach mozna go wlaczyc z powrotem.
- **Uwaga, jesli na laptopie jest tez Windows z BitLockerem**: zmiana Secure Boot moze wymusic podanie
  klucza odzyskiwania BitLockera - najpierw zapisz ten klucz (konto Microsoft / ustawienia BitLockera).

### 3. Start

Wloz pendrive, wlacz komputer, **F12** przy logo Lenovo -> wybierz pendrive (`EFI USB Device`).
Na ekranie: logi startu, potem `desoos:/$`. Warto sprawdzic:

- `disk` - dyski NVMe i partycje GPT (wszystko `read-only`)
- `ls /esp` - partycja EFI z dysku (tylko do odczytu), np. `ls /esp/EFI`
- `lspci`, `acpi`, `mem`, `ps`
- `cpus` - rdzenie procesora (M17: Ryzen 7 4800H powinien pokazac 16 CPU online)
- Shift+PgUp - przewijanie logow startu

Komputer nie ma portu szeregowego - wszystko widac tylko na ekranie (zrob zdjecie, jesli cos
nie dziala). Wylaczenie: `k halt` i przytrzymaj przycisk zasilania, albo od razu przytrzymaj przycisk.
Potem wyjmij pendrive - komputer startuje normalnie z dysku.

Jesli wewnetrzna klawiatura nie dziala (laptopy bez kontrolera 8042), DeSoOS i tak wystartuje - widac
logi, ale nie da sie pisac; klawiatura USB dojdzie w M20.

## Pliki

- `/` to ramfs (w pamieci, znika po restarcie), `/disk` to dysk FAT32 (`disk.img`, zostaje).
- Nowy `disk.img` jest pusty - sformatuj go raz w DeSoOS: `mkfs 0`, potem `mkfs 0 yes`
  (od razu montuje sie w `/disk`). Dopoki dysk nie jest sformatowany, `/disk` nie istnieje.
- Sprawdzenie: `df` pokazuje dwie linie (`/` i `/disk`) - wtedy pliki w `/disk` przetrwaja restart.
- Komendy: `ls`, `cd`, `pwd`, `cat`, `touch`, `mkdir`, `rm`, `cp`, `mv`, `stat` (programy w /bin
  albo wbudowane) oraz `hexdump`, `write`, `mount`, `df`, `mkfs`, `sync`, `date` (kernel).
  Przekierowanie: `echo tekst > plik`, `help >> plik`. Nazwy ze spacjami w cudzyslowach:
  `cat "moj plik.txt"`.
- Dysk jest zgodny z Linuxem: na hoscie mozna go czytac i zapisywac np. przez mtools
  (`mdir -i disk.img ::`, `mcopy -i disk.img plik.txt ::/`) - tylko gdy QEMU jest wylaczone.
- Na nizszym poziomie: `lspci`, `disk`, `disk read 0 <sektor>`, `disk write 0 <sektor> <tekst>`.
- Zadania (M12): `ps` - lista zadan (stan, czas CPU), `spawn spin` - zadanie w petli bez przerwy
  (shell dalej odpowiada dzieki wywlaszczaniu), `spawn tick` - zadanie budzace sie co 1 s,
  `kill <id>` - zakonczenie zadania.
- Wiele rdzeni (M17): `cpus` - procesory, zadanie na kazdym, ticki timera, IPI. Kolumna `CPU` w `ps`
  pokazuje rdzen (`~2` = nie dziala teraz, ostatnio CPU 2). Np. `primes 3000000 &` dwa razy, potem `ps`
  - oba licza naraz na roznych rdzeniach. QEMU startuje z 4 rdzeniami (`-smp 4` w `run-qemu.sh`).
- Szybciej i naprawdę równolegle (Linux z KVM): `ACCEL=kvm ./run-qemu.sh`, `ACCEL=kvm ./test.sh`
  (potrzebny dostęp do /dev/kvm: `sudo usermod -aG kvm $USER`, potem wyloguj się). Liczba rdzeni: `SMP=8`.
- Stress test (M17a): `stress` (10 s) albo `stress 300` - wiele procesow, pliki, spinlocki na wszystkich
  rdzeniach naraz; na koncu `stress PASS: ...`. Potem `cpus` pokazuje, ile razy rdzenie czekaly na
  Big Kernel Lock, i statystyke TLB shootdown (M17a.b).
- Stress test bez klawiatury (np. Legion z pendrive'a): `DESOOS_AUTOSTRESS=60 ./make-usb.sh /media/...`
  (albo `./build.sh --autostress=60`) - 5 s po starcie kernel sam robi stress test 60 s i wypisuje na
  ekranie `[AUTOSTRESS] PASS/FAIL`, `cpus` i `mem`. Zwykly `./make-usb.sh` - bez tego.
- Procesy w ring 3 (M13a): `run` - lista programow testowych, `run sum` - pierwszy program
  uzytkownika (wynik 5050), `run pf` / `gp` / `ud` / `nx` / `sse` - bledy, ktore koncza tylko
  proces, `run loop` - petla bez konca (Ctrl+C konczy), `run loop &` - w tle (`ps`, `kill`).
  `run <program> <n>` uruchamia n kopii naraz (1..16), np. `run xmm 16 &`. Komunikat procesu z tla
  nie psuje linii, ktora piszesz - prompt z wpisanym tekstem rysuje sie pod nim od nowa.
- Syscalle (M14): `run hello` (write), `run cat` (read z klawiatury; od M15 to programy ELF z /bin), `run files` (open/write/read
  na /tmp/ring3.txt - potem `cat /tmp/ring3.txt`), `run ticker &` (sleep, wypisuje w tle),
  `run regs` (100 tys. syscalli), `run badptr` (zly wskaznik -> -14). Ctrl+C konczy proces na
  pierwszym planie. Lista syscalli: `kernel/user/syscalls.rs` i ARCHITEKTURA.md.
- Od M16 programy uruchamia sie po nazwie (bez `run`); `run ...` nizej dziala dalej (komenda kernela).
- Programy ELF (M15): `ls /bin` - programy napisane w Rust (`user/bin/*.rs`), wbudowane w kernel.
  `run hello`, `run args jeden dwa` (wypisuje argv), `run primes 50000` (liczy liczby pierwsze),
  `run save notatka.txt ala ma kota` + `run cat notatka.txt` (pliki, sciezki wzgledem `cd`),
  `run primes 300000 &` - w tle. To zwykle pliki: `cp /bin/args /tmp/a` i `run /tmp/a x` albo
  `cd /tmp` i `run ./a x`. Samo `run` pokazuje liste (/bin + programy testowe w asm).
  Nowy program: plik `user/bin/<nazwa>.rs` (wzor: `user/bin/hello.rs`) i `./build.sh` - pojawi sie
  jako `/bin/<nazwa>`. Biblioteka: `user/lib/desoos.rs` (`println!`, `open`, `read`, `write`,
  `sleep_ms`, argumenty; od M16 `spawn`/`wait`/`kill`, katalogi, `readkey`, a z `extern crate alloc;`
  takze `Vec`/`String`).
- FPU/SSE w procesach (M13b): `run sse` (42), `run x87` (3), `run xmm 3` - 3 procesy naraz, kazdy
  wypelnia xmm0-15 swoimi wartosciami i sprawdza je 2 mln razy (wynik 1 = nic sie nie pomieszalo),
  `run fpuclean` - nowy proces zaczyna z czystymi rejestrami.

- strzalki, Home/End, Backspace/Delete - edycja linii
- strzalki gora/dol - historia, Tab - dopelnianie komendy
- Ctrl+C - porzuc linie, Ctrl+U - wyczysc linie, Ctrl+L - wyczysc ekran
- przewijanie ekranu wstecz (1000 linii): Shift+strzalka gora/dol - o 1 linie,
  Shift+PgUp/PgDn - o caly ekran, kolko myszy - o 3 linie; pisanie wraca na dol.
  Na klawiaturze numerycznej tez: Shift + 8/2 (linia), Shift + 9/3 (ekran). Dziala w oknie QEMU (nie w terminalu - terminal ma wlasna historie).
  Mysz: najpierw kliknij w okno QEMU (przechwyci mysz), zwolnienie myszy: Ctrl+Alt+G.
- polskie znaki na klawiaturze PS/2: prawy Alt (AltGr) + a/c/e/l/n/o/s/x/z, AltGr+u = €

Uwaga: w terminalu QEMU (`-serial stdio`) Ctrl+C zamyka QEMU. W oknie QEMU Ctrl+C trafia do shella.

## Samotesty (`--selftest`, `./test.sh`)

`./test.sh` buduje kernel z samotestami, uruchamia QEMU bez okna i konczy sie wynikiem:
`PASS` (kod 0), `FAIL` (1, z lista bledow), `TIMEOUT` (2, zawieszenie) albo blad QEMU (3).
Pelny log: `test.log`. Testy dzialaja na osobnym, pustym dysku - `disk.img` zostaje nietkniety.
Opcje: `--no-build` (bez budowania), `--verbose` (log na biezaco), `TIMEOUT=300 ./test.sh`.
QEMU w testach dziala z `-cpu max` (NX, SMEP jak na nowym procesorze).
Nie uruchamiaj `test.sh` rownoczesnie z `run-qemu.sh` (oba uzywaja katalogu `build/`).

Jak to dziala: QEMU dostaje plik fw_cfg `opt/desoos/autotest` i urzadzenie `isa-debug-exit`;
kernel po testach (albo przy panice / krytycznym wyjatku) sam wylacza QEMU z kodem wyniku.
Zwykle `./run-qemu.sh` z buildem `--selftest` dziala jak dotad - po testach startuje shell.

Build z `--selftest` kompiluje kernel z `--cfg selftest`: po kazdym etapie
uruchamia sie jego test, a wyniki ida na serial (`... TESTS PASSED` albo
`... FAIL: ...`). Zwykly build nie zawiera kodu testow wcale (kod testowy jest
oznaczony `#[cfg(selftest)]`), wiec startuje od razu, bez ok. 2 s testow.

Przy dodawaniu nowego etapu: funkcje/testy uzywane tylko w testach oznaczaj
`#[cfg(selftest)]`, a wywolanie `self_test()` w `kernel_main` tez pod
`#[cfg(selftest)]`.

## Stan (etapy)

Kolejnosc startu kernela (M16b: po konsoli ACPI + Local APIC, po virtio NVMe + partycje GPT): serial -> GDT/IDT (M4) -> frame allocator (M1) -> paging (M2) -> heap (M3) -> mapowanie on-demand (M4) -> PIC + PIT + `sti` (M5) -> klawiatura PS/2 (M6) -> konsola na ekranie + shell (M7; konsola startuje zaraz po M4, od tego momentu logi sa tez na ekranie) -> PCI + dysk virtio (M8) -> VFS: ramfs w / i FAT32 w /disk (M9).
Scheduler (M12) startuje zaraz po timerze: kod startowy staje sie zadaniem 1 ("kernel", potem shell), obok dziala zadanie 0 ("idle").
DSB (M10): ELF kernela -> wlasne tablice stron (direct map + kernel w gornej polowie + stos) -> ExitBootServices -> skok do kernela.
Szczegoly i plan: `roadmapa`. Architektura (co w kernelu, co w user space): `ARCHITEKTURA.md`. Historia zmian: `CHANGELOG.md`.

## Licencja

DeSoOS: GNU General Public License v3 albo nowsza (`GPL-3.0-or-later`) - pelny tekst w `LICENSE`.
Wyjatek: `kernel/drivers/font.rs` - zmodyfikowany podzbior czcionki Terminus Font (Copyright (c) 2020
Dimitar Toshkov Zhekov), wylacznie na licencji SIL Open Font License 1.1 (`OFL-1.1`) - patrz `FONT-LICENSE.txt`.
Rozpowszechniajac DeSoOS (takze BOOTX64.EFI) dolacz `LICENSE` i `FONT-LICENSE.txt`.
