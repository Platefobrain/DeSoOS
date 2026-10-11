# DeSoOS

Własny system operacyjny x86_64 napisany w Rust – od bootloadera UEFI po procesy w user space
i komunikację między nimi. *A hobby x86_64 operating system written in Rust (UEFI, SMP, user space, IPC).*

Wersja: **0.18.4** (etap M18 – IPC). Testowany w QEMU i na prawdziwym laptopie (Lenovo Legion, 16 CPU).

## Co działa

- **Start:** UEFI → własny bootloader DSB → jądro w górnej połowie przestrzeni adresowej.
- **Pamięć:** paging 4-poziomowy, NX / SMEP / SMAP, heap jądra z listami per CPU, pamięć procesów
  z leniwymi stronami (`brk`, `mmap`), pamięć współdzielona.
- **Wiele rdzeni:** ACPI (MADT), APIC / I/O APIC, do 16 CPU, drobne blokady zamiast Big Kernel Lock,
  TLB shootdown, watchdog z NMI, wykrywanie złej kolejności blokad.
- **Procesy:** ring 3, statyczne programy ELF w Rust, `/bin/init` i shell w user space (potoki,
  przekierowania, `&`, Ctrl+C), 38 syscalli.
- **IPC:** uchwyty z prawami (można je tylko zmniejszać), kanały z przekazywaniem uchwytów,
  pamięć współdzielona, `spawn_ex` (dziecko dostaje tylko wskazane uchwyty).
- **Sprzęt:** konsola na framebufferze (polskie znaki), serial, klawiatura i mysz PS/2, PCI / PCIe (ECAM),
  MSI-X, virtio-blk, NVMe, GPT, HPET, RTC.
- **Pliki:** VFS, ramfs, FAT32 (długie nazwy).

Opis budowy systemu: [`ARCHITEKTURA.md`](ARCHITEKTURA.md). Plan etapów: [`roadmapa`](roadmapa).
Historia zmian: [`CHANGELOG.md`](CHANGELOG.md).

## Wymagania

Linux (testowane na Linux Mint / Ubuntu):

```bash
# Rust (stabilny, edycja 2024 – rustc 1.85 lub nowszy)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# QEMU, firmware UEFI, binutils
sudo apt install qemu-system-x86 ovmf binutils
```

Targety `x86_64-unknown-none` i `x86_64-unknown-uefi` `build.sh` doinstaluje sam przez `rustup`.

## Budowanie i uruchamianie

```bash
./build.sh               # buduje build/EFI/BOOT/BOOTX64.EFI
./run-qemu.sh            # uruchamia DeSoOS w QEMU (shell: wpisz help)
./test.sh                # samotesty w QEMU (26 zestawów) – wynik PASS / FAIL
ACCEL=kvm ./test.sh      # to samo z KVM (szybciej)
SMP=8 ./stress-qemu.sh   # stress test 60 s na 8 CPU, na końcu linia [RESULT]
```

Nie uruchamiaj skryptów przez `sudo`. Obrazy dysków (`disk.img`, `nvme.img`) `run-qemu.sh` tworzy
przy pierwszym uruchomieniu.

## Prawdziwy komputer (pendrive)

```bash
./make-usb.sh /media/$USER/NAZWA                         # wgrywa DeSoOS na zamontowany pendrive FAT32
DESOOS_AUTOSTRESS=60 ./make-usb.sh /media/$USER/NAZWA    # sam robi stress test 5 s po starcie
```

Uruchom komputer z pendrive'a w trybie UEFI (Secure Boot wyłączony).

**Bezpieczeństwo danych:** DeSoOS nie zapisuje na prawdziwe dyski – sterownik NVMe zapisuje tylko do
kontrolera emulowanego przez QEMU, a warstwa dysków odrzuca każdy zapis na dysk tylko do odczytu.
Mimo to to eksperymentalny system – używasz na własną odpowiedzialność.

Klawiatury na USB (większość laptopów) jeszcze nie ma – przyjdzie z obsługą USB (etap M20).

## Struktura

```
boot/          bootloader UEFI (DSB) – ładuje jądro ELF
common/        kod wspólny bootloadera i jądra (parser ELF)
kernel/        jądro
  arch/x86_64/   GDT, IDT, wyjątki, APIC, SMP, TLB, SYSCALL
  memory/        ramki, paging, heap
  sched/         scheduler, blokady, stosy zadań
  drivers/       konsola, klawiatura, PCI, NVMe, virtio, ...
  fs/            VFS, ramfs, FAT32
  user/          procesy, syscalle, ELF loader, IPC, testy
user/          programy user space
  bin/           init, sh, ls, cat, ... oraz programy testowe
  lib/           biblioteka programów (syscalle, alokator)
```

## Licencja

Copyright (C) 2026 Dawid ([Platefobrain](https://github.com/Platefobrain))

DeSoOS jest wolnym oprogramowaniem: możesz go rozpowszechniać i zmieniać na warunkach
**GNU General Public License w wersji 3** albo (według Twojego wyboru) dowolnej późniejszej wersji,
opublikowanej przez Free Software Foundation. Program jest rozpowszechniany bez żadnej gwarancji.
Pełny tekst: [`LICENSE`](LICENSE). SPDX: `GPL-3.0-or-later`.

**Wyjątek – czcionka konsoli.** Plik [`kernel/drivers/font.rs`](kernel/drivers/font.rs) zawiera
zmodyfikowany podzbiór czcionki **Terminus Font** (Copyright (c) 2020 Dimitar Toshkov Zhekov,
Reserved Font Name "Terminus Font") i podlega wyłącznie licencji **SIL Open Font License 1.1** –
pełny tekst w [`FONT-LICENSE.txt`](FONT-LICENSE.txt), SPDX: `OFL-1.1`. Przy rozpowszechnianiu
DeSoOS, także w postaci zbudowanej (`BOOTX64.EFI`), dołącz `LICENSE` i `FONT-LICENSE.txt`.
