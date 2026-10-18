# Changelog DeSoOS

Format: najnowsze na gorze. Daty wg czasu polskiego.

## v0.35.2 — 2026-10-17

### Bezpieczeństwo, krok 3: limity – etap zamknięty
- **Procesy:** najwyżej 1024 (żywe + jeszcze nie sprzątnięte). Ponad 960 `spawn` dostaje `EAGAIN`; ostatnie 64 miejsca
  tylko dla init i jego bezpośrednich dzieci (shell, usługi) – po bombie procesów shell nadal uruchomi `ps` / `kill`,
  a init zrestartuje usługę.
- **Zapas pamięci tylko dla jądra:** 1/16 RAM (16–256 MiB; Legion 16 GB → 256 MiB, QEMU 512 MiB → 32 MiB). Strony
  procesów, ich tablice stron i pamięć współdzielona – tylko ponad zapasem (`alloc_frame_user`, sprawdzenie bez
  blokady). Pożeracz pamięci ginie (brak strony), `shm_create` dostaje `ENOMEM`, jądro dalej ma z czego działać.
- **Bufory IPC na heapie jądra:** kolejki kanałów i dane w potokach razem najwyżej 16 MiB (`kbuf`). Wcześniej kilka
  procesów mogło zapełnić heap (64 MiB) kolejkami i jądro padało przy następnej alokacji. Ponad budżetem: `chan_send`
  i zapis do potoku – `ENOMEM` (komunikat wraca, nic nie ginie).
- **ramfs:** pliki (też na heapie) najwyżej 24 MiB – ponad tym `ENOSPC`. **Znaleziony przy okazji błąd:** `seek` na
  ogromną pozycję + zapis 1 bajtu kazał jądru zaalokować gigantyczny bufor – panika jądra z dowolnego programu. Teraz
  `ENOSPC`. Rozmiar plików zmieniany przez `try_reserve` (brak pamięci = błąd, nie panika).
- `cpus`: linia `limits: N of 1024 processes, kernel memory reserve X MiB (… refused), IPC buffers … ramfs …`.
- **Test:** FILE TEST 6/6 – `/bin/limtest` (17 sprawdzeń): bomba procesów do `EAGAIN` (959 procesów w QEMU), potem
  znowu działa; `shm_create(16 MiB)` do `ENOMEM`; pożeracz pamięci zabity; ramfs do `ENOSPC` + zapis na 1 TiB →
  `ENOSPC`; kolejki kanałów (z pomocnikiem) do `ENOMEM`, potok w tym czasie – `ENOMEM`, po zamknięciu działa. Jądro
  sprawdza, że procesy, budżet IPC, ramfs i ramki wróciły, a zwykły program działa.
- **Legion (v0.35.2):** porównawczy **600 637** (v0.34.3: 599 726), max6 **593 350** (593 119) – limity nic nie
  kosztują; `limits: 6 of 1024 processes, kernel memory reserve 256 MiB (0 user frame(s) refused), IPC buffers 0 of
  16384 KiB (0 refused), ramfs 1287 of 24576 KiB` – normalna praca nie dotyka żadnego limitu. pass=1.
- USB TEST: końcowe sprawdzenie ramek całego zestawu uwzględnia wzrost heapu (jak stress i nowe testy) – u Dawida (KVM)
  raz „frames leaked (111927 -> 111913)”, choć wszystkie 7 testów USB, każdy z własnym sprawdzeniem, przeszło; heap
  po dużych testach (ramfs, kolejki) bywa pofragmentowany i rośnie na końcu. Linia `[USB TEST] frames after the suite:
  … (heap +N pages)` pokazuje, ile.
- QEMU 28/28.

## v0.35.1 — 2026-10-17

### Bezpieczeństwo, krok 2: bez cykli uchwytów w kanałach
- **Błąd (znany brak, wskazany też przez Pawła i ChatGPT):** proces mógł włożyć koniec kanału A do kolejki kanału B,
  a koniec B do kolejki A, i zamknąć resztę uchwytów. Kanały trzymały się nawzajem – nikt ich już nie odbierze, a
  pamięć jądra nigdy nie wracała. Jeden program mógł tak w pętli zjadać pamięć.
- **Zasada:** koniec kanału, w którego kolejce leży komunikat z innym końcem kanału, nie może sam podróżować w
  komunikacie – `chan_send` zwraca `EBUSY`, uchwyt zostaje u nadawcy. Po odebraniu tego komunikatu koniec znowu może
  podróżować. Cykl jest niemożliwy: ostatnie włożenie, które by go domknęło, zawsze trafia na tę zasadę. Sprawdzenie i
  włożenie razem pod jedną blokadą `chan-xfer` – biorą ją tylko komunikaty z końcami kanałów, zwykłe komunikaty bez
  zmian (wydajność IPC ta sama). Usługi (usbd, łączenie po nazwie przez init) działają jak dotąd.
- **Test:** IPC TEST 3/5 – xfertest 43 sprawdzenia (było 32): cykl z 2 i 3 kanałami odrzucony, zwykłe komunikaty
  przechodzą, po odebraniu koniec znowu podróżuje, łańcuch bez cyklu dozwolony; jądro liczy żywe kanały – po teście
  żaden nie zostaje. Sprawdzone: bez zasady test pada (check 34).
- QEMU 28/28.

## v0.35.0 — 2026-10-17

### Bezpieczeństwo, krok 1: audyt wywołań systemowych + fuzzer
- **Audyt:** przejrzane wszystkie wywołania systemowe pod kątem arytmetyki na liczbach od procesu (długości, adresy,
  liczniki – jak błąd w `mmap` z v0.34.2): kopiowanie z / do procesu (`user_range_ok` z `checked_add`, każda długość
  ograniczona: MAX_IO, 255 B ścieżki, 4 KiB argumentów, MSG_MAX, limity list), `sleep` (do 1 h), `seek`, `wait_many`
  (długi limit = bez limitu), `dup2`, pamięć współdzielona, wywołania usług (`dev_map`, `blk_attach`,
  `input_inject`), parser i loader ELF. **Nowych błędów nie znaleziono** – poprzedni był jedyny w tym rodzaju.
- **Fuzzer `/bin/sysfuzz`** (FILE TEST 5/5):
  - 32 dzieci bez żadnych uchwytów, każde do 3000 losowych wywołań ze skrajnymi argumentami (0, −1, 2^64−1, adresy
    jądra, prawie-przepełnienia, prawdziwy bufor ze złą długością, losowe uchwyty; na start prawdziwe obiekty:
    potok, kanały, pamięć wspólna, plik), 8 naraz na kilku CPU; dziecko, które utknie (sleep, wait_many, recv),
    jest zabijane – to sprawdza też sprzątanie procesu w trakcie wywołania;
  - 300 zepsutych plików ELF (kopie `/bin/hello` z losowo zmienionymi bajtami, głównie w nagłówkach, czasem ucięte)
    – zapis do pliku i `spawn`: proces może uruchomić dowolny plik, więc loader to też wejście od programu;
  - pomijane: `exit`, `spawn` (bomba procesów – krok 3, limity), `kill` (mógłby zabić rodzica albo init);
  - test: jądro nie pada ani się nie zawiesza, ramki wracają, śmieci z losowych ścieżek usuwa jądro.
- Jednorazowy długi przebieg (256 dzieci × 4000 wywołań ≈ 1 mln, 2000 plików ELF): jądro przeżyło, 0 wycieków.
- QEMU 28/28.

## v0.34.3 — 2026-10-16

### Stress mniej mierzy sam siebie
- Zadania `stress-spin` (test poprawności spinlocków: 16 zadań zwiększa wspólny licznik, na końcu suma musi się
  zgadzać) robiły 500 operacji na rundę – na Legionie 68,7 mln czekań, **7,9% CPU w samym kręceniu** na blokadzie
  `stress-counter`. Teraz 50 na rundę: nadal miliony operacji z tłokiem, test gubienia zwiększeń zostaje, ale CPU
  idzie na właściwą pracę (skrypty, procesy, IPC).
- **Legion (v0.34.3):** tryb porównawczy **599 726 skryptów** (v0.34.1: 535 827, +11,9%), pełne obciążenie (max6)
  **593 119** (533 725, +11,1%); idle 5%, ping-pong 4,5 µs, pass=1; `stress-counter` 7,9% → 0,0% CPU; pendrive w tle
  73,7 MB/s w trybie porównawczym (było 26 MB/s). Nadal max6 ≈ porównawczy; najdroższe teraz: `spawn` (wczytanie ELF)
  ~9% CPU, heap 0,6–1,0%. Zegar: nadal 45–51 zgubionych ticków PIT i przerwy do 40 ms – następny krok.
- **Logi w folderze `logs/`:** `logs/test.log` (tests/test.sh), `logs/stress-qemu.log` (tests/stress-qemu.sh),
  `logs/build-usb.log` (make-usb.sh). Stare `test.log`, `stress-qemu.log`, `build-usb.log` w głównym folderze można usunąć.
- **Liczby skryptów od v0.34.3 są wyższe przez samą zmianę testu** – porównywać z v0.34.2 tylko z tym zastrzeżeniem.
- QEMU 28/28.

## v0.34.2 — 2026-10-16

### Poprawki bezpieczeństwa (z przeglądu kodu od Pawła)
- **`mmap` / `munmap` z długością bliską 2^64 wywracały jądro.** Zaokrąglenie do strony (`page_up`) przepełniało
  się przed sprawdzeniem limitu, a jądro jest budowane z kontrolą przepełnień – więc dowolny program jednym
  `mmap(u64::MAX)` robił PANIC całego systemu (sprawdzone: stara wersja pada w MemTest). Teraz najpierw limit,
  potem zaokrąglenie; `munmap` zaokrągla bez przepełnienia → `ENOMEM` / `EINVAL`. FILE TEST 4/4: memtest 25
  sprawdzeń (było 23).
- **Wyścig `chan_send` z zamknięciem odbiorcy.** Nadawca sprawdzał „druga strona zamknięta” przed blokadą kolejki;
  gdy odbiorca zamknął się dokładnie w tej chwili, komunikat (z uchwytami w środku) trafiał do martwej kolejki, a
  `send` zwracał sukces. Teraz drugie sprawdzenie pod blokadą kolejki – nadawca dostaje `EPIPE` i uchwyty wracają.
- **`readkey` bez sprawdzania uprawnień.** Czytał klawiaturę każdemu procesowi. Teraz tylko, gdy uchwyt 0 to
  konsola z prawem READ (jak `read(0)`); inaczej `EBADF`. Przy okazji proces z plikiem / potokiem na wejściu nie
  podbiera już klawiszy shellowi. IPC TEST 1/5: handletest sprawdza to w dziecku z plikiem na uchwycie 0.
- Znany brak bez zmian: cykl uchwytów przez kolejki kilku kanałów zostaje w pamięci (opisany w roadmapie).
- QEMU 28/28.

## v0.34.1 — 2026-10-15

### Wyniki Legiona dla v0.34.0 + drobna poprawka raportu
- **Legion A/B (16 CPU, stress 60 s):**

  | Okno kręcenia | Skrypty | Idle | Ping-pong | Pobudki w kręceniu (bez IPI) | Uśpienia (`hlt`) |
  |---|---|---|---|---|---|
  | dobierane do 200 µs (domyślne) | 535 827 | 7% | 4,35 µs | 831 103 (632 102) | 42 817 |
  | stałe 200 µs | 535 300 | 3% | 4,45 µs | 819 500 (623 851) | 27 504 |
  | stałe 50 µs (jak v0.33.0) | 534 027 | 3% | 4,4 µs | 862 796 (655 029) | 58 382 |
  | stałe 20 µs | 536 961 | 2% | 4,35 µs | 739 641 (546 652) | 83 748 |

  Wszystkie w granicach szumu (~0,5%) – długość okna między 20 a 200 µs nie ma znaczenia. **Zostaje dobierane**:
  tak samo szybkie, a bezczynny system się nie kręci (bateria). Pobudka bez IPI działa: ~75% pobudek bez przerwania,
  ping-pong 5,0 µs (v0.33.0) → 4,35 µs. Średnie okno pod obciążeniem 85 µs.
- **Legion, pełne obciążenie (`DESOOS_STRESS_POOL=6`, 96 procesów): 533 725 skryptów + 266 863 primes** – rekord
  (v0.22.0: 528 869, +0,9%), idle 2%, ping-pong 4,45 µs, pendrive w tle 26 MB/s (764 przejścia identyczne), pass=1.
  Blokada schedulera: 25,0 mln wzięć, 24% czeka, 2,4 s czekania, najdłużej 121 µs. Pełne obciążenie daje już tyle
  samo co tryb porównawczy (535 827) – teraz ogranicza sam stress: licznik `stress-counter` to 7,9% CPU w czekaniu
  na spinlock (68,7 mln czekań), a `spawn` (wczytanie ELF) ~17% czasu.
- Raport `cpus` przy stałym oknie pokazywał „now avg 50 us” (startowa wartość) zamiast ustawionej – poprawione.

## v0.34.0 — 2026-10-15

### Kręcenie przed `hlt`: okno dobierane samo + pobudka bez przerwania
- **Okno kręcenia dobiera się per CPU** (jak `haltpoll` w Linuksie): gdy praca przyszła w ciągu 200 µs od uśpienia
  rdzenia, okno rośnie ×2 (kręcenie by ją złapało); po dłuższej bezczynności maleje /2, aż do 0. Pod obciążeniem
  rdzenie kręcą się do 200 µs, bezczynny system wcale – nie traci prądu na baterii.
- **Pobudka bez IPI:** rdzeń, który się kręci, ma flagę „kręcę się”; budzący tylko ustawia mu „przełącz się”, bez
  przerwania międzyprocesorowego. Kolejność flag (jak algorytm Dekkera) gwarantuje, że pobudka nie przepada, gdy
  rdzeń właśnie kończy kręcenie i idzie spać.
- Ustawienia przy budowaniu: `DESOOS_IDLE_POLL_US` – górna granica okna (domyślnie 200, 0 = bez kręcenia),
  `DESOOS_IDLE_POLL_ADAPT=0` – stałe okno (jak v0.32.2–v0.33.0 z 50 µs). W [RESULT] `idlepoll=a200` (dobierane) albo
  `idlepoll=50` (stałe).
- Raport: `idle: spins before hlt (adaptive up to 200 us, now avg N us): X wake-ups while spinning (Y without IPI),
  Z halts, window A x up / B x down`.
- QEMU 28/28 (1 i 4 CPU).

## v0.33.0 — 2026-10-15

### ✅ P4 zamknięte + porządek w testach
- **P4 (blokada schedulera) – podsumowanie na Legionie:** czekanie na blokadę schedulera 18,9 s → ~4,6 s na minutę,
  najdłuższe czekanie < 100 µs; stress (tryb porównawczy) **432 210 → 534 072 (+23,6%)** – głównie dzięki kręceniu
  przed `hlt` (v0.32.2), które wyszło przy szukaniu spadku po krokach 0–c.
- **Testy w osobnym folderze `tests/`:** `tests/test.sh`, `tests/stress-qemu.sh`, `tests/mkfat32.py`,
  `tests/qemu-hotplug.py` (wcześniej w głównym katalogu). Działają z dowolnego miejsca (`tests/test.sh`,
  `ACCEL=kvm tests/test.sh`, `SMP=8 tests/stress-qemu.sh`); logi jak dotąd w głównym katalogu. Kod samotestów
  w jądrze tylko w buildzie `--selftest` – kernel na pendrive go nie zawiera.
- `build.sh` nie wypisuje już linii o kręceniu przed `hlt`, gdy jest domyślne (50 µs).

## v0.32.2 — 2026-10-15

### Hipoteza: pobudka uśpionego rdzenia – kręcenie przed `hlt`
- **A/B na Legionie (jedno po drugim, ten sam pendrive):** v0.29.0 **434 178**, v0.32.1 **412 946 (−4,9%)** – spadek
  prawdziwy. NIE z blokady: najdłuższe czekanie na blokadę schedulera 65 µs (0 czekań > 100 µs, w przerwaniu
  19 µs), zgubione ticki 70 (v0.29.0: 56), czasy `spawn` / `exit` / `wait` / `reap` takie same lub krótsze.
  Rośnie tylko bezczynność: 26% → 28%.
- **KVM 16 CPU (komputer Dawida):** v0.29.0 342 392, v0.32.1 **346 764 (+1,3%)**, czekanie na blokadę 18,9 → 4,4 s,
  zadania IPC +14% – na maszynie wirtualnej spadku nie ma.
- Hipoteza: na prawdziwym sprzęcie `hlt` usypia rdzeń głębiej (AMD: C1 → CC6) i pobudka trwa dziesiątki µs.
  Po P4 rdzenie mniej kręcą się na blokadzie, częściej śpią, a każde przekazanie zadania uśpionemu rdzeniowi
  wydłuża łańcuch spawn → skrypt → wait.
- **Test:** bezczynny CPU kręci się `DESOOS_IDLE_POLL_US` µs (domyślnie 50) przed `hlt` – pobudka (IPI) trafia w
  działający rdzeń (jak `haltpoll` w Linuksie). `DESOOS_IDLE_POLL_US=0` = jak dotąd. Raport: `idle: spins N us
  before hlt: X wake-ups while spinning, Y halts`; w [RESULT] `idlepoll=N`.
- ✅ **Legion – hipoteza potwierdzona (A/B, ten sam build, tylko zmienna):**

  | | `idlepoll=0` | **`idlepoll=50`** |
  |---|---|---|
  | skrypty (compare) | 412 315 | **534 072 (+29,5%)** |
  | idle | 32% | **7%** |
  | zadania IPC | 6 247 | **8 535 (+37%)** |
  | ping-pong / kanał | 5,6 µs / 662 MB/s | **5,0 µs / 1001 MB/s** |
  | pendrive w trakcie stressu | 48 MB/s | **68 MB/s** |

  Pobudki w trakcie kręcenia: 742 747 (wejść w `hlt`: 53 441). **Rekord Legiona w trybie porównawczym** – o 23%
  więcej niż v0.29.0 (434 178), więcej niż dotychczasowy rekord pełnego obciążenia (max6 528 869). Najdłuższe
  czekanie na blokadę schedulera 83 µs. Wniosek: przed P4 rdzenie „przypadkiem” nie spały, bo kręciły się na
  blokadzie; po P4 zasypiały i każde przekazanie zadania czekało na wybudzenie rdzenia.

## v0.32.1 — 2026-10-15

### Diagnostyka: dlaczego stress spada, choć blokada schedulera przestała hamować
- **Legion v0.32.0 (P4.c):** czekanie na blokadę schedulera **3,7 s** (v0.31.1: 11,1 s; v0.29.0: 18,9 s – **−80%**),
  czeka 32% wzięć (było 41%), blokada trzymana ~10,1 s (15,4 s); `on_cpu`: 430 czekań na 9,1 mln przełączeń (0,5 ms).
  KVM 8 CPU: czekanie 1083 → 333 ms, trzymanie 7,0 → 4,0 s.
- **Ale stress na Legionie spada z każdą wersją P4:** 432 210 → 423 575 → 416 610 → 409 018 (−5%), rośnie idle
  (26 → 32%) i liczba zgubionych przerwań zegara na CPU 0 (44 → 379).
- Nowe linie raportu `cpus`, żeby znaleźć przyczynę:
  - `scheduler lock: longest wait X us (miejsce), N waits over 100 us, longest wait in an interrupt Y us`,
  - `clock: …, longest gap between timer interrupts X us, N gaps over 2 ms` (CPU 0).
- Porównanie A/B z v0.29.0 (kod z `~/Pulpit/DeSoOS-github`) na tym samym pendrivie, jedno po drugim.

## v0.32.0 — 2026-10-14

### P4.c: przełączanie zadań poza blokadą schedulera
- **Blokada schedulera oddawana przed przełączeniem.** Pod nią zostaje tylko wybór następnego zadania, stany i
  kolejki; zapis / odczyt FPU, zmiana przestrzeni adresowej (CR3), stos i samo przełączenie dzieją się już bez niej
  (Legion v0.31.1: przełączanie to 36% czasu trzymania blokady – 5,6 s na minutę, 624 ns na przełączenie).
- **Flaga `on_cpu`** w zadaniu (jak w Linuksie): ustawiana, gdy CPU wybiera zadanie, zdejmowana przez CPU, który z
  niego schodzi – zaraz po przełączeniu, gdy rejestry i FPU są zapisane. CPU, który wybrał zadanie jeszcze
  schodzące z innego CPU (obudzone tuż przed jego przełączeniem), czeka na zdjęcie flagi; sprzątanie (reap) nie
  zwalnia zadania z flagą. Pobudka bez zmian – stan i kolejki dalej pod blokadą, więc uśpienie i pobudka nie
  mogą się minąć.
- Koniec „blokady przenoszonej przez przełączenie” (zwalniało ją następne zadanie, także nowe – w
  `sched_new_task_start`): strażniki wzięte przed przełączeniem po powrocie zadania nic nie zwalniają.
- Raport `cpus`: `scheduler: N task switches outside the lock, M waited for a task still leaving another CPU`.
- Test SMP 7/7: 4 pary zadań na różnych CPU budzą się nawzajem w kółko (pobudka zgubiona = czekanie do terminu
  1 s = FAIL), obok setki krótkich zadań kończy się i jest sprzątanych. Bez czekania na `on_cpu` jądro pada od
  razu (sprawdzone). QEMU 28/28 (1 i 4 CPU).
- Legion v0.31.1 (P4.b): wzięcia blokady schedulera 39,6 → 27,2 mln (−31%), czekanie 14,3 → 11,1 s; stress
  416 610 – bez zysku (zapis tablicy zadań wydłużył `spawn_in` i `reap` pod blokadą schedulera).

## v0.31.1 — 2026-10-14

### Poprawka testu SMP 6/6
- Pod KVM test przerywał się „too little churn: 16 processes”: uznawał proces za żywy, dopóki zadanie było na liście
  (`task_exists`), a zakończone zadania sprząta dopiero `spawn` albo pętla idle – której przy CPU zajętych przez
  czytających nie było. Teraz „żywy” = ma proces, który się nie zakończył (`with_process`). Błąd testu, nie jądra.
- KVM 8 CPU (v0.31.0): wzięcia blokady schedulera 16,2 → **11,5 mln (−29%)**, `with_process` zniknął z listy
  miejsc; tablica zadań: 4,9 mln odczytów + 2,0 mln zapisów, 7 ms czekania. Przełączanie zadań to **43%** czasu
  trzymania blokady schedulera (3,0 s z 7,0 s, 775 ns na przełączenie) – tyle może odzyskać krok c.

## v0.31.0 — 2026-10-14

### P4.b: lista zadań pod własną blokadą
- **Pytania „jaki proces ma numer X” nie stoją już w kolejce do blokady schedulera.** Lista zadań (i kubełki
  numerów) ma własną blokadę RW „task table”: `with_process`, `task_exists`, `children_of`, `for_each_process`
  czytają ją równolegle (Legion v0.30.0: `with_process` 10,8 mln wzięć blokady schedulera na minutę, 3,7 s
  czekania). Zapis: dodanie zadania (spawn), usunięcie (reap) – pod blokadą schedulera i tej; zmiana rodziców
  (`reparent_with`) – tylko ta, do zapisu (wyklucza `with_process` jak dotąd).
- Czytający widzą „zakończone” przez lustro atomowe `dead`; zadanie ma znacznik życia (zwolnione = inny znacznik).
- Czekanie na blokady RW potwierdza teraz TLB shootdown (czytający tablicę czekają z wyłączonymi przerwaniami).
- **Pomiar do kroku c:** nowa linia `scheduler lock: task switches under it X ms of Y ms held (Z%)` – ile czasu
  trzymania blokady schedulera to samo przełączenie zadań. QEMU (TCG, 4 CPU): 51%.
- Test: SMP TEST 6/6 – czytający na kilku CPU pytają o procesy w trakcie uruchamiania, kończenia i zwalniania
  setek procesów; zwolnione zadanie widziane przez czytającego = FAIL. Bez blokady zapisu w reap test wykrywa
  błąd (2 na 2 próby). QEMU 28/28 (1 i 4 CPU).

## v0.30.0 — 2026-10-14

### P4.0: blokada schedulera czeka odczytem
- **Plan P4 (blokada schedulera)** spisany: `roadmapa` i `ARCHITEKTURA.md` („Scheduler – P4”), z porównaniem do
  Linuksa, Redoksa, FreeBSD ULE i BFS/MuQSS.
- **Pierwszy krok, najprostszy:** CPU czekający na blokadę schedulera przy każdym obrocie pętli wykonywał
  `compare_exchange` (instrukcja atomowa) – 15 czekających zabierało sobie nawzajem i trzymającemu linię pamięci
  podręcznej z blokadą, więc trzymający wolniej ją oddawał. Teraz czeka samym odczytem i próbuje przejąć dopiero,
  gdy blokada wygląda na wolną (test-and-test-and-set) – tak czekają już zwykłe spinlocki. To samo w blokadzie
  listy zombie procesu i w blokadzie inicjatora TLB shootdown.
- **Legion:** czekanie na blokadę schedulera **18,9 → 14,3 s (−25%)**; nadal 41% wzięć czeka (wait_event 5,4 → 4,0 s,
  with_process 4,9 → 3,7 s, wake_channel 4,2 → 3,4 s). Stress 423 575 (v0.29.0: 432 210 – rozrzut, bez zysku).
  KVM 8 CPU bez zmian. Wniosek: blokada jest za długo TRZYMANA – następne kroki P4.b i P4.c.
- QEMU 28/28.

## v0.29.1 — 2026-10-14

### ✅ M20 zamknięte – USB na Legionie (v0.29.0)
- Pendrive startowy (SuperSpeed) przed stressem: **121 640 KiB/s** (bufor 256 KiB), **125 365 KiB/s** (bufor 4 KiB,
  jak `cat`); w trakcie stressu **52 140 KiB/s** (v0.28.0: 4 586 KiB/s), 3056 MiB, 1519 przejść identycznych, 0 błędów.
- Klawiatura USB: 37 wciśnięć, przerwanie → znak w jądrze śr. **275 µs** (min 28, maks. 695).
- Enumeracja: kamera 88 ms, pendrive 2 ms, hub USB 2 201 ms, hub USB 3 137 ms, klawiatura 107 ms, mysz 95 ms.
- Stress compare **432 210** (v0.28.0: 436 488, −1% – w tle 3 GiB czytane z pendrive'a), `pass=1`.
- `df`: `/usb0` 2,0 MiB zajęte (= BOOTX64.EFI, 2,0 MiB), `/usb1` 25 651 MiB z 59 117 MiB.
- Pendrive 59 GB w hubie USB 3 zgłosił się jako high speed (`port 1.1` – część USB 2 huba), działa.
- Bez zmian w kodzie (tylko dokumentacja).

## v0.29.0 — 2026-10-14

### M20.h: szybszy odczyt z pendrive'a, `df`, pomiary – zamknięcie M20
- **FAT32 dużo szybciej.** Wcześniej każde `read` czytało od nowa katalogi na ścieżce (na Legionie: 3 × 64 KiB z
  pendrive'a przed każdym odczytem `/usb0/EFI/BOOT/BOOTX64.EFI`), każdy klaster osobnym żądaniem, a `cat` z buforem
  512 B czytał ten sam klaster wiele razy. Teraz: FAT czytany blokami po 4 KiB, cache klastrów (katalogi, końcówki
  plików; zapis przez cache), ciągłe klastry pliku jednym odczytem (do 1 MiB), odczyt z wyprzedzeniem 64 KiB dla
  małych odczytów, zapamiętana pozycja w łańcuchu klastrów.
- **ublk potokiem:** długi odczyt wysyła do 4 żądań naraz – usbd bierze następne zaraz po poprzednim, bez czekania
  na obudzenie jądra. Walidacja odpowiedzi bez zmian (id, liczba bloków, timeout → kwarantanna).
- **QEMU (TCG):** odczyt 4 MiB z pendrive'a w usbtest **716 → 70 620 KiB/s**; w jądrze buforem 256 KiB 74 369 KiB/s,
  buforem 4 KiB (jak `cat`) 36 957 KiB/s (było 5 577 przed odczytem z wyprzedzeniem).
- **`df` na pendrivie:** wolne miejsce liczone z FAT (raz), nie z FSInfo – ten bywa nieaktualny. Obraz testowy ma
  celowo zły FSInfo; test porównuje z prawdziwą liczbą.
- **INQUIRY do 4 prób** (przerwy 200 / 400 / 600 ms) – na Legionie raz `INQUIRY failed` na porcie 5.1; komunikat
  błędu podaje przyczynę („no answer”, „STALL”…), licznik `stor_retries` w statusie usbd.
- **Pomiary:**
  - czas enumeracji urządzenia (reset portu → gotowe): na końcu linii urządzenia „ready in N ms”, w statusie usbd
    `enum_avg_ms` / `enum_max_ms`; QEMU: śr. 23 ms, maks. 49 ms;
  - opóźnienie klawiatury USB: od przerwania xHCI (znacznik w handlerze jądra) do znaku w kolejce wejścia jądra
    (przez usbd); QEMU (`sendkey` z monitora): śr. 535 µs, min 278, maks. 1337;
  - `[RESULT-USB]` w `test.sh`: `enum_avg_ms enum_max_ms kread_kbs kcat_kbs hid_n hid_avg_us hid_max_us`.
- **Autostress (Legion):** przed stressem odczyt największego pliku z /usbN buforem 256 KiB i 4 KiB (dane muszą być
  te same, inaczej `pass=0`) – linia `usb: … read before the stress`; linia `usb keyboard:` (wciśnięcia od startu –
  warto nacisnąć kilka klawiszy w trakcie); osobna linia `[RESULT-USB]`.
- Testy: USB TEST 7/7 sprawdza odczyt DATA.BIN obu buforami co do bajtu ze wzorem, `df` przy złym FSInfo i
  klawiaturę przez `sendkey`. QEMU 28/28 (1 i 4 CPU).

## v0.28.1 — 2026-10-14

### ✅ M20.g na Legionie – odporność USB działa na sprzęcie
- Autostress: compare **436 488** (v0.27.1: 431 338), `pass=1` – bez spadku, choć pendrive startowy był czytany w tle.
- Linia `usb:` – `/usb0/EFI/BOOT/BOOTX64.EFI` czytany w trakcie stressu: **268 MiB, 4586 KiB/s, 134 pełne
  przejścia, wszystkie identyczne, 0 błędów**.
- Pendrive wyjęty w trakcie `cat /usb1/liczby.txt` → `cat: … I/O error`, `usb2 port 1.1: device disconnected`,
  `[USB] sdb: removed, /usb1 unmounted (reads 6318, timeouts 0, protocol errors 0)` – bez zawieszenia.
- Pisanie w trakcie stressu działa.
- Uwaga do M20.h: raz `usb2 port 5.1: 13fe:6700 SuperSpeed … storage setup failed: INQUIRY failed` (ten sam
  pendrive po przełożeniu działał na `port 1.1`; w v0.27.1 działał na 5.1) – dodać ponowienie INQUIRY.
- Bez zmian w kodzie (tylko dokumentacja).

## v0.28.0 — 2026-10-13

### M20.g: odporność USB
- **Zawieszony pendrive nie zatrzymuje systemu.** FAT32 na dysku USB działa teraz pod własną blokadą (`fs::Locked`,
  VFS woła go jak `ConcurrentFs` pod FS_LOCK tylko do odczytu). Wcześniej każdy odczyt z `/usbN` trzymał FS_LOCK do
  zapisu – pendrive czekający do 5 s na usbd zatrzymywał w tym czasie cały VFS (ramfs, `/bin`, uruchamianie
  programów). `mount`, `open`, `df` też nie czekają na dysk (opis i „tylko do odczytu” zapamiętane przy montowaniu).
- **Pendrive wyjęty z huba w trakcie odczytu:** usbd przerywa czekanie na transfer bulk, gdy hub zgłosi zmianę na
  tym porcie (było: 4 s timeoutu transferu + reset recovery na nieistniejącym urządzeniu → jądro dostawało timeout
  po 5 s, odmontowanie po ~7 s). Teraz czytający dostaje błąd w ~12 ms, dysk odmontowany w ~140 ms. Jeśli urządzenie
  jednak zostało – reset recovery przed następną komendą.
- **Restart i awarie usbd:** init pisze „init: usb0: USB keyboard and disks back in a moment” po restarcie usbd, a po
  5 awariach w 30 s: „init: USB controller usb0 disabled after 5 failures - its USB keyboard and disks are
  unavailable until reboot (PS/2 still works)”.
- **usbd w autostressie:** jeśli jest zamontowany pendrive (/usbN – na Legionie startowy), zadanie `usb-stress`
  czyta w kółko jego największy plik w trakcie stressu; każde pełne przejście liczy sumę kontrolną – wszystkie muszą
  być równe. Linia `usb: … MiB, … KiB/s, N full passes (all identical), 0 errors`, w [RESULT] `usb_mib`, `usb_kbs`,
  `usb_err`, `usb_bad` (błąd albo różnica = `pass=0`). `stress-qemu.sh` podłącza testowy pendrive.
- **Testy (28 zestawów, USB TEST 1–7/7):** nowy 6/7 – (a) FAT32 na „zawieszonym” dysku testowym: odczyt `/bin/sh` i
  `ls /bin` w tym czasie bez czekania (0 ms; z dawną blokadą – do zwolnienia dysku), (b) `init test /bin/usbtest
  robust`: kill usbd w trakcie czytania pliku z `/usb0` – czytający dostaje EIO po kilku ms, init restartuje usbd,
  dysk i klawiatura wracają w ~0,5 s, pliki dalej identyczne z `/bin`, (c) 4 kolejne kille → 5 awarii w 30 s →
  `broken` + komunikat, kontroler oddany (bus mastering off), nic nie wycieka; 7/7 – wyjęcie dysku za hubem w trakcie
  odczytu (zadanie jądra czyta `DATA.BIN`): błąd w ~12 ms.

## v0.27.1 — 2026-10-13

### ✅ M20.d na Legionie – huby, TT i podłączanie w locie działają
- Huby Genesys: `usb2 port 1` 05e3:0610 „USB2.1 Hub” → `hub ready (2 ports, USB 2)`, `usb2 port 5` 05e3:0620
  „USB3.2 Hub” → `hub ready (2 ports, USB 3)` (Set Hub Depth, SuperSpeed za hubem).
- **Mysz Logitech G502 (full speed) za hubem high speed** (`port 1.2`) – `mouse ready`: translator transakcji (TT)
  działa na prawdziwym sprzęcie (w QEMU nie dało się tego sprawdzić).
- **Pendrive „Wilk USB DISK 3.0” 59 GB (SuperSpeed) za hubem USB 3** (`port 5.1`) → sdb → `/usb1` (FAT32 'USB DISK',
  klaster 64 KiB); wyjęty w trakcie pracy → `device disconnected`, `/usb1 unmounted`; włożony → sdc → `/usb1`.
- Stress bez spadku: compare **431 338** (v0.26.2: 434 164), `pass=1`, ping-pong 6,9 µs.
- Jeden błąd: `usb2 port 1.1` przy starcie – `Address Device failed` 3 razy, port zignorowany (po wyjęciu urządzenia
  port wrócił do normy). Wyjaśnienie (Dawid): w tym gnieździe był kabel do ładowania telefonu bez telefonu – kabel
  z elektroniką (dioda / układ) wygląda dla huba jak podłączone urządzenie, które nie odpowiada. Zachowanie
  poprawne (Linux: „unable to enumerate USB device”); po wyjęciu kabla w to samo gniazdo wszedł pendrive 59 GB
  (port 5.1 = strona USB 3 tego samego gniazda, 1.1 – strona USB 2).

### Diagnostyka i poprawka testu
- usbd: „Address Device failed” z kodem zakończenia xHCI (np. `USB transaction error`, `split transaction error`,
  `parameter error`), a komunikat o nieudanej enumeracji portu huba podaje prędkość urządzenia.
- ALLOC TEST 4/5: ten sam fałszywy alarm „więcej wolnych ramek na końcu” (u mnie raz: 110629 -> 110727) – punkt
  odniesienia po ustaleniu się licznika, koniec `>=`.

## v0.27.0 — 2026-10-13

### M20.d: huby USB (urządzenia za hubem, podłączanie w locie)
- **usbd – huby USB 2 i USB 3** (także hub za hubem, do 5 poziomów): endpoint przerwań z mapą zmian portów,
  Set Configuration, Set Hub Depth (USB 3), deskryptor huba (liczba portów, TT think time, czas włączenia zasilania),
  drugi Configure Endpoint z polami huba w kontekście slotu, zasilanie portów.
- **Porty huba** w tej samej maszynie stanów co porty kontrolera: debounce 100 ms, reset portu huba (≤ 500 ms),
  3 próby, potem ignorowany do odłączenia; stan przez GET_STATUS, zmiany kasowane CLEAR_FEATURE. Zmiany zgłasza hub
  (mapa bitów na endpoincie przerwań) – sprawdzane tylko zgłoszone porty.
- **Urządzenie za hubem:** route string (port huba na każdym poziomie), port kontrolera najwyższego huba, prędkość z
  portu huba, **TT** (slot i port najbliższego huba high speed) dla klawiatur / myszy low i full speed za hubem USB 2.
  Kontekst slotu w jednym miejscu (`slot_ctx`) – Address Device i wszystkie Configure Endpoint (HID, dysk, hub).
- **Odłączenie huba = odłączenie wszystkiego za nim** (dyski znikają w jądrze, klawisze puszczone).
- `lsusb`: `usb0 port 11.2: … mass storage …` (port kontrolera . port huba), `hub ready (8 ports, USB 2)`;
  status usbd: hubs, hub_events, hub_errors.
- `init test /bin/x arg` – program testowy dostaje jeden argument.
- **Testy (28 zestawów, USB TEST 1–6/6):** w QEMU hub w porcie 3, za nim mysz (3.1) i testowy pendrive (3.2);
  2/6 i 5/6 – 5 urządzeń, hub i urządzenia za nim działają (pendrive za hubem montowany, pliki = /bin); **nowy 6/6 –
  podłączanie w locie**: `qemu-hotplug.py` czyta z logu linie „[HOTPLUG] …” wypisane przez samotest i wysyła je do
  monitora QEMU – dysk za hubem wyjęty (odmontowany w ~200 ms), włożony (zamontowany w ~280 ms), cały hub wyjęty
  (hub, mysz i dysk znikają), usbtest widzi 5 → 4 → 5 → 2 urządzenia bez błędów, nic nie wycieka.
- `HUB=1 ./run-qemu.sh` – hub w porcie 3, z `USB=1` klawiatura i mysz za hubem (pisanie przez hub działa), `usb.img`
  w porcie 3.3. QEMU: `qemu-xhci,id=xhci` + stałe porty urządzeń; testowy pendrive jako `-blockdev`.
- Uwaga: hub QEMU jest full speed – TT (hub high speed + klawiatura full speed) sprawdzi dopiero Legion.

## v0.26.2 — 2026-10-13

### ✅ M20.f na Legionie – pendrive startowy czytany przez DeSoOS
- `lsusb`: pendrive „Wilk” 13fe:5500 (SuperSpeed, usb1 port 6) → `disk sda ready (7560 MiB, 512-byte blocks,
  read-only)`; jądro: GPT → partycja @2048 → FAT32 'NOSNIK USB' (klaster 4 KiB) zamontowany w `/usb0`.
- `ls /usb0` → `EFI/`, `df` → `/usb0 7544 MiB`, `echo x > /usb0/a.txt` → „read-only file system”.
- Stress bez spadku: compare **434 164** (v0.25.1: 431 023), `pass=1`, ping-pong 6,6 µs. Klawiatura ITE dalej działa.

### Porządki po M20.f
- Ostrzeżenie kompilatora w zwykłym buildzie (`methods probed and mounts are never used`, `ublk.rs`) – obie metody
  używa tylko samotest; oznaczone `cfg_attr(not(selftest), allow(dead_code))`. Oba buildy bez ostrzeżeń.
- Monitor `usb-disks` nie czyta partycji dysku, który już zniknął (usbd zabity tuż po rejestracji) – bez mylącego
  `[BLK] sdX: GPT: no such disk` w logu.
- Wyniki v0.26.1 (Dawid): QEMU TCG 28/28 (odczyt z pendrive'a 1170 KiB/s), KVM 28/28 (828 KiB/s), stress KVM 8 CPU
  **176 450** (v0.25.1: 179 713 – w granicach szumu), `pass=1`.

## v0.26.1 — 2026-10-13

### Poprawka testu: fałszywy „frames leaked” w IPC TEST
- Objaw (Dawid, v0.26.0): `[IPC TEST] FAIL: frames leaked (111523 -> 111933)` – na końcu zestawu **więcej** wolnych
  ramek niż na starcie (u mnie raz na kilka przebiegów: 111559 -> 111725). To nie wyciek: punkt odniesienia złapany,
  zanim skończyło się sprzątanie po poprzednim zestawie (FILE TEST – procesy zabite przez #PF), resztki zwolniły się
  w trakcie IPC TEST. Ten sam rodzaj fałszywego alarmu był już raz poprawiany (M19.c).
- Poprawka: `settled_free_frames` czeka na 10 zgodnych próbek (50 ms) zamiast 3 (15 ms), a sprawdzenia wycieków w
  IPC, SVC i USB (koniec zestawu i po każdym kroku) wymagają „wolnych ramek nie mniej niż na starcie” – prawdziwy
  wyciek (mniej wolnych) dalej jest wykrywany. (Po pierwszej zmianie ten sam objaw raz w USB TEST 5/5:
  110749 -> 110964.) QEMU: 28/28 w 4 kolejnych przebiegach.

## v0.26.0 — 2026-10-13

### M20.f: pendrive USB tylko do odczytu (przed krokiem d – pendrive Legiona też nie wisi za hubem)
- **usbd – pamięć masowa:** interfejs 08/06/50 (SCSI, Bulk-Only) z endpointami bulk IN / OUT: Configure Endpoint,
  Set Configuration, INQUIRY (tylko dysk – nie CD-ROM), TEST UNIT READY (do 10 prób, REQUEST SENSE kasuje UNIT
  ATTENTION), READ CAPACITY(10). Transfery bulk: TRB dzielone na granicach 64 KiB (wymóg xHCI) i łączone w
  łańcuch; STALL → Reset Endpoint + Set TR Dequeue + Clear Feature(HALT); timeout (4 s) / zły CSW → Bulk-Only
  Reset (reset recovery). Odłączenie w trakcie transferu wykrywane od razu (port), nie po timeoucie.
- **Zapisu nie ma:** jedyne komendy SCSI to `SCSI_ALLOWED` (TEST UNIT READY, REQUEST SENSE, INQUIRY, READ
  CAPACITY(10), READ(10)) – sprawdzane przed każdą komendą, a asercja przy kompilacji pilnuje, że na liście nie ma
  żadnej komendy zapisu (WRITE 6/10/12/16, FORMAT, MODE SELECT, SYNCHRONIZE CACHE, UNMAP…).
- **Jądro – uchwyt `BLK` i syscall 50 `blk_attach`** (projekt M20.a): rodzaj uchwytu 11, tworzy go tylko jądro
  dla init (slot 6), init daje kopię każdemu usbd. usbd tworzy kanał i bufor DMA (256 KiB = 4 sloty po 64 KiB) i
  rejestruje pendrive; jądro bierze własne referencje. Błędy: EBADF, EACCES (BLK bez WRITE, kanał bez TRANSFER),
  EINVAL (blok ≠ 512 / 4096, 0 bloków, sloty spoza 1..8, za mały bufor), ENOSPC (8 dysków).
- **`ublk` (`kernel/user/ublk.rs`) – dysk „sda”, „sdb”…, zawsze tylko do odczytu:** odczyt = żądanie kanałem
  (id, lba, bloki, slot), pendrive pisze DMA prosto do slotu, jądro kopiuje dopiero po poprawnej odpowiedzi.
  Odpowiedź z cudzym id / złą liczbą bloków – odrzucona (licznik). Timeout 5 s → EIO i slot w **kwarantannie**
  (urządzenie może jeszcze pisać) – wraca po spóźnionej odpowiedzi. 3 timeouty pod rząd, koniec usbd albo wyjęty
  pendrive = **dysk znika**.
- **Zadanie jądra `usb-disks`:** nowy dysk → partycje GPT (albo MBR / cały dysk) → FAT32 montowany w `/usb0`,
  `/usb1`… (tylko odczyt); dysk zniknął → odmontowanie, usunięcie partycji i dysku, bufor i kanał zwolnione.
- **Blokada per dysk w warstwie block** (było: jedna globalna „block layer”) – czekanie na pendrive (do 5 s) nie
  zatrzymuje NVMe ani virtio. Lista dysków pod krótką blokadą, usunięty dysk zwalnia numer.
- `ChanEnd::recv_timeout` (jądro czeka na odpowiedź z terminem); FAT32 na dysku tylko do odczytu odrzuca zmiany
  od razu (zanim cokolwiek trafi do buforów); `open` do zapisu na takim systemie plików → EROFS.
- Tylko odczyt – **cztery niezależne zamki**: brak komend zapisu w usbd, brak operacji zapisu w protokole, dysk
  `read_only` (warstwa block i `ublk` odrzucają zapis), FAT32 / `open` → EROFS.
- `lsusb`: „disk sda ready (… MiB, 512-byte blocks, read-only, "producent produkt")”; `usbd status`: storage,
  disks, stor_reads, stor_bytes, stor_errors. `disk`, `mount`, `df`, `ls`, `cat` działają na `/usb0`.
- Testy (28 zestawów, USB TEST 1–5/5): 2/5 – dwa pendrive'y w QEMU (startowy vvfat + nowy obraz FAT32), testowy
  zamontowany przez jądro, kill usbd → dysk znika i wraca z nową instancją, bufory DMA wracają; 3/5 – nowy
  `/bin/blktest` udaje usbd i psuje protokół (błędy blk_attach, odczyt 1 i 2 żądaniami, cudze id, zła liczba
  bloków, timeout + kwarantanna, **odczyt virtio w tym czasie 8 ms – blokada per dysk**, spóźniona odpowiedź, EIO,
  zapis odrzucony, 3 timeouty → dysk usunięty, nic nie wycieka); 5/5 – przez prawdziwy init: pliki z `/usb0`
  identyczne z `/bin`, 4 MiB wzoru sprawdzone, zapis / `rm` / `mkdir` → EROFS. `[RESULT-USB]`: `mount_ms`,
  `read_kbs` (QEMU TCG: ~685 KiB/s – FAT32 czyta klaster po klastrze, obraz ma klaster 512 B).
- `mkfat32.py` – obraz testowego pendrive'a (MBR + FAT32) bez mtools i sudo (`test.sh`); `run-qemu.sh`
  podłącza `usb.img` (jeśli jest) jako drugi pendrive tylko do odczytu. QEMU: `qemu-xhci,p2=8,p3=8` (więcej
  portów – bez automatycznego huba).

## v0.25.1 — 2026-10-12

### ✅ M20.e na Legionie – wbudowana klawiatura działa
- **Pierwszy raz w historii DeSoOS pisanie na Legionie**: `lsusb` pokazuje „keyboard ready (input to kernel)” dla
  klawiatury ITE 048d:c100 (usb2 port 4), w shellu działają `help`, `lsusb`, `echo`, Caps Lock i polskie znaki
  (AltGr: ąęśż…).
- Stress bez spadku: compare **431 023** (v0.24.0: 434 021, v0.23.0: 436 765 – w granicach szumu), `pass=1`,
  ping-pong 6,7 µs.
- QEMU: samotesty 28/28 (TCG i KVM), stress KVM 8 CPU 179 713, `USB=1` autostress z pisaniem – PASS.

### Poprawka: PANIC lockdep przy pisaniu na klawiaturze USB w trakcie stressu
- Objaw (Dawid, `USB=1 ./run-qemu.sh`, pisanie w trakcie autostressu): `PANIC: spinlock order: 'waiters' (level 45)
  taken at kernel/user/waitset.rs:68 while holding 'stress-counter' (level 210)`.
- Przyczyna: przerwanie MSI kontrolera USB (raport klawiatury) budzi usbd czekającego w `wait_many` – handler bierze
  `waiters` (IrqSpinLock). Przerwany kod na tym CPU trzymał `stress-counter` (zwykły SpinLock, przerwania włączone).
  Lockdep sprawdzał kolejność względem **wszystkich** blokad CPU, także przerwanego kontekstu – fałszywy alarm: przerwany
  kod nie może czekać na handler, a `waiters` nigdy nie jest trzymane z włączonymi przerwaniami. Błąd siedział od M19
  (przerwania usług), ujawnił się, bo pierwszy raz urządzenie usługi przerywa w trakcie stressu.
- Poprawka (`sched/spin.rs`): blokada wzięta w handlerze przerwania jest oznaczona (bit 0 adresu w tablicy trzymanych);
  **w przerwaniu kolejność sprawdzana tylko względem blokad wziętych w przerwaniu**, rekurencja (ta sama blokada) –
  zawsze. LOCK TEST 2/6 sprawdza oba przypadki (przerwanie: blokada przerwanego kodu nie jest złamaniem; zadanie:
  złamanie nadal wykryte).
- Przy okazji: autorepeat USB i puszczenie klawiszy zabitego źródła przeniesione z ticku zegara (kontekst przerwania)
  do zadania jądra `input-repeat` (pod BKL; budzone przy wciśnięciu, generacja zapobiega przespaniu terminu) – mniej
  pracy w przerwaniu. Tick zegara wrócił do stanu sprzed v0.25.0.
- Test: autostress 20 s na 4 CPU (TCG, bez 8042) z ciągłym pisaniem przez `sendkey` – PASS, bez PANIC; samotesty 28/28
  przy 1, 2 i 4 CPU.
- Ta sama sytuacja mogła wystąpić przy przerwaniach PS/2 (IRQ1 / IRQ12) w trakcie stressu – poprawka lockdep obejmuje
  wszystkie przerwania.

## v0.25.0 — 2026-10-12

### M20.e: klawiatura i mysz USB (przed krokiem d – klawiatura Legiona nie wisi za hubem)
- **Jądro – uchwyt `INPUT` i syscall 49 `input_inject`** (projekt M20.a): rodzaj uchwytu 10, tworzy go tylko jądro
  dla init (slot 5), init daje kopię każdemu `usbN` (nie shellowi). Prawa WRITE + DUP, bez TRANSFER. **Każda kopia
  uchwytu to osobne źródło** z mapą wciśniętych klawiszy – gdy znika (koniec / kill usbd), jądro puszcza jej klawisze
  (w ticku zegara pod BKL; w Drop tylko atomiki), więc po awarii nie wisi Shift ani Ctrl.
- `input_inject(h, zdarzenia, n ≤ 64)`: zdarzenie 8 B – klawisz (HID usage, wciśnięty) albo mysz (przyciski,
  kółko); najpierw walidacja całości (zły rodzaj → EINVAL, nic nie przechodzi), EBADF / EACCES jak przy innych
  uchwytach. Wynik: stan diod (Num / Caps / Scroll) – usbd ustawia je w klawiaturze.
- Jądro: tablica HID usage → `KeyCode` (litery, cyfry, F1–F12, nawigacja, klawiatura numeryczna, modyfikatory) – dalej
  bez zmian: polski układ programisty, AltGr, Caps Lock, Ctrl+C, konsola, `readkey`. **Autorepeat w jądrze** dla źródeł
  USB (klawiatura USB sama nie powtarza): 500 ms, potem co 33 ms (~30/s), jeden klawisz naraz, modyfikatory i blokady
  bez powtarzania. Mysz USB: kółko przewija konsolę (jak PS/2).
- usbd: dla interfejsu boot keyboard (03/01/01) i boot mouse (03/01/02) – Configure Endpoint (endpoint przerwań IN,
  interwał wg prędkości), Set Configuration, Set Protocol (boot), Set Idle, 8 TRB czeka na raporty. Raport klawiatury
  (modyfikatory + 6 klawiszy) → różnica z poprzednim → zdarzenia (ErrorRollOver pomijany). Zdarzenia endpointów HID
  obsługiwane od razu, także w trakcie innego transferu; błąd endpointu → reset endpointu i nowe TRB. Diody: Set Report.
  Odłączenie klawiatury → puszczenie jej klawiszy. `lsusb`: „keyboard ready (input to kernel)”. Nowa prośba
  `idle MS` (test). **Pamięć masowa nadal bez żadnej konfiguracji** (krok f).
- `USB=1 ./run-qemu.sh` – QEMU bez kontrolera 8042 (jak Legion), klawiatura i mysz tylko na USB.
- Testy (28 zestawów): USB TEST 2/4 – klawiatura i mysz QEMU skonfigurowane, raporty przez endpointy przerwań (Set Idle
  16 ms: 50 raportów w 400 ms); **3/4 – nowy `/bin/inputtest`** (16 sprawdzeń): prawa i błędy, „hiA” w kolejce jądra,
  autorepeat (8 × „b” po 700 ms), dioda Caps Lock, dziecko z kopią uchwytu zabite z wciśniętym Shiftem i „q” – Shift
  puszczony, „q” się nie powtarza (test mutacyjny: bez puszczania – „QQQQQQQQQQQ”, wykryte); 4/4 – init daje usbd
  uchwyt INPUT.
- QEMU u mnie: 28/28 przy 1, 2 i 4 CPU. Ręcznie przez monitor QEMU (`sendkey`, bez 8042): `echo Usb`, AltGr+s → „ś”,
  Caps Lock, trzymanie „z” 1,2 s → 23 znaki (autorepeat).

## v0.24.0 — 2026-10-12

### ✅ M20.c na Legionie – wszystkie urządzenia rozpoznane
- KVM 8 CPU: 28/28, stress 170 404 (w szumie: 174–178 tys.), start usbd z enumeracją ~150 ms.
- **Legion: 7 urządzeń, 0 błędów enumeracji** (usb0 NVIDIA – pusty):
  - `usb2 port 4: 048d:c100 full speed, USB 2.01, keyboard, interfaces 03/01/01, "ITE Tech. Inc." "ITE Device(8910)"` –
    **wbudowana klawiatura, bezpośrednio na porcie kontrolera** (bez huba), interfejs boot keyboard,
  - `usb2 port 3: 8087:0029` Intel Bluetooth (full speed), `usb1 port 3: 13d3:56ff` kamera Azurewave „Integrated Camera”
    (high speed, IAD ef/02/01, interfejsy 0e/01 + 0e/02 – ustawienia alternatywne przyjęte bez błędu),
  - `usb1 port 6: 13fe:5500` pendrive „Wilk” (SuperSpeed, mass storage 08/06/50),
  - `usb2 port 1: 05e3:0610` i `port 5: 05e3:0620` – hub Genesys Logic (część USB 2.1 high speed + część USB 3.2
    SuperSpeed tego samego huba); urządzenia za nim – krok d.
- Prędkości po resecie portu prawdziwe (kamera i hub high speed, wcześniej przed resetem „full speed”).
- Stress bez spadku: compare **434 021** (v0.23.0: 436 765, v0.22.0: 436 134), `pass=1`, ping-pong 6,75 µs.
- Wniosek: klawiatura nie wymaga hubów – **kolejność zmieniona: najpierw M20.e (klawiatura i mysz HID), potem d**.

### M20.c: rozpoznawanie urządzeń USB (enumeracja) + `lsusb`
- usbd: **maszyna stanów portu** z projektu M20.a – podłączenie → debounce 100 ms → reset portu (USB 2, ≤ 500 ms; port
  USB 3 z już wytrenowanym łączem bez resetu) → Enable Slot → Address Device → deskryptor urządzenia (8 B: rozmiar
  pakietu EP0, w razie potrzeby Evaluate Context; potem 18 B) → konfiguracja (9 B, potem całość ≤ 4 KiB) → napisy
  (producent, produkt) → „Działa”. Każda komenda i transfer z timeoutem 1 s. Błąd → Disable Slot, ponowienie za 500 ms,
  po 3 próbach port ignorowany do odłączenia. Odłączenie w dowolnym stanie → Disable Slot, strony DMA wracają do puli.
  STALL → Reset Endpoint + Set TR Dequeue (np. urządzenie bez napisu).
- **Do urządzeń idą tylko prośby o odczyt deskryptorów** – bez Set Configuration i endpointów (krok e/f); na pendrive
  nic nie jest wysyłane poza GET_DESCRIPTOR.
- Nowy parser `user/lib/usb_desc.rs` (czysty kod: bez MMIO, alokacji i paniki): deskryptor urządzenia, konfiguracja
  z interfejsami, endpointami i HID, napisy UTF-16 → ASCII. Limity: konfiguracja ≤ 4 KiB, 8 zapamiętanych interfejsów
  (ustawienie 0; ponad – pomijane, nie błąd), ≤ 64 deskryptory interfejsu z ustawieniami alternatywnymi (kamery),
  16 endpointów na interfejs; bLength < 2 (pętla bez końca), wyjście poza wTotalLength, więcej endpointów niż
  zadeklarowano, bulk / przerwania z rozmiarem 0, endpoint przed interfejsem → błąd.
- Nowy `/bin/usbparse` (USB TEST 1/3): poprawne próbki (klawiatura HID, pamięć masowa, kamera z 20 ustawieniami
  alternatywnymi, 9 interfejsów), 21 złośliwych przypadków z oczekiwanym błędem, **10 000 mutacji** z ustalonym ziarnem
  (4 497 przyjętych w limitach, 5 503 odrzuconych, zero paniki). Test mutacyjny: usunięcie sprawdzenia „poza
  wTotalLength” – wykryte.
- Nowa komenda **`lsusb`**: pyta każdą usługę `usbN` („list”), linia na urządzenie – port, VID:PID, prędkość, wersja USB,
  adres, rodzaj (klawiatura, mysz, pamięć masowa, hub, Bluetooth, kamera…), klasy interfejsów, producent i produkt.
  Porty z błędem też widać (powód, która próba).
- `test.sh`: QEMU dostaje `usb-kbd` i `usb-mouse` obok pendrive'a. USB TEST 2/3 (29 sprawdzeń): 3 urządzenia (08/06/50,
  03/01/01, 03/01/02) z nazwami „QEMU USB …”, kill w trakcie serii komend i **w trakcie enumeracji** → nowa instancja
  znów rozpoznaje wszystko; 3/3: `lsusb` przez init. Po każdym: przejęcie, bus mastering, wektory i ramki – czyste.
- QEMU TCG u mnie: 28/28 przy 1, 2 i 4 CPU; start usbd z enumeracją ~155 ms. Normalny start z hubem: hub QEMU
  (0409:55aa) rozpoznany jako „hub” – urządzenia za nim to krok d.

## v0.23.0 — 2026-10-12

### ✅ M20.b na prawdziwym sprzęcie (KVM + Legion)
- KVM 8 CPU: 28/28, stress 177 971 (v0.22.0: 174 257 – szum), No-Op 58–70 µs (każda komenda czeka na przerwanie,
  a budzenie uśpionego wirtualnego CPU przez hosta kosztuje – jak 32 µs dla `edu` w M19), `polled=0`.
- **Legion: 3 kontrolery xHCI znalezione po klasie i uruchomione** – `usb0` = 01:00.2 NVIDIA 10de:1aec (USB-C
  karty graficznej; 6 portów, scratchpad 3, BIOS: not owned, No-Op 230 µs, nic nie podłączone), `usb1` = 05:00.3
  i `usb2` = 05:00.4 AMD 1022:1639 (po 6 portów: USB 2 1–4, USB 3 5–6; scratchpad 2; **BIOS: handed over**; No-Op
  5,0 µs). Podłączone: `usb1` port 3, `usb2` porty 1, 3, 4 – wśród nich wbudowana klawiatura ITE (rozpozna je M20.c).
  Prędkość „full speed” na portach USB 2 przed resetem portu to nie ostateczna wartość – urządzenie high speed
  ujawnia się dopiero w resecie (chirp), więc prawdziwe prędkości pokaże enumeracja.
- Stress na Legionie bez spadku: compare **436 765** (v0.22.0: 436 134), `pass=1`, ping-pong 6,75 µs; trzy usbd
  w tle nic nie kosztują.
- Do sprawdzenia przy okazji: No-Op 230 µs na kontrolerze NVIDIA (przerwania dochodzą – przy odpytywaniu byłoby
  ~10 ms; podejrzenie: wybudzanie łącza PCIe z oszczędzania energii).

### M20.b: start kontrolera USB (xHCI) w usłudze `usbd`
- Pierwszy krok M20 (USB w user space, projekt: `ARCHITEKTURA.md`, „USB (M20 – projekt 20.a)”). Jeszcze bez
  urządzeń USB – kontroler startuje, przyjmuje komendy i widzi porty; enumeracja to M20.c.
- Jądro: syscall **48 `dev_find(hw_root, klasa, nr)`** – adres `nr`-tego urządzenia PCI o klasie (24 bity), tylko
  z `HW_ROOT` (`EBADF`), `EINVAL` dla klasy > 24 bity, `ENOENT` za ostatnim. Niczego nie przejmuje – o dostępie
  decyduje `dev_claim`. Profil: 51 numerów (49 `input_inject`, 50 `blk_attach` zarezerwowane z projektu).
- Init: kontrolery xHCI szuka po klasie 0C0330 i dla każdego dodaje usługę `usb0`, `usb1`, … (`/bin/usbd`,
  restart z odstępem jak każda usługa z M19). Log: `init: usb0 = xHCI USB controller 00:03.0`.
- Nowy `/bin/usbd` (jeden na kontroler): rejestry z BAR0; **przejęcie od BIOS-u** (USB Legacy Support: OS Owned,
  ≤ 1 s, potem siłą jak w Linuksie; wyłączenie SMI); zatrzymanie i reset (HCRST, każdy krok z timeoutem 1 s);
  DCBAA, bufory scratchpad, pierścień komend (Link + Toggle Cycle), pierścień zdarzeń (interrupter 0), MSI przez
  `irq_bind`, Run; zasilanie portów (PPC); komendy **No-Op** z czekaniem na przerwanie (i licznikiem `polled`,
  gdyby przerwania nie dochodziły – diagnostyka na Legiona); zdarzenia zmiany portów (kasowanie bitów RW1C bez
  ruszania PED). Na konsolę: model, wersja, sloty, porty USB 2 / USB 3, stan BIOS-u, podłączone urządzenia
  z prędkością, czas No-Op. Klienci przez `svc` („usb0”): `status`, `noop N`. Błąd kontrolera (HSE / HCE) →
  koniec z kodem 3 → init restartuje, nowa instancja robi pełny reset.
- DMA bez IOMMU zapisane w komentarzu usbd i w `ARCHITEKTURA.md` – izolacja procesu chroni przed crashem, nie
  przed błędnym DMA.
- Nowy zestaw **USB TEST** (28 zestawów): 1/2 `/bin/usbtest` (19 sprawdzeń: `dev_find`, start, No-Op, porty – pendrive
  startowy QEMU widoczny, `noop 2000`, zła prośba, **kill w trakcie serii komend → pełny reset nowej instancji**,
  samodzielny koniec, kontroler wolny); 2/2 `init test /bin/usbtest` – init sam znajduje kontroler i uruchamia
  `usb0`, status przez `svc`. Po każdym: przejęcie wolne, bus mastering wyłączony, wektory MSI i ramki DMA wróciły.
  Linia `[RESULT-USB]` w `test.sh` (start, No-Op, restart po kill).
- QEMU TCG u mnie: 28/28 przy 1 i 4 CPU; start usbd ~115 ms (w tym 100 ms na zgłoszenia portów), No-Op 6–20 µs,
  `polled=0` (przerwania działają), restart po kill ~110 ms. Normalny start: `usb0: port 1: device connected,
  SuperSpeed (5 Gb/s), enabled` (pendrive startowy).

## v0.22.0 — 2026-10-12

### ✅ P3 zamknięte (KVM + Legion)
- KVM 8 CPU: 27/27, stress 174 257 (w szumie; compare na KVM ogranicza pula), czekania na „frames” 8,2 mln → 4 351,
  spawn 34,1 → 23,4 µs, reap 26,0 → 15,1 µs.
- Legion 16 CPU: compare **436 134** (v0.21.0: 412 608, +5,7%), max6 **528 869** (473 223, +11,8%), `pass=1`,
  ping-pong 6,75 / 6,5 µs. „frames”: 48 / 60 mln czekań → 17 / 26 tys., CPU 4 / 6% → 0%. spawn 48,3 → 24,5 µs
  (compare), 54,3 → 27,3 µs (max6).
- Cały etap P od M18 (v0.18.4: 392 943 / 448 079): **+11% compare, +18% max6**.
- Teraz największe: blokada schedulera (37–41% wzięć czeka, 15–19 s czekania na 960 s CPU ≈ 1,6–1,9%), heap
  w max6 znów 1,1 mln czekań (1,0% CPU).

### P3: zapasy ramek fizycznych per CPU
- Powód (Legion v0.21.0): blokada alokatora ramek „frames” – 48 / 60 mln czekań w minucie (compare / max6),
  4 / 6% CPU; każdy proces bierze dziesiątki ramek (obraz, stos, tablice stron), wszystkie spod jednej blokady.
- Każdy CPU trzyma do 64 wolnych ramek; `alloc_frame` / `free_frame` to zdjęcie / dołożenie przy wyłączonych
  przerwaniach, bez blokady. Pusto – paczka 32 ramek spod blokady, pełno – 32 wracają do bitmapy.
  `free_frame_count` liczy ramki w zapasach jako wolne (testy wycieku bez zmian).
- Druga bitmapa „wydana” (atomowa, ten sam obszar co bitmapa wolnych, 2× większy): każda ścieżka wydania ustawia
  bit, `free_frame` najpierw go zdejmuje (`fetch_and`) – bez blokady odrzuca double-free (także ramki leżącej już
  w zapasie CPU), ramki zarezerwowane i adresy spoza RAM-u.
- Ciągłe przedziały (`alloc_frames*`, `alloc_frame_below`, DMA) – spod blokady jak dotąd.
- Nowy test ALLOC TEST 4/5: odmowy (0, niewyrównany, poza RAM-em, zarezerwowany, double-free z zapasu), k zadań
  po 400 ramek ze znacznikami (żadna ramka u dwóch właścicieli), połowa oddana na innym CPU, licznik wolnych
  ramek wraca dokładnie. Testy mutacyjne: przyjęcie double-free i wydanie tej samej ramki dwa razy – wykryte.
- Stress TCG (8 CPU): czekania na „frames” ~2,8 tys. (v0.20.0) → 13. Samotesty 27/27 przy 1/2/4 CPU (raz TIME TEST
  790 ticków na sekundę RTC – obciążony host u mnie, niezwiązane), stress PASS, bez ostrzeżeń.

## v0.21.0 — 2026-10-11

### ✅ P2 zamknięte (KVM + Legion)
- KVM 8 CPU: stress **177 373** (rekord; v0.20.2: 166 373), czekania na heap 2 395 873 → 113 785 (−95%),
  spawn 41,8 → 34,1 µs.
- Legion 16 CPU: compare **412 608** (v0.20.2: 394 272, +4,7%), max6 **473 223** (447 314, +5,8%), `pass=1`,
  ping-pong 6,6 / 6,85 µs. Heap: 7,23 / 7,66 mln czekań → 0,66 / 0,86 mln (−90%), CPU 6,0 / 7,5% → 0,4 / 0,6%.
- Następne wąskie gardło: alokator ramek („frames”: 48 / 60 mln czekań, 4,0 / 6,0% CPU) i blokada
  schedulera (27–35% wzięć czeka, łącznie 5,7 / 12,1 s na 16 CPU ≈ 0,6–1,3% CPU).

### ✅ P1 zamknięte (Legion, 16 CPU, v0.20.2)
- compare **394 272** skryptów (v0.19.7: 388 883, +1,4%), max6 **447 314** (443 666, +0,8%), `pass=1`, ping-pong
  6,75 µs. Blokady „process table (zombies)” nie ma (było 168 s czekania w max6). Blokada schedulera w max6:
  6,3 s czekania (było 13,1 s). Wąskie gardła teraz: heap (7,2–7,7 mln czekań, 6–7,5% CPU) i scheduler.

### P2: duże klasy heapa (4–32 KiB) na listach per CPU
- Pomiar wolnej ścieżki heapa w stressie (licznik tymczasowy, 8 CPU): 164 tys. alokacji poza listami CPU –
  89% to bloki 2–8 KiB, 7% 16–32 KiB, reszta: 32–128 KiB (~1 na skrypt) i wyrównanie 64 B (~1,5 na skrypt).
- Klasy list per CPU rozszerzone z 16 B..2 KiB do 16 B..32 KiB (12 klas). Duże klasy trzymają mniej bloków na
  CPU (4 KiB: 8, 8 KiB: 8, 16 KiB: 4, 32 KiB: 2 – najwyżej 224 KiB na CPU). Wynik lokalnie: alokacje wolną
  ścieżką 164 tys. → 6,7 tys. (−96%), czekania na blokadę heapa w stressie TCG ~17 tys. → ~0,9 tys.; heap
  zmapowany 2,3 → 4,0 MiB (8 CPU).
- Test: ALLOC TEST 3/4 (producenci / konsumenci na różnych CPU) także z blokami 2049 B, 4, 6, 12 i 32 KiB.
- Zostaje na później: bloki 32–128 KiB (bufory potoków, ELF przy spawn) i obiekty z wyrównaniem 64 B.
- Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń.

## v0.20.2 — 2026-10-11

### P1 cd.: prawdziwa przyczyna wzrostu czekań na heap
- U Dawida (v0.20.1): 27/27 TCG i KVM, stress KVM 166 362, ale spin „heap” nadal 3,61 mln (v0.19.7: 2,39 mln) –
  hipoteza z v0.20.1 (alokacja listy zombie) była błędna: liczba alokacji się nie zmieniła.
- Przyczyna: `IrqSpinLock` w `Process`. `RawSpin` ma `#[repr(align(64))]` (osobna linia cache), więc cały
  `Process` dostał wyrównanie 64 B, a heap obsługuje szybko tylko bloki do 2 KiB z wyrównaniem do 16 B –
  każdy proces (milion na minutę) szedł wolną ścieżką: globalna lista bloków pod jedną blokadą. Widać to też
  w profilu: spawn 38 → 44 µs, reap 25 → 30 µs.
- Teraz lista zombie ma własną jednobajtową blokadę (`procs::ChildList`: przerwania wyłączone na czas sekcji,
  bez lockdep, nigdy dwie naraz) – `level::CHILDREN` usunięty. Asercja w czasie kompilacji: `Process` ≤ 2 KiB
  i wyrównanie ≤ 16 (żeby to się nie powtórzyło).
- Wniosek na P2: obiekty z `SpinLock` (wyrównanie 64) alokowane często (kanały, potoki, pliki) też idą wolną
  ścieżką heapa – do sprawdzenia.
- Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń.

## v0.20.1 — 2026-10-11

### P1 cd.: lista zombie bez heapa
- Potwierdzone u Dawida (v0.20.0): 27/27 TCG i KVM, stress KVM 8 CPU 168 711 skryptów, `pass=1`; blokady
  „process table (zombies)” już nie ma w raporcie.
- Ale czekania na blokadę heapa wzrosły o 45% (2,39 → 3,47 mln): każdy proces z dziećmi alokował i zwalniał
  własny `Vec` na zombie. Teraz `procs::Zombies` – 4 wpisy w samym procesie (bez alokacji), dopiero dalsze w
  `Vec`. Odbiór w dowolnej kolejności (jak w POSIX).
- famtest (200 dzieci naraz) sprawdza też przelanie poza 4 wpisy. Samotesty 27/27 przy 1/2/4 CPU, stress PASS.

## v0.20.0 — 2026-10-11

### P1: zombie w procesie-rodzicu (koniec globalnej tablicy ZOMBIES)
- Powód (Legion v0.19.7, max6): blokada „process table (zombies)” – jedna usypiająca blokada dla wszystkich
  procesów: 12,3 mln wzięć w minucie, 168 s czekania łącznie (compare 46 s).
- Teraz każdy proces ma własną listę zombie dzieci (`Process.zombies`, `IrqSpinLock` poziom 52 – nowy
  `level::CHILDREN`) i licznik `child_gen`:
  - koniec dziecka: pod blokadą schedulera (`with_process` na rodzicu) – sprawdza, że rodzic wciąż jest jego
    rodzicem (inaczej próbuje u nowego) i że się nie kończy; wpis zombie i −1 żywych dzieci w jednej sekcji,
  - koniec rodzica: `sched::reparent_with` – w jednej sekcji pod blokadą schedulera `exiting`, zabranie
    własnych zombie, oddanie żywych dzieci (init dostaje też licznik żywych dzieci +n w tej samej sekcji –
    wcześniej osobno, z małym wyścigiem); zombie przekazane init,
  - `wait`: tylko blokada własnej listy (bez blokady schedulera dla ANY); ECHILD dopiero po sprawdzeniu, że
    `child_gen` się nie zmienił (dziecko mogło dopisać się i zniknąć między sprawdzeniami).
- init w trybie `init test`: na końcu „init: test program ended, N orphans reaped”.
- Nowy test NOBKL TEST 10/10 – `/bin/famtest` pod prawdziwym init (zarejestrowanym jako init): 200 dzieci
  naraz (każdy status raz, właściwy kod), wait(pid) w odwrotnej kolejności, WNOHANG, 8 × 25 wnuków-sierot →
  init odbiera dokładnie 200, 4 rodziców po 50 dzieci równolegle. Test mutacyjny: zgubione przekazanie sierot
  do init – wykryte.
- Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń; w stressie blokady zombie już nie ma na liście
  czekających.

## v0.19.7 — 2026-10-11

### ✅ Zamknięcie M19 (Legion, 16 CPU)
- Potwierdzone u Dawida (v0.19.7): 27/27 TCG i KVM, stress KVM 8 CPU 172 059 skryptów; pomiar KVM: przerwanie
  34,6 µs jądro / 31,4 µs usługa, restart usługi 1,2 ms.
- Legion: compare **388 883** skryptów (M18: 392 943), max6 **443 666** (M18: 448 079) – −1%, w granicach szumu;
  ping-pong 6,55 / 6,75 µs, kanał 930 MB/s (compare), `pass=1` w obu trybach. W QEMU (`run-qemu.sh`): `services`
  pokazuje edu i echo, `mem` przez sysinfo, `sync` działa, `mkfs 0` odrzucone.
- Do poprawy (następny krok): przy pełnym obciążeniu blokada tablicy procesów („process table (zombies)”)
  czeka łącznie 168 s na 16 CPU (13% wzięć musiało czekać); w compare 46 s.

### M19.i: koniec mostu `kcmd` – `sysinfo` i `sysctl` za uchwytem
- Potwierdzone u Dawida (v0.19.6): 27/27 TCG i KVM, stress KVM 8 CPU 174 243 skryptów, `pass=1`.
  Pomiar KVM: przerwanie → sterownik 32,6 µs jądro / 31,9 µs usługa, silnia 53,1 / 55,5 µs, przez `edud`
  84,4 µs, PING 22,6 µs, restart 1,2 ms (opis w ARCHITEKTURA.md, „Pomiar”).
- Syscall 21 `kcmd` usunięty (ENOSYS). Nowe:
  - 46 `sysinfo(temat, bufor)` – tylko odczyt: ver, uptime, date, mem, irq, cpus, lspci (-v), acpi, disk (lista),
    mount, df; ERANGE, gdy bufor za mały.
  - 47 `sysctl(uchwyt, akcja, arg, fd)` – reboot, halt, sync, stress [s]; tylko z uchwytem `SYSCTL` (rodzaj 9,
    prawo tylko DUP). Jądro tworzy go dla init (slot 4), init daje shellowi, shell nie przekazuje programom.
- `/bin/sh`: `mem`, `lspci`… przez sysinfo (z przekierowaniem); wbudowane `sync`, `reboot`, `halt`, `stress`;
  `mkfs`, `disk read/write`, `run`, `k` → „only in the kernel emergency shell”. Bez uchwytu SYSCTL reboot
  odmawia (shell nie z init).
- Testy: INIT TEST 4/9 (sysinfo z przekierowaniem, mkfs / k / disk read / reboot odrzucone), svctest 42
  sprawdzeń (sysinfo, prawa SYSCTL, EBADF / EINVAL, nie da się go wysłać, shell bez niego odmawia, kcmd = ENOSYS).
- Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń.

## v0.19.6 — 2026-10-11

### M19.h: pomiar – sterownik w jądrze vs usługa w user space
- Potwierdzone u Dawida (v0.19.5): 27/27 TCG i KVM, stress KVM 8 CPU 172 953 skryptów, `pass=1`.
- SVC TEST 7/7 mierzy tę samą pracę na `edu` (każdy pomiar ≥ 200 ms):
  - przerwanie → obudzony sterownik (jądro: `WaitQueue` + handler MSI; user space: `wait_many`),
  - silnia zakończona przerwaniem: jądro / sterownik w procesie / klient przez usługę `edud`,
  - `PING` przez usługę (sam koszt IPC) i restart usługi (kill → nowa instancja odpowiada).
- Linia `[RESULT-SVC] ver=… irq_kernel_ns irq_user_ns fact_kernel_ns fact_user_ns fact_svc_ns ping_svc_ns
  restart_us` – `test.sh` wypisuje ją pod „Log:”. W autostressie jej nie ma (edu trzyma `edud` z init).
- `/bin/svcbench`: z HW_ROOT – pełny pomiar; z shella – PING i silnia przez usługę `edu` z init.
  svctest: +1 sprawdzenie (svcbench z shella przez menedżer usług).
- Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń.

## v0.19.5 — 2026-10-11

### M19.g: menedżer usług w init (wariant A)
- Potwierdzone u Dawida (v0.19.4): 27/27 TCG i KVM, stress KVM 8 CPU 168 140 skryptów, `pass=1`.
- `/bin/init` uruchamia usługi z tabeli: `edu` (`/bin/edud`, urządzenie 00:06.0) i `echo` (`/bin/echod`, bez
  urządzenia). Restart po końcu z odstępem 100 ms, podwajanym do 5 s (po 10 s pracy znowu 100 ms); 5 awarii
  w 30 s → „broken”. Brak urządzenia → „no device” (Legion: edu nie ma, echo działa).
- Łączenie po nazwie: shell i programy mają w slocie 3 kanał do init (tylko wysyłanie). `svc_connect("edu")`
  – init przekazuje koniec kanału klienta usłudze; nieznana / leżąca usługa → `EPIPE`. `svc_list` i nowa
  komenda `services` (stan, pid, restarty, program).
- `/bin/echod` – najprostsza usługa (odbija komunikaty, `pid`, `crash` → kod 7), wzór i test na sprzęcie bez edu.
- Shell przekazuje slot 3 uruchamianym programom (`spawn_ex`), gdy sam go dostał.
- `init test <program>` – tryb samotestu; SVC TEST 6/6: prawdziwy init + `/bin/svctest` (28 sprawdzeń: prawa
  kanału svc, lista, echo po nazwie, restart po awarii z nowym pid, edu przez menedżer, restart edud po kill,
  nieznana usługa i złe prośby, `sh -c services`, broken po 5 awariach). Po teście: edu wolne, bus mastering
  off, wektory i ramki wróciły.
- Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń.

## v0.19.4 — 2026-10-11

### M19.f: edud – pierwsza usługa w user space (sterownik `edu`)
- Potwierdzone u Dawida (v0.19.3): 27/27 TCG i KVM, stress KVM 8 CPU 166 889 skryptów, `pass=1`.
- `/bin/edud`: sterownik urządzenia edu jako zwykły proces. Uchwyty na starcie: 1 konsola, 3 urządzenie,
  4 kanał połączeń (w 19.g da je menedżer usług w init). Rejestry przez `dev_map`, silnia i DMA kończą się
  przerwaniem (`irq_bind` + `wait_many`; o końcu decyduje status urządzenia), bufor DMA 8 KiB.
  Jedna pętla `wait_many`: kanał połączeń + przerwanie + do 14 klientów. Prośby obsługiwane po kolei
  (urządzenie jest jedno); odpowiedź wysyłana bez czekania (klient, który nie odbiera, nie zatrzyma usługi).
  Koniec: kanał połączeń zamknięty i żadnego klienta – kod 0.
- Protokół (`user/lib/edu_proto.rs`, wspólny dla usługi i klientów): nagłówek 16 B + dane; `PING`
  (identyfikacja 0x010000ed), `FACT n` (silnia na urządzeniu, 13! = EINVAL – nie mieści się w rejestrze),
  `COPY` (do 4000 B: bufor usługi → urządzenie → bufor przez DMA), `STATS`. Zła prośba – odpowiedź EINVAL,
  usługa działa dalej. Połączenie: klient tworzy kanał i wysyła jeden koniec do kanału połączeń usługi.
- `/bin/edutest` (16 sprawdzeń) – uruchamia usługę jak przyszły menedżer (przejęcie z HW_ROOT, `spawn_ex`),
  klient: PING, silnie 0..12, kopiowanie 4000 B przez DMA, zła / krótka prośba; 4 procesy-klienci po 50 próśb
  naraz; **kill usługi → klient dostaje EPIPE, urządzenie wraca, nowa instancja działa** (restart ręczny – w
  19.g zrobi to init); zamknięcie – usługa kończy się sama. Jądro po teście: urządzenie wolne, bus mastering
  wyłączony, wektory i ramki wróciły. SVC TEST 5/5 (219 próśb obsłużonych przez usługę).
- Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń.

## v0.19.3 — 2026-10-11

### M19.e: DMA – urządzenie samo czyta i zapisuje bufor usługi
- Potwierdzone u Dawida (v0.19.2): 27/27 TCG i KVM, stress KVM 8 CPU 168 412 skryptów, `pass=1`.
- Syscalle: 44 `dma_alloc(dev, rozmiar, bity_adresu)` → uchwyt pamięci współdzielonej (mapowanie przez
  `shm_map`) z **ciągłych** ramek leżących całe poniżej `2^bity` (24..=64; `edu` widzi tylko 28 bitów i
  obcina wyższe – bufor powyżej trafiłby w cudzą pamięć); ≤ 2 MiB na bufor, ≤ 16 MiB na urządzenie (`ENOMEM`);
  wymaga `MAP_WRITE`; włącza bus mastering. 45 `dma_phys(bufor)` – adres fizyczny (`EINVAL` dla zwykłej pamięci
  współdzielonej; bez BKL).
- **Bufor DMA żyje tak długo jak przejęcie urządzenia** (`DevClaim` trzyma listę) – zamknięcie uchwytu i
  munmap go nie zwalniają; ramki wracają dopiero po wyłączeniu bus masteringu i MSI przy oddaniu urządzenia.
- Alokator ramek: `alloc_frames_below(n, align, limit)` – ciągłe ramki poniżej adresu.
- `/bin/dmatest` (23 sprawdzenia): prawa, rozmiary, bity szyny, `dma_phys`; edu czyta bufor (RAM → edu) i
  zapisuje go w drugą połowę (edu → RAM), dwa razy z różnymi wzorami, koniec każdego transferu przerwaniem;
  zamknięty bufor nie jest oddany innemu (sprawdzone mutacją: bez listy w przejęciu nowy bufor dostaje te same
  ramki – FAIL); limit 16 MiB; kill procesu z buforem DMA i przerwaniem. Jądro po teście: ramki wróciły
  (15 MiB buforów), bus mastering wyłączony, urządzenie wolne. SVC TEST 4/4.
- **irqtest – poprawka założenia:** 10 szybkich przerwań może dać licznik < 10 – przerwania tego samego wektora,
  które przyjdą, zanim procesor obsłuży poprzednie, APIC łączy w jedno (lokalnie raz: 9 z 10). Licznik to
  „co najmniej jedno przerwanie od ostatniego odczytu”, nie dokładna liczba; usługa sprawdza status urządzenia.
  Test sprawdza teraz 1..=10 i wszystkie bity w rejestrze statusu edu. Opisane w ARCHITEKTURA.md.
- Samotesty 27/27 przy 1/2/4 CPU (4 CPU – 3 razy z rzędu), stress PASS, bez ostrzeżeń.

## v0.19.2 — 2026-10-11

### Poprawka testów: fałszywy "frames leaked"
- U Dawida (v0.19.1, raz na dwa uruchomienia): `[IPC TEST] FAIL: frames leaked (115418 -> 115478)` – na końcu
  zestawu WIĘCEJ wolnych ramek niż na starcie. Przyczyna: pomiar startowy, zanim reap (pętla idle) sprzątnął
  procesy poprzedniego zestawu (FILE TEST kończy procesy przez #PF i sprawdza ramki z tolerancją). Nowe
  `selftest::settled_free_frames()` – reap, aż liczba wolnych ramek nie zmienia się przez 3 próbki co 5 ms –
  jako punkt odniesienia w ELF, SYSCALL, INIT, IPC i SVC TEST. To nie był wyciek w jądrze.

### M19.d: przerwania urządzeń w user space
- Syscalle: 42 `irq_bind(dev)` → uchwyt **IRQ** (rodzaj 8, prawo `RECV`; wymaga `MAP_WRITE` na urządzeniu) –
  wektor MSI (albo MSI-X wpis 0), bus mastering (MSI to zapis urządzenia do pamięci); `EBUSY` – już przypięte
  albo brak wektorów, `ENODEV` – urządzenie bez MSI. 43 `irq_read(irq)` – przerwania od ostatniego odczytu
  (zeruje; bez BKL). `wait_many` z sygnałem **`W_IRQ`**.
- `device.rs`: statyczne sloty wektor ↔ licznik + obserwatorzy (handler nie dotyka pamięci, która mogłaby być
  zwolniona); handler: licznik + pobudka – nic więcej. MSI zboczowe – bez maskowania; kilka przerwań przed
  obsługą = jedna pobudka z licznikiem.
- **Zwalnianie wektorów** (`msi::free`, `free_count`) – wcześniej wektor raz wzięty zostawał na zawsze; usługa
  restartowana 16 razy zabrałaby wszystkie. Drop uchwytu IRQ: MSI off w urządzeniu, odczyt rejestru (zapis
  dotarł), wektor wolny. Drop przejęcia urządzenia: MSI off i **bus mastering off**, zanim urządzenie wróci.
  `pci.rs`: `disable_msi`, `set_bus_master`.
- `/bin/irqtest` (25 sprawdzeń na `edu`): prawa i EBUSY, przerwanie na żądanie budzi `wait_many`, licznik i
  status w urządzeniu, 10 przerwań → 1 pobudka z licznikiem 10, silnia 12! zakończona przerwaniem zamiast
  odpytywania, przerwanie i kanał na jednej liście (właściwe bity), 20 × przypięcie / zamknięcie (wektorów jest
  16), zabicie procesu z przypiętym przerwaniem. Jądro sprawdza po teście: wektory wróciły, bus mastering edu
  wyłączony, urządzenie wolne. Sprawdzone, że bez `msi::free` test pada („13 succeeded”). SVC TEST 3/3.
- Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń.

## v0.19.1 — 2026-10-11

### M19.c: urządzenie jako uchwyt – HW_ROOT, dev_claim, dev_map
- Potwierdzone u Dawida (v0.19.0): 27/27 TCG i KVM, stress KVM 8 CPU 166 070 skryptów, `pass=1`.
- **HW_ROOT** (rodzaj uchwytu 6): powstaje tylko w jądrze (`SpawnOptions::hw_root`) – dostaje go `/bin/init`
  w slocie 3 (i testy jądra). Prawa 0: bez `DUP` i `TRANSFER` nie da się go skopiować, dać dziecku ani wysłać.
- **Właściciel urządzenia** (`drivers/pci.rs`): tablica `OWNERS` (wolne / sterownik jądra / usługa), virtio-blk
  i NVMe zapisują się jako sterownik jądra. `claim_user` odmawia: sterownik w jądrze, klasy 0x01 (dyski –
  zawsze, także bez sterownika), 0x03 (grafika), 0x06 (mostki), 0x08 (urządzenia systemowe), funkcje
  niebędące zwykłym urządzeniem. `lspci` pokazuje właściciela.
- Syscalle: 39 `dev_claim(hw_root, bdf)` → uchwyt **DEVICE** (rodzaj 7; `MAP_READ|MAP_WRITE|DUP|TRANSFER`),
  błędy `EACCES` / `EBUSY` (-16) / `ENODEV` (-19); 40 `dev_info` (vendor, device, klasa, rozmiary BAR-ów, BAR-y
  I/O, MSI / MSI-X); 41 `dev_map(dev, bar, prot)` – rejestry BAR-u w procesie, **bez cache (UC), nigdy
  wykonywalne**, strony tablicy MSI-X / PBA pominięte; BAR musi mieć ≥ 4 KiB i być wyrównany do strony (na
  wspólnej stronie mogłyby leżeć rejestry innego urządzenia), ≤ 256 MiB. Pod BKL (dostęp do konfiguracji PCI
  przez porty nie jest bezpieczny na wielu CPU naraz; syscalle rzadkie).
- `kernel/user/device.rs`: `DevClaim` (Arc – uchwyty i mapowania); Drop oddaje urządzenie. `vm.rs`: obszar
  wspólny ma właściciela `SharedRef` (pamięć współdzielona albo przejęcie urządzenia) – mapowanie trzyma
  przejęcie, `munmap` tylko w całości.
- **Koniec procesu zdejmuje mapowania wspólne od razu** (`exit_current`, nie dopiero przy reap) – przejęte
  urządzenie wraca, zanim rodzic dostanie status z `wait` (test to wykrył: po kill urządzenie było jeszcze
  zajęte).
- Profil: 48 numerów syscalli (było 40). QEMU w `test.sh`, `stress-qemu.sh`, `run-qemu.sh`: `-device edu,addr=06`.
- `/bin/devtest` (37 sprawdzeń): HW_ROOT nie do skopiowania / wysłania / przekazania, odmowy dla mostka, VGA,
  virtio-blk, NVMe, mostka ISA, SATA; edu: przejęcie, EBUSY, `dev_info`, rejestry (identyfikacja 0x010000ed,
  rejestr żywotności, silnia 10! przez MMIO), prawa mapowania, munmap w całości, przejęcie trzymane przez
  mapowanie, zapis przez mapowanie tylko do odczytu = #PF, kill procesu z zamapowanym urządzeniem → wolne.
  SVC TEST 2/2. Samotesty 27/27 przy 1/2/4 CPU, stress PASS, bez ostrzeżeń.

## v0.19.0 — 2026-10-11

### M19.a: projekt usług w user space
- `ARCHITEKTURA.md`, „Usługi w user space”: `wait_many`, `HW_ROOT` / `dev_claim` / `dev_map`, przerwania jako
  licznik + pobudka, DMA (bufory żyją z przejęciem urządzenia, sprzątanie: bus mastering off → wektor → ramki),
  menedżer usług w init (wariant A; wariant B – osobny `/bin/svcmgr` – opisany na później), pierwsza usługa
  `edu` z QEMU, koniec `kcmd`, numery syscalli 38–46. Zaakceptowany przez Dawida.

### M19.b: wait_many – czekanie na wiele uchwytów naraz
- Syscall 38 `wait_many(lista, n, timeout_ms)`: lista do 16 par [uchwyt, sygnały], wynik = maska gotowych
  wpisów (0 = minął czas; `u64::MAX` = bez limitu, 0 = tylko sprawdź). Sygnały: `READABLE` (kanał: komunikat
  albo zamknięta druga strona; potok: dane albo brak piszących), `WRITABLE` (miejsce albo zamknięta druga
  strona); `IRQ` zarezerwowany na 19.d. Prawa jak przy operacji: `RECV` / `SEND`, `READ` / `WRITE`. Cała lista
  sprawdzana przed czekaniem (EINVAL / EBADF / EACCES / EFAULT). Kill przerywa (EINTR). Bez BKL.
- `kernel/user/waitset.rs`: `Observers` – lista kanałów czekających zadań w każdym obiekcie (kolejka końca
  kanału, potok), `IrqSpinLock` na nowym poziomie `WAITERS` (45 – nad kanałami / potokami, pod schedulerem).
  `wait_many` zapisuje się u obiektów, śpi na własnej WaitQueue, wypisuje się po pobudce. Obiekty budzą
  obserwatorów przy każdej zmianie (komunikat, miejsce, zamknięcie). Licznik obserwatorów – `notify` bez
  czekających nie bierze blokady (każdy send / recv go woła; bez tego ping-pong w TCG wolniejszy o ~30%).
- `/bin/waittest` (34 sprawdzenia): błędy listy, limit czasu, kanały i potoki, ten sam uchwyt dwa razy,
  zamknięta druga strona, pobudka komunikatem od dziecka, **serwer obsługujący 4 klientów naraz** (2000 próśb,
  nadawca od jądra), pełna kolejka, kill procesu czekającego w `wait_many`. Sprawdzone, że bez budzenia
  obserwatorów test się zawiesza (FAIL).
- Nowy zestaw samotestów **SVC TEST** (27 zestawów). Profil: nazwa `wait_many`. Biblioteka: `wait_many`,
  `W_READABLE` / `W_WRITABLE` / `W_IRQ`, `FOREVER`.
- Samotesty 27/27 przy 1, 2 i 4 CPU, stress 8 CPU PASS, bez ostrzeżeń.

## v0.18.4 — 2026-10-11

### M18.f: IPC pod obciążeniem, pomiar, linia [RESULT]
- **M18 zamknięte (2026-10-11, Legion 16 CPU, 60 s):** tryb porównawczy **392 943 skryptów** (v0.17.35: 360 713,
  +9%) + 5056 zadań ipcload (1 011 200 wymian, 5056 dzieci zabitych w czekaniu); pełne obciążenie (pula 6)
  **448 079** (v0.17.35: 447 028). `ipcbench`: ping-pong **6,6 µs**, kanał 165–190 tys. msg/s × 4 KiB
  (645–744 MB/s), 16 MiB kanałem 21–25 ms / pamięcią współdzieloną 5 ms. 0 zgłoszeń zakleszczeń, 0 pomiarów
  z ujemnym czasem, `pass=1` w obu trybach. KVM 8 CPU: 171 891 skryptów, ping-pong 5,6 µs (samotest).
- Pomiar Dawida (v0.18.3, KVM, 4 CPU): ping-pong **6 µs** na wymianę; 26/26 (TCG i KVM), stress KVM 8 CPU
  154 988 skryptów.
- `/bin/ipcload`: rodzic pisze 4 KiB wzoru do pamięci współdzielonej i dzwoni przez kanał, dziecko (spawn_ex:
  kanał + pamięć tylko do odczytu) liczy sumę i odpowiada – 200 wymian; na koniec rodzic zabija dziecko
  czekające w `chan_recv` (z zamapowaną pamięcią) i sprawdza, że jego koniec kanału znika (EPIPE).
- Stress: trzeci rodzaj zadania – jedno `ipcload` na pętlę sterującą, **poza pulą** skryptów (tryb porównawczy
  zostaje porównywalny; zadanie IPC zabiera trochę CPU). Nowy wiersz raportu `ipc:` (zadania, wymiany, zabite
  dzieci).
- `/bin/ipcbench`: ping-pong 8 B (20 000), przepustowość kanału (20 000 × 4 KiB w jedną stronę: msg/s, MB/s),
  16 MiB przez kanał (komunikaty 4 KiB) kontra pamięć współdzieloną (kawałki 1 MiB + dzwonek), z kontrolą sum.
  Autostress uruchamia go po stressie i wypisuje wynik.
- **`[RESULT]`** – ostatnia linia autostressu: `ver mode cpus ms scripts primes ipc idle pingpong_ns chan_msgs
  chan_mbs chan16_ms shm16_ms pass` (błąd: `pass=0 error="…"`). `stress-qemu.sh` czeka na nią i ją wypisuje;
  limit czasu + 180 s (pomiar po stressie).
- `/bin/ipcdemo` – pokaz do uruchomienia w shellu: kanał, `spawn_ex` z trzema uchwytami (kanał, konsola,
  pamięć), tekst tam i z powrotem, dziecko pisze do wspólnej pamięci, rodzic czyta po dzwonku.
- IPC TEST 5/5: ipcload, ipcdemo (sprawdzane wyjście), ipcbench (wynik w logu). QEMU TCG: ping-pong ~240 µs,
  kanał ~25 000 msg/s (~100 MB/s), 16 MiB: kanał ~130 ms / pamięć ~75 ms.
- Samotesty 26/26 przy 1, 2 i 4 CPU, stress 8 CPU PASS z `ipc:` i `[RESULT]`, bez ostrzeżeń.

## v0.18.3 — 2026-10-11

### M18.e: pamięć współdzielona
- `kernel/user/shm.rs`: obiekt pamięci współdzielonej – ramki brane od razu i zerowane, rozmiar zaokrąglony do
  4 KiB, najwyżej 16 MiB. Liczony przez `Arc` (uchwyty + mapowania); ramki wracają w `Drop`, gdy znika ostatni
  uchwyt i ostatnie mapowanie.
- `vm.rs`: nowy rodzaj obszaru `Shared` – cały obiekt mapowany od razu w obszarze mmap, zawsze NX, zapis tylko z
  prawem `MAP_WRITE`. `munmap` obszaru wspólnego tylko w całości (część – EINVAL) i bez zwalniania ramek;
  `fault_in` nie podstawia prywatnej strony w obszarze wspólnym.
- **Koniec procesu:** Drop przestrzeni adresowej zwalnia każdą zamapowaną ramkę – nowy `Drop for Process`
  najpierw zdejmuje mapowania wspólne (`release_shared`). Sprawdzone, że bez tego test wykrywa zniszczone dane
  (ramki obiektu wracały do puli po końcu jednego z procesów).
- Syscalle: 34 `shm_create(rozmiar)`, 35 `shm_map(h, prot)`, 37 `shm_size(h)` (bez BKL, jak brk / mmap).
  Uchwyt: `MAP_READ|MAP_WRITE|DUP|TRANSFER`; `read`/`write` na nim – EBADF.
- IPC TEST 4/4: `/bin/shmtest` – 29 sprawdzeń: rozmiary i błędy, wyzerowana pamięć, dwa mapowania tych samych
  stron w jednym procesie, uchwyt tylko do odczytu (mapowanie do zapisu – EACCES), munmap częściowy / całość,
  dziecko-pisarz dostaje uchwyt przez kanał, zapisuje 64 KiB i dzwoni przez kanał, dziecko-czytelnik z
  uchwytem tylko do odczytu liczy sumę, zapis do mapowania tylko do odczytu / skok do wspólnej pamięci /
  dostęp po munmap – dziecko zabite przez #PF, obiekt żyje po zamknięciu uchwytów, dopóki jest zamapowany;
  zero wycieku ramek (sprawdza zestaw).
- Samotesty 26/26 przy 1, 2 i 4 CPU (QEMU TCG, 4 CPU dwa razy), stress 8 CPU PASS, bez ostrzeżeń.

## v0.18.2 — 2026-10-11

### M18.d: uchwyty w komunikatach, spawn_ex
- Pomiar Dawida (v0.18.1, KVM, 4 CPU): ping-pong przez kanał **8 µs na wymianę** (komunikat tam i z powrotem,
  dwa przełączenia procesów); stress KVM 8 CPU 153 500 skryptów – bez zmian.
- `chan_send` z listą uchwytów (do 8): uchwyty **przenoszone** – znikają z tablicy nadawcy, wymagają
  `TRANSFER`, prawa bez zmian. Lista sprawdzana w całości przed zdjęciem czegokolwiek (istnieje, `TRANSFER`,
  bez powtórzeń – EBADF / EACCES / EINVAL). Żaden koniec kanału nie może podróżować przez ten sam kanał
  (EINVAL; wcześniej w projekcie – tylko koniec wysyłający; drugi koniec też tworzyłby cykl). Błąd wysyłki
  (pełna kolejka, EPIPE, kill) – uchwyty wracają na swoje numery.
- `chan_recv`: uchwyty u odbiorcy pod najniższymi wolnymi numerami, numery w tablicy podanej przez proces;
  za mało miejsca na numery – EMSGSIZE (`info.handles` = ile), pełna tablica uchwytów – EMFILE; w obu
  przypadkach komunikat zostaje w kolejce. Uchwyty w komunikatach do zamkniętego końca – zwalniane.
- 36 `spawn_ex(ścieżka, argv, mapa, n | flagi)` – dziecko dostaje **tylko** uchwyty z mapy [(uchwyt rodzica,
  numer u dziecka)], n ≤ 16, numer < 64 bez powtórzeń, każdy wymaga `DUP`. Bez mapy dziecko nie ma nawet
  konsoli. `spawn` (3 × stdio) i `spawn_ex` mają wspólną część (`spawn_common`); `spawn_child` przyjmuje
  całą tablicę uchwytów.
- IPC TEST 3/3: `/bin/xfertest` – 32 sprawdzenia: przeniesienie i prawa, EACCES bez TRANSFER (uchwyt
  zostaje), powtórzenie / zły numer, oba końce własnego kanału (EINVAL), koniec innego kanału przez kanał,
  EMSGSIZE i EMFILE bez utraty komunikatu, zwolnienie końca kanału z porzuconej kolejki (EPIPE), błędy
  `spawn_ex`, dziecko z jednym uchwytem (sprawdza, że nie ma żadnego innego) dostaje plik tylko do odczytu
  przez kanał, czyta, nie może pisać, odpowiada; nadawca = pid rodzica.
- Samotesty 26/26 przy 1, 2 i 4 CPU (QEMU TCG, 4 CPU dwa razy), stress 8 CPU PASS, bez ostrzeżeń.

## v0.18.1 — 2026-10-11

### M18.c: kanały
- `kernel/user/channel.rs`: kanał = para końców, każdy z własną kolejką przychodzących (dwukierunkowy).
  Komunikat do 4 KiB, do 64 w kolejce, nadawca (pid) wpisywany przez jądro. Blokada per kolejka (poziom
  PROCESS, jak potok), pod nią tylko operacje na kolejce; dane kopiowane z procesu przed blokadą, do procesu po
  niej. Czekanie przez `WaitQueue` na atomikach (`len`, `closed`) – bez gubienia pobudek, przerywane przez
  kill (EINTR). Zamknięcie ostatniego uchwytu końca: kolejka opróżniona, druga strona dostaje EPIPE (po
  odebraniu tego, co już przyszło).
- Syscalle: 31 `channel_create`, 32 `chan_send`, 33 `chan_recv` (bez BKL). Prawa: wysyłanie wymaga `SEND`,
  odbiór `RECV` (EACCES); `read`/`write` na kanale – EBADF. Nowe błędy: `EAGAIN` (-11, `CHAN_NONBLOCK`),
  `EMSGSIZE` (-90, komunikat > 4 KiB albo za mały bufor – wtedy wymagany rozmiar w `info`, komunikat
  zostaje). ABI ma już miejsce na uchwyty w komunikacie (M18.d; na razie n_uchwytów musi być 0).
- IPC TEST 2/2: `/bin/chantest` – 28 sprawdzeń: obie strony, nadawca, pusty komunikat, EAGAIN przy pustej i
  pełnej (64) kolejce, FIFO, EMSGSIZE, 4096 B, prawa, EPIPE po zamknięciu, ping-pong 10 000 wymian z
  dzieckiem (QEMU TCG: 122–250 µs na wymianę), kill dziecka czekającego w `chan_recv` (jego koniec znika).
- Poprawka profilu (v0.18.0): przy rozszerzeniu numerów syscalli zabrakło jednej nazwy – etykiety tabeli
  `prof` przesunięte o jedną ("ctx switch" pokazywał spawn:load, "TSC skew" – drv exec). Liczby były dobre.
  Teraz sprawdzenie w czasie kompilacji: nazwy muszą zgadzać się z numerami kategorii.
- Samotesty 26/26 przy 1, 2 i 4 CPU (QEMU TCG, 4 CPU – 4 przebiegi pod rząd), stress 8 CPU PASS, bez ostrzeżeń.

## v0.18.0 — 2026-10-11

### M18.a–b: projekt IPC, uchwyty z prawami
- **M18.a** – projekt IPC w `ARCHITEKTURA.md` („IPC – kanały, uchwyty, pamięć współdzielona”): uchwyty z
  prawami, kanały (para końców, 4 KiB + 8 uchwytów na komunikat, 64 w kolejce, nadawca wpisywany przez jądro),
  pamięć współdzielona (max 16 MiB, zawsze NX), `spawn_ex`, blokada per kanał, numery syscalli 29–36,
  linia `[RESULT]`. Roadmapa M18: kroki a–f.
- **M18.b** – deskryptory stały się **uchwytami**: wpis tablicy = obiekt + prawa (`READ`, `WRITE`, `SEND`,
  `RECV`, `MAP_READ`, `MAP_WRITE`, `DUP`, `TRANSFER`). Prawa początkowe jak dotychczasowe zachowanie (plik
  tylko do odczytu = `READ|DUP|TRANSFER`, koniec potoku do zapisu = `WRITE|DUP|TRANSFER`, konsola
  `READ|WRITE|DUP|TRANSFER`). Limit 16 → 64 uchwytów na proces.
- Nowe syscalle: 29 `handle_dup(h, maska)` – kopia z prawami `stare & maska` (prawa nigdy nie rosną),
  30 `handle_info(h)` – rodzaj obiektu i prawa. `read`/`write` bez prawa → `EBADF` (POSIX), kopia (`dup`,
  `dup2`, `handle_dup`, uchwyty dziecka w `spawn`) bez `DUP` → `EACCES`.
- Profil: miejsce na syscalle 0–39 (nowe numery nie mieszają się z kategoriami #PF / przerwań).
- IPC TEST (nowy zestaw, 26 zamiast 25): `/bin/handletest` – 23 sprawdzenia: prawa z obiektu, zmniejszanie,
  brak wzrostu przez `handle_dup(ALL)` / `dup` / `dup2`, EBADF / EACCES, dziecko po `spawn` dostaje uchwyt z
  tymi samymi prawami i nie może ich zwiększyć, limit 64; bez wycieku ramek.
- Samotesty 26/26 przy 1, 2 i 4 CPU (QEMU TCG), stress 8 CPU PASS, bez ostrzeżeń.

## v0.17.35 — 2026-10-10

### Poprawki przed M18 – bezpieczeństwo heapa, test między CPU, dwa tryby stressu
- **Heap: jedna reguła rozmiaru bloku.** Małe bloki (<= 2 KiB, wyrównanie <= 16) zawsze zaokrąglane do klasy
  (potęga 2), także przy wyłączonych listach CPU. Wcześniej blok wzięty przed `enable_cpu_caches` (np. 80 B
  jako 80) i oddany po (na listę klasy 128) oddałby heapowi 48 B sąsiada. Dziś listy włączane są zaraz po
  starcie heapa, więc się nie zdarzało – ale wystarczyła zmiana kolejności startu. Teraz niemożliwe.
- MM TEST 10/10: bloki o rozmiarach spoza potęg 2 wzięte przed włączeniem list, oddane po, ponownie wzięte
  i zapisane w całości (rozmiar klasy) – bloki-strażnicy nienaruszone. Sprawdzone na starej regule: test
  łapie błąd ("guard block 4 (1100 B) overwritten").
- ALLOC TEST 3/4: producenci biorą bloki (12 rozmiarów, wszystkie klasy), wypełniają wzorem, co czwarty
  trzymają do końca, resztę przez kanał (SpinLock, najwyżej 256) oddają konsumentom, którzy sprawdzają wzór,
  piszą po bloku i zwalniają – zwykle na innym CPU (4 CPU: 14 860 z 18 000; 2 CPU: 6 103 z 9 000). Bez
  zgubionych bloków i wycieku.
- **Stress: dwa tryby, opisane w raporcie** (linia `mode:`). Domyślny – porównawczy, bez zmian (3 procesy na
  CPU, najwyżej 48). Pełne obciążenie: `DESOOS_STRESS_POOL=P` przy buildzie (P procesów na CPU, najwyżej
  128) – np. `DESOOS_AUTOSTRESS=60 DESOOS_STRESS_POOL=6 ./make-usb.sh ...`. Wyników z różnych trybów nie
  porównujemy.
- Samotesty: 25/25 przy 1, 2 i 4 CPU (QEMU TCG).

## v0.17.34 — 2026-10-09

### Wydajność – M17b.h: listy wolnych bloków heapa per CPU (koniec kręcenia na blokadzie `heap`)
- **Legion**, tabela `spin wait`: v0.17.32 – 49 797 skryptów, v0.17.33 (pamięć stosów) – 51 068. W obu
  **blokada `heap`: ~70 mln czekań, średnio 11 µs = 83% czasu wszystkich CPU** na kręceniu. Pamięć stosów
  działa (TLB shootdown: 373 494 → 476 żądań, `sp:task` 235 → 126 µs), ale przy heapie to szum. To tłumaczy
  wolne syscalle plikowe (270–420 µs przy ~2,5 µs w drzewie ramfs) – jądro alokuje ścieżki i bufory w
  każdym syscallu.
- Przyczyna: heap to jedna lista wolnych bloków posortowana po adresie pod IrqSpinLock – przy alloc
  przeglądana (first-fit), przy dealloc dwa razy (wstawienie + `shrink()` szukający ostatniego węzła
  przejściem CAŁEJ listy przy każdym zwolnieniu).
- `memory/heap.rs`: bloki do 2 KiB (wyrównanie <= 16) w klasach 16..2048; każdy CPU ma dla klasy listę
  wolnych bloków – alloc / dealloc bez blokady (przerwania wyłączone na chwilę). Pusta lista = paczka bloków
  jedną wizytą pod blokadą, za długa (~16 KiB na klasę) = połowa wraca naraz. Włączone po samoteście heapa.
  `shrink()` dostaje węzeł końca heapa z `insert_free` (bez przejścia listy). `used_bytes` bez bloków na
  listach.
- Testy TLB 5 i ALLOC 1: duże bloki mogą trafić w dziury heapa – TLB 5 alokuje po 1 MiB, aż heap urośnie;
  ALLOC 1 wymaga shootdown tylko, gdy heap urósł.
- QEMU TCG 8 CPU, 15 s: 650 skryptów (v0.17.33: 559, v0.17.32: ~220).
- A/B: `ab/v0.17.33` (bez list heapa), `ab/v0.17.32` (bez list heapa i pamięci stosów).
- **Legion v0.17.34: 360 986 skryptów + 180 491 primes w 60 s** (v0.17.33: 51 068, v0.17.28: 55 834) – 7x.
  `spin wait`: heap 3,0% CPU (było 83%), 37 mln czekań po 0,7 µs; 32% bezczynności – stress (pula 48
  procesów, 4 pętle sterujące 18% zajęte) ogranicza sam siebie. Blokada schedulera: 23% wzięć z czekaniem
  (28,7 mln wzięć, 4,1 s), tablica procesów 23 s snu. **M17b zamknięte.**

## v0.17.33 — 2026-10-09

### Wydajność – M17b.g: pamięć stosów zadań (bez blokady `stack-pages` przy spawn / reap)
- **Legion** v0.17.32 (profil czasu CPU, 16 CPU, 60 s): 53 234 skrypty; na skrypt `spawn` 5,2 ms CPU (z tego
  ładowanie dziecka 4,1 ms), `write` 1,9 ms, `stat` 1,1 ms; operacje plików po 270–420 µs, choć drzewo ramfs
  jest trzymane ~2,5 µs na operację. 45% wzięć spinlocków z czekaniem (93 mln z 205 mln).
- Profil rozszerzony: `spawn` rozbity na `sp:readfile` (plik programu do pamięci), `sp:elf+pt` (przestrzeń,
  segmenty, stos), `sp:task` (stos kernela + scheduler); nowa tabela **spin wait** – czas kręcenia na
  spinlockach per nazwa blokady (TSC na jednym CPU – wywłaszczanie wyłączone).
- QEMU 8 CPU: 38% czasu CPU to kręcenie na `stack-pages` (średnio 20 ms!) w `sp:task` i `reap`. Ta globalna
  IrqSpinLock trzymała przy tworzeniu stosu kernela zadania alokację i zerowanie 16 ramek, a przy zwalnianiu –
  odmapowanie i TLB shootdown na wszystkie CPU z czekaniem na potwierdzenia.
- **Pamięć stosów** (`sched/stack.rs`): stos zakończonego zadania zostaje zamapowany (bit `MAPPED`, slot wolny)
  – spawn bierze najniższy wolny slot jak wcześniej i jeśli ma stos, używa go bez alokacji, zerowania i
  blokady; reap bez odmapowania i shootdown. Najwyżej 256 stosów (16 MiB), nadmiar zwalniany po staremu.
  Testy wycieku ramek i stress liczą wolne ramki po `flush_cache()` (odmapowanie pamięci stosów).
- QEMU TCG 8 CPU: 559 skryptów / 15 s (bez pamięci stosów 145 / 10 s); `stack-pages` – 1 czekanie.
- A/B: `./ab-usb.sh v0.17.32 "/media/dawid/NOSNIK USB"` – ten sam profil bez pamięci stosów.

## v0.17.32 — 2026-10-09

### Pomiar – M17b.f: profil wejść do kernela (czas na syscall / wyjątek / przerwanie)
- **Legion** z v0.17.31: 50 987 skryptów – +11% wobec v0.17.30 (45 773), ale nadal ~9% poniżej v0.17.28
  (55 834). Statystyki blokad na skrypt bez zmian, więc brakujący czas jest w samej ścieżce wykonania.
- Nowy moduł `user/prof.rs`: liczba wywołań i cykle TSC (`rdtscp` – czas i numer CPU jedną instrukcją),
  per CPU w osobnych liniach cache. Mierzone: każdy syscall (od wejścia, z czekaniem na BKL, do SYSRET),
  #PF procesu (leniwe strony), IRQ PIT, timer LAPIC, IPI przełączenia, przełączenie zadania (bez samego
  `sched_switch`), reap, koniec procesu, tworzenie dziecka w `spawn` (`spawn:load`) i `exec` pętli stressu.
- Autostress / `stress`: 12 najdroższych pozycji – liczba, średnio µs, % czasu wszystkich CPU, µs na
  skrypt. Syscalle, które mogą spać (`(sleeps)`), mają czas ściany, nie CPU.
- Linie autostressu z wersją: `[AUTOSTRESS v0.17.32]` – zdjęcie z Legiona od razu mówi, który build działał
  (`stress-qemu.sh` rozpoznaje oba formaty).
- Poprawka po pierwszym starcie na Legionie (panic `prof.rs`: attempt to add with overflow): TSC rdzeni Ryzena
  nie jest idealnie zgrany – pomiar zaczęty na jednym CPU i skończony na drugim dawał `t1 < t0`, a
  odejmowanie z zawinięciem ~2^64 cykli. Takie pomiary liczą się teraz osobno (`TSC skew`, czas 0), sumy
  nasycają się.
- Drugi start na Legionie: tabela bez sensu (`stat` średnio 64 ms, `spawn` 6248% CPU) – przesunięcia TSC między
  rdzeniami są duże, więc każdy pomiar z migracją był śmieciem w obie strony (40 745 ujemnych). Profil mierzy
  teraz **czas CPU zadania**: scheduler dolicza zadaniu cykle od wejścia na CPU do zejścia, oba odczyty na
  tym samym CPU (`sched::task_cpu_cycles`). Sen i czas innych zadań się nie liczą; linia `check:` = liczba
  ujemnych pomiarów (ma być 0).

## v0.17.31 — 2026-10-09

### Wydajność – M17b.e: dane per CPU i liczniki w osobnych liniach cache (false sharing)
- Bisekcja na Legionie (`./ab-usb.sh`, 60 s, 16 CPU): v0.17.27 – 54 382, v0.17.28 (obiekty plików, potoki)
  – 55 834, v0.17.29c (v0.17.28 + tylko #PF bez IST) – 51 564, v0.17.30 ze starą stertą programów – 47 556,
  v0.17.29 / v0.17.30 – 47 880 / 45 773. Zmiana v0.17.29c (bramka #PF, tablica per CPU) nie wykonuje się
  w stressie, a kosztowała ~7% – objaw zależności od układu zmiennych w pamięci.
- Przyczyna: gęste tablice per CPU (`[AtomicU32; 16]` – 16 CPU w 1–2 liniach cache) zapisywane na gorących
  ścieżkach – licznik wywłaszczania i trzymanych spinlocków (każde wzięcie / zwolnienie), stan blokady
  schedulera, kwant, NEED_RESCHED, ticki – oraz globalne liczniki statystyk (`fetch_add` z każdego CPU:
  wzięcia spinlocków ~200 mln / 60 s, blokady schedulera, syscalle). Każdy zapis unieważnia linię u
  pozostałych CPU.
- Nowy moduł `arch/x86_64/percpu.rs`: `PerCpu<T>` (każdy element w osobnej linii 64 B, indeksowanie jak
  tablicą, `per_cpu!`), `PerCpuCounter` (każdy CPU dodaje do swojego, odczyt sumuje), `CacheLine<T>`.
  Przeniesione: wszystkie tablice per CPU jądra (cpu, spin, scheduler, smp, tlb, vm, stress), liczniki
  spinlocków, blokady schedulera, BKL i syscalli; `RawSpin`, wpisy statystyki miejsc i `SCHED_OWNER` –
  każde w osobnej linii.
- QEMU TCG: 1 CPU, 20 s – 693 skrypty (v0.17.30: ~550, +25%); 4 CPU, 15 s – 524 (~400–450).

## v0.17.30 — 2026-10-08

### Pomiar – M17b.d2: liczniki pamięci procesów, fault-around jako pokrętło
- **Legion** (16 CPU, 60 s) z v0.17.29: 47 880 skryptów (v0.17.27: 53 809, −11%); `SMP=8 ./stress-qemu.sh`:
  38 363 (41 328). Blokady bez zmian (BKL 0,26 s, scheduler 2%, ramfs 2,2 s); tablica procesów 101 s (74 s).
- `cpus` / autostress: "process memory: N page faults -> M pages, K pages via kernel copy, brk/mmap".
  W stressie ~0,5 #PF na proces – leniwe strony nie są przyczyną.
- Fault-around (`vm::FAULT_AROUND`, dociąganie sąsiednich stron przy #PF) – zmierzony i wyłączony (1):
  QEMU TCG 1 CPU, 3 × 20 s: 1 strona – 553 skrypty, 16 stron – 515, stara sterta 256 KiB w `.bss` – 541.
  Koszt skryptu na 1 CPU nie wzrósł względem starego alokatora; spadek na Legionie do potwierdzenia
  kolejnym pomiarem (wahania między uruchomieniami / temperatura).

## v0.17.29 — 2026-10-08

### Dodane – M17b kroki c i d: #PF bez IST, pamięć procesu (brk, mmap, leniwe strony)
- #PF bez IST: z ring 3 obsługiwany na stosie kernela zadania (może brać blokady / czekać); przepełnienie
  stosu kernela kończy się #DF (IST) z rozpoznaniem strony-strażnika (ARCH TEST 8/8). Znacznik
  "#PF w trakcie #PF" – per CPU (był wspólny dla wszystkich CPU).
- Pamięć procesu (`kernel/user/vm.rs`): obszary sterty, mmap i stosu; strony przy pierwszym dostępie
  (#PF z ring 3 albo kopiowanie przez kernel). Syscalle `brk` (26), `mmap` (27), `munmap` (28; także
  części obszarów). Stos rośnie leniwie do 8 MiB. #PF procesu bez BKL.
- Biblioteka programów: alokator na brk / mmap zamiast tablicy 256 KiB w `.bss` – każdy proces nie
  mapuje już od razu 64 ramek na stertę; duże bloki (> 64 KiB) – własny obszar mmap, zwalniany munmap.
- FILE TEST 4/4: `/bin/memtest` (23 sprawdzenia: brk, 64 MiB mmap z kilkoma użytymi stronami, częściowe
  munmap, read do niedotkniętych stron, 4 MiB Vec, 20 000 małych alokacji, rosnący stos, #PF po munmap
  i przepełnienie 8 MiB stosu kończą tylko dziecko; ramki wracają). USER TEST 4/9: #PF z ring 3 na
  stosie zadania.

## v0.17.28 — 2026-10-08

### Dodane – M17b kroki a i b: obiekty plików, dup / dup2 / seek, potoki
- Deskryptor wskazuje obiekt: `Fd::File(Arc<OpenFile>)` – kopie (dup, dup2, deskryptory dziecka przy spawn)
  dzielą pozycję, jak w Uniksie. Nowe syscalle: `dup` (22), `dup2` (23), `seek` (24; konsola / potok – ESPIPE).
- Potoki: `pipe` (25) – bufor 64 KiB w kernelu, read czeka na dane (0 = nikt nie pisze), write czeka na
  miejsce (EPIPE, gdy nikt nie czyta), kill / Ctrl+C przerywa czekanie. Proces zamyka deskryptory już przy
  końcu (`exit_current`), nie przy reap.
- Shell: potoki `a | b | c` (programy z /bin oraz echo, pwd, help, history), z przekierowaniami
  (`primes 30 | cat | cat > plik`), w tle (`&` na końcu).
- Biblioteka programów: `dup`, `dup2`, `seek`, `pipe`. Nowe programy testowe `/bin/fdtest`, `/bin/pipetest`.
- Nowy zestaw samotestów FILE TEST (25 zestawów): obiekty plików (24 sprawdzenia), potoki (18 – w tym
  200 KiB przez `cat`, czytający czekający na piszącego), potoki w shellu.

## v0.17.27 — 2026-10-08

### M17a zamknięte
- **Legion** (16 CPU, autostress 60 s) z v0.17.27: **rekord 53 809 skryptów** (v0.17.26: 50 524, +6,5%;
  rekord sprzed g10–g16: 45 802, +17,5%); drzewo ramfs 2,2 s czekania (505 s); BKL 0,23 s; blokada
  schedulera 2% czeka. `SMP=8 ./stress-qemu.sh` (KVM): 41 328 skryptów.
- Warunki "Gotowe, gdy" spełnione: syscalle 99% bez BKL i równolegle (NOBKL TEST 1/9), BKL poza gorącymi
  ścieżkami, stress i samotesty bez błędów. Podsumowanie i otwarte wątki – `roadmapa` (M17a). Następny:
  M17b – obiekty plików + pamięć procesu.

### Zmienione – M17a krok g16: drzewo ramfs pod kręcącą się blokadą czytelnicy–pisarz
- **Legion** (16 CPU, 60 s) z v0.17.26: **rekord 50 524 skrypty** (v0.17.25: 45 606, +10,8%), blokada
  schedulera 2,3 s (6,5 s). Zostało drzewo ramfs: 438 tys. czekań odczytu (30%), 505 s – kręcenie przed
  uśpieniem rozwiązało tylko 31 tys.
- Nowa `spin::RwSpinLock`: wielu czytelników albo jeden pisarz, kręcenie zamiast snu (sekcje drzewa trwają
  µs, a uśpienie i pobudka – dwa przejścia przez scheduler), pierwszeństwo pisarza, wywłaszczanie
  wstrzymane, liczy się jako trzymany spinlock (sen pod nią = panic), wykrywanie zakleszczeń (HPET, 2 s
  raport / 10 s panic). Statystyka w `cpus`: "spin rwlock …" (wzięcia, czekania, czas czekania i trzymania).
- ramfs: drzewo pod `RwSpinLock`; `read_dir` i `stats` nie biorą już blokad plików (usypiających) pod
  drzewem – zbierają Arc plików i czytają rozmiary po zwolnieniu; usunięty węzeł zwalniany poza blokadą.
- QEMU TCG 4 CPU 20 s: czekanie na drzewo ~4,2 s → 42 ms.

## v0.17.26 — 2026-10-08

### Zmienione – M17a krok g15: wait bez przeglądania zadań, krótkie kręcenie przed uśpieniem
- `SMP=8 ./stress-qemu.sh` (KVM) z v0.17.25: **38 352 skrypty** (v0.17.23: 16 560); blokady pomijalne.
- **Legion** (16 CPU, 60 s) z v0.17.25: **45 606 skryptów** (v0.17.19: 37 578, +21%; rekord v0.17.16:
  45 802), 2% idle, BKL 0,24 s, blokada schedulera 12% czeka, 6,5 s (children_of trzyma 4 s – 946 tys.
  przeglądów listy zadań), drzewo ramfs: 30% odczytów czeka, 536 s; tablica procesów 33 s.
- `wait` bez `children_of`: proces liczy żywe dzieci (`Process::live_children`: spawn +1, koniec dziecka −1
  w tej samej sekcji co wpis zombie, przejęte w reparent +n); konkretne dziecko – wyszukanie O(1).
- KMutex / KRwLock: przed uśpieniem 200 × `pause` (kilka µs; `SPIN_ITERS`, w g9 wyłączone). Po g13/g14
  sekcje trwają µs, a uśpienie + pobudka to dwa przejścia przez scheduler. "spun" w raporcie pokazuje,
  ile czekań rozwiązało kręcenie. (QEMU TCG 4 vCPU na 2 rdzeniach – mniej skryptów, jak należy się
  spodziewać przy przeciążonym hoście; miarodajne: KVM i Legion.)

## v0.17.25 — 2026-10-08

### Poprawione – fałszywe zakleszczenie spinlocka (regresja z v0.17.23)
- `./test.sh` (TCG, 4 CPU): PANIC "spinlock 'heap': deadlock (CPU 0 waited > 10000 ms)" w ALLOC TEST –
  raport "czeka 17 364 ms", choć cały przebieg trwał ~19 s. W g13 wykrywanie zakleszczeń (spinlock,
  blokada schedulera, BKL) przeszło z HPET na TSC, a TSC bywa niewiarygodny (TCG, różne TSC rdzeni) –
  dlatego od początku było na HPET. To też tłumaczy pojedyncze FAIL-e samotestów zaraz po buildzie.
- Wykrywanie zakleszczeń / długich czekań znów HPET – czytany dopiero przy pierwszym sprawdzeniu (co 1024 /
  4096 obrotów), nigdy pod blokadą. TSC tylko w statystyce czekania (`clock::tsc_wait_us`: ten sam CPU,
  wynik > 10 s odrzucony).

## v0.17.24 — 2026-10-08

### Poprawione – M17a krok g14: zegar ścienny bez portów CMOS
- `SMP=8 ./stress-qemu.sh` (KVM) z v0.17.23: **16 560 skryptów** (v0.17.22: 6279 – 2,6×), blokada
  schedulera 4% czeka (192 ms), tablica procesów bez czekania. Zostało drzewo ramfs: 441 tys. z 480 tys.
  odczytów czeka (92%), 815 s; 44% idle.
- Przyczyna: `rtc::now()` (znacznik czasu katalogu przy create / mkdir / remove) wołane POD blokadą drzewa
  do zapisu – ~45 operacji na portach CMOS (w KVM każda to wyjście do QEMU), czasem kręcenie, gdy RTC się
  aktualizuje. Przy tym `cmos()` bez blokady między CPU (wspólny rejestr indeksu 0x70).
- RTC czytany raz przy starcie (`rtc::init`); `rtc::now()` = odczyt startowy + uptime (konwersje
  `DateTime::to_unix` / `from_unix`). `rtc::read_hw()` – odczyt sprzętu.
- TIME TEST 7/8 sprawdza konwersje dat (1970, 29.02.2000, 2100) i zgodność zegara z RTC (±2 s).
- QEMU TCG 4 CPU 15 s: czekania na drzewo ramfs 833 → 252, 6,9 s → 2,5 s.

## v0.17.23 — 2026-10-08

### Poprawione – M17a krok g13: pomiar czasu nie wydłuża trzymania blokad
- `SMP=8 ./stress-qemu.sh` (KVM) z v0.17.22: 6279 skryptów; blokada schedulera 87% czeka, 299 s, choć
  trzymana łącznie ~1,3 s (wait_event ~1 µs na wzięcie). Przyczyna: po czekaniu na blokadę (schedulera,
  spinlock, BKL) czas czekania liczony odczytem HPET – już PO wzięciu blokady. HPET to MMIO: w KVM wyjście
  do QEMU (szeregowane między vCPU, dziesiątki µs), na sprzęcie ~1 µs – dłużej niż cała sekcja. Każde
  czekanie wydłużało trzymanie, więc następni czekali dłużej (samonapędzające się). To samo w KMutex /
  KRwLock (tablica procesów, drzewo ramfs): koniec czekania i próbka trzymania czytane pod blokadą.
- Spinlocki, blokada schedulera, BKL: czekanie mierzone TSC (`clock::tsc` / `tsc_us`, ten sam CPU).
  KMutex: trzymanie – TSC + numer CPU (`rdtscp`; zmiana CPU = próbka pominięta). KMutex / KRwLock:
  koniec czekania (HPET) odczytywany po pobudce, PRZED wzięciem blokady.
- QEMU TCG 4 CPU 15 s: tablica procesów trzymana 36 ms (wcześniej ~1,7 s na 20 s).

## v0.17.22 — 2026-10-08

### Zmienione – M17a krok g12: tick bez blokady schedulera + kto ją bierze
- `SMP=8 ./stress-qemu.sh` (KVM) z v0.17.21: **6031 skryptów** (v0.17.20: 5075, +19%), tablica procesów
  536 s czekania (1239 s), ale blokada schedulera 85% czeka, 314 s.
- Tick timera bez blokady schedulera: każdy CPU co 1 ms brał ją tylko po to, żeby policzyć czas CPU
  zadania i kwant (Legion: ~16 tys. wzięć/s). Teraz czas CPU (`cpu_ticks` – atomowy), kwant (per CPU) i
  "są gotowe zadania" (licznik `READY_N`) bez blokady; BSP bierze ją tylko, gdy nadszedł najbliższy termin
  pobudki (`NEXT_WAKE`). QEMU TCG 4 CPU 15 s: `ap_tick` 4535 wzięć → 0, `on_tick` 10 668 → 2667.
- `cpus` / autostress: "scheduler lock by site" – wzięcia, czekanie i trzymanie per funkcja (schedule,
  wait_event, sleep_until, spawn_in, exit, children_of, with_process, on_tick, reap …). Tablica miejsc
  wspólna z BKL (`bkl::SiteTable`).

## v0.17.21 — 2026-10-07

### Zmienione – M17a krok g11: koniec procesu budzi tylko rodzica
- `SMP=8 ./stress-qemu.sh` (KVM) z v0.17.20: PASS, 5075 skryptów, ale tablica procesów: 48% wzięć śpi,
  **1239 s czekania**, trzymana 43 s z 60 s; blokada schedulera 75% czeka. Przyczyny: każdy koniec procesu
  budził WSZYSTKICH rodziców czekających w `wait` (jedna kolejka) – każdy przeglądał listę zadań pod
  blokadą schedulera i brał tablicę procesów; `on_exit` trzymał tablicę procesów, biorąc 3× blokadę
  schedulera (w tym przegląd wszystkich zadań w `reparent`).
- Rodzic czeka w jednej z 64 kolejek wybranej po swoim numerze – koniec procesu budzi jego rodzica
  (i init, gdy przejmuje zombie), nie wszystkich.
- `Process::has_children` – proces, który nigdy nie miał dzieci, kończy się bez `reparent` i bez szukania
  init (pod tablicą procesów zostaje jedno sprawdzenie rodzica).
- QEMU (TCG, 4 CPU, 20 s): czekanie na tablicę procesów 6,8 s → 3,1 s, blokada schedulera 1,5 s → 1,1 s.

## v0.17.20 — 2026-10-07

### Zmienione – M17a krok g10: blokady usypiające budzą jednego czekającego
- Legion z v0.17.19: 37 578 skryptów, blokada schedulera 62% czeka (235 s), tablica procesów 357 s,
  ramfs tree 1108 s. Przyczyna: każde zwolnienie KMutex / KRwLock budziło WSZYSTKICH czekających – stado
  pobudek przez blokadę schedulera, a blokadę i tak bierze jeden.
- KMutex: licznik śpiących; zwolnienie budzi jednego (`WaitQueue::wake_one`, `sched::wake_one_channel`),
  i tylko gdy ktoś śpi.
- KRwLock: osobne kolejki czytelników i pisarzy. Zwolnienie pisarza wpuszcza grupę czekających
  czytelników (albo budzi jednego pisarza), ostatni czytelnik budzi jednego pisarza.
- QEMU: samotesty 24/24 (1, 2, 4 CPU), autostress 20 s na 4 CPU – PASS.

## v0.17.19 — 2026-10-07

### Zmienione – M17a krok f3b: kolejki schedulera bez alokacji
- Legion z v0.17.18 wyszedł gorzej: 36 689 skryptów (41 667), blokada schedulera 79% czeka, 335 s (232 s),
  tablica procesów 768 s. Podejrzenie: f3a trzymała kolejki w BTreeMap / Vec – każde uśpienie i pobudka
  alokowały pamięć pod blokadą heapa (mocno obleganą), z wyłączonymi przerwaniami, trzymając blokadę
  schedulera.
- Kolejki bez alokacji: listy dwukierunkowe wbudowane w zadanie (kolejka gotowych, kubełki kanałów
  WaitQueue – 256, lista zadań z terminem), numer → zadanie w 1024 kubełkach (łańcuch w zadaniu). Tick
  przegląda tylko zadania z terminem. `reap` rezerwuje miejsce na martwe zadania przed wzięciem blokady.
- Nowy `./stress-qemu.sh`: ten sam autostress co na Legionie, ale w QEMU na tym komputerze (KVM, jeśli jest;
  tyle CPU, ile rdzeni, najwyżej 16; `SECS=60` domyślnie) – wynik na ekranie, kod wyjścia 0/1/2, log
  `stress-qemu.log`. Najpierw tu, potem pendrive.

## v0.17.18 — 2026-10-07

### Zmienione – M17a g9 + f3a: bez kręcenia, scheduler bez przeglądania listy zadań
- Legion z v0.17.17: kręcenie przed uśpieniem zaszkodziło – 6% idle (CPU zajęte kręceniem), 41 667 skryptów
  (−9%); drzewo ramfs 910 s, tablica procesów 216 s, **blokada schedulera 65% czeka, 232 s**.
- g9: kręcenie wyłączone (`SPIN_ITERS = 0` w sched/sync.rs; liczniki "spun" zostają).
- f3a: scheduler nie przegląda już wszystkich zadań pod swoją blokadą. Nowe struktury: kolejka gotowych
  (FIFO – round-robin jak dotąd), mapa numer → zadanie, listy uśpionych per kanał WaitQueue, posortowana
  lista terminów. `schedule` – O(1), `wake_channel` – tylko zadania z kanału, tick – tylko przeterminowane,
  `ap_tick` / `on_tick` ("są gotowe?") – O(1), wyszukiwanie zadania – O(log n). `reap` przy spawn tylko,
  gdy są martwe zadania (wcześniej przy każdym). Lista zadań: `swap_remove` przy sprzątaniu.
- QEMU (4 CPU, stress 3 s): ~113 skryptów (v0.17.17: ~100–108).

## v0.17.17 — 2026-10-07

### Zmienione – M17a krok g8: kręcenie przed uśpieniem, kilka pętli stressu
- Legion z v0.17.16: VFS 2 zapisy, 0 czekania (było 668 s). Tłok przeszedł do drzewa ramfs (409 s, ~1 ms na
  jedno czekanie przy sekcjach trwających mikrosekundy – koszt to uśpienie i pobudka przez scheduler) i
  tablicy procesów (114 s). 44% idle, 45 802 skryptów, pętla stressu 90% zajęta.
- KMutex i KRwLock: przy zajętej blokadzie najpierw do 2000 obrotów `pause` (kilkadziesiąt µs, tylko przy
  SMP), dopiero potem sen. `cpus`: "% slept, % spun" (KMutex), "(N by spinning)" (KRwLock).
- Stress: pętle sterujące jako osobne zadania kernela bez BKL – 1 na 4 CPU, najwyżej 4 (Legion: 4), pula 48
  dzielona między nie, każda ma swoje numery zadań. Wynik: "N stress driver(s) X% busy" (średnia).

## v0.17.16 — 2026-10-07

### Zmienione – M17a krok g7: ramfs z własnymi blokadami
- Legion z v0.17.15: 44 946 skryptów (+14%), ale VFS nadal 668 s czekania (710 s) – 405 tys. zapisów
  (mkdir/echo/rm w /stN) zatrzymywało czytelników (exec z /bin), a czytelnik trzymał blokadę przez cały
  plik.
- `ConcurrentFs` (fs/mod.rs): operacje `&self` dla systemów plików z własnymi blokadami, w tym niepodzielne
  `read_all` / `write_whole` / `append`. `FileSystem::concurrent()` – Some dla ramfs, None dla FAT32.
- ramfs: drzewo katalogów pod `KRwLock` ("ramfs tree" w `cpus`) – wyszukanie do odczytu, create / mkdir /
  remove do zapisu; zawartość każdego pliku pod własnym Mutexem (Arc) – kopiowanie danych (np. programu przy
  exec) bez trzymania drzewa i bez blokowania innych plików.
- VFS: operacje na ramfs pod FS_LOCK do odczytu (wszystkie, także zapisy plików); do zapisu tylko montowanie
  i FAT32. `remove` sprawdza punkt montowania i usuwa pod tym samym odczytem.
- `KRwLock` z nazwą rejestruje się przy pierwszym użyciu i wyrejestrowuje przy zwolnieniu (ramfs
  montowany w testach); ramfs "/" najpierw trafia na heap, potem pierwsza operacja.

## v0.17.15 — 2026-10-07

### Zmienione – M17a krok g6: VFS czytelnicy–pisarz
- Legion z v0.17.14: VFS (jeden KMutex) – 2,05 mln wzięć, 31% czeka, **710 s czekania** w 60 s testu (średnio
  ~12 zadań stale śpi w kolejce); pętla stressu 92% zajęta; 64% idle.
- Nowe `KRwLock` (sched/sync.rs): usypiająca blokada czytelnicy–pisarz, reentrant, pisarz w kolejce zatrzymuje
  nowych czytelników, czytelnik → pisarz = panic (zamiast zakleszczenia); stan pod IrqSpinLock.
- FS_LOCK to `KRwLock`. `FileSystem` dostał odczyty współdzielone (`stat_shared`, `read_shared`,
  `read_dir_shared`, `shared_reads`) – ramfs je ma (tylko czytają drzewo), FAT32 nie. stat / read /
  read_dir / read_file (także wczytanie ELF przy uruchamianiu programu) na ramfs biorą blokadę do odczytu,
  wielu naraz; zmiany i FAT32 – do zapisu. `cpus`: "sleeping lock vfs: N reads + M writes, waited ...".
- Czas trzymania KMutex mierzony HPET co 16. wzięcie (×16) zamiast TSC – v0.17.14 pokazała 33 815 s
  trzymania w 60 s testu (trzymający śpi i zmienia CPU, TSC rdzeni Legiona się różnią).
- Stress: `sched::task_exists` (bez kopiowania listy zadań) zamiast `task_info` w pętli sterującej.

## v0.17.14 — 2026-10-07

### Dodane – M17a krok g5: pomiar blokad usypiających
- Legion z v0.17.13: BKL 5,0 s czekania (przed g: 173 s), 0 zgubionych przerwań PIT, blokada schedulera
  55,7 s (było 124 s). Mimo to 63% idle i 38 548 skryptów – zadania czekają śpiąc.
- KMutex z nazwą (`KMutex::new_named`, `Mutex::new_named`): wzięcia, wzięcia z czekaniem (raz na `lock`),
  czas czekania (HPET) i trzymania (TSC). Nazwane: VFS (FS_LOCK), warstwa block, tablica procesów (zombie),
  przechwycone wyjście. `cpus` i ekran autostress: linie "sleeping lock ...".
- Stress: "driver N% busy" w linii PASS – ile czasu pętla sterująca pracuje poza snem 2 ms (blisko 100% =
  stress ogranicza sam siebie). W QEMU (4 CPU): 83%.
- `[NOBKL TEST]` 9/9 wypisuje też linie blokad usypiających.
- Wynik stressu (autostress, komenda `stress`) w kilku krótkich liniach (load / jobs / spin / alloc / BKL)
  zamiast jednej linii szerszej niż ekran (prośba Dawida).

## v0.17.13 — 2026-10-07

### Zmienione – M17a krok g4: przerwania zegara bez Big Kernel Lock
- Legion z v0.17.12 (pełne 60 s, PASS): 58% idle, 39 428 skryptów (nowa pula), BKL 46 s czekania – z czego
  ~38 s to przerwania przerywające kernel (LAPIC timer 26,2 s, PIT 9,7 s, resched IPI 2,6 s). Blokada
  schedulera: 46% wzięć czeka, 124 s (to następny krok – f3).
- Tick PIT, timer LAPIC i IPI przełączenia nie biorą BKL na wejściu (exceptions.rs). Ich praca: licznik
  ticków (atomik), budzenie śpiących i kwant (blokada schedulera), watchdog, hook ticku.
- Odpytywanie klawiatury PS/2 w ticku (dekoder i wejście shella jeszcze pod BKL): tylko gdy przerwany kontekst
  ma BKL albo BKL jest wolny od ręki – nowe `bkl::try_acquire_tagged` (bez stania w kolejce); inaczej przy
  następnym ticku odpytywania (co 5 ms). IRQ1 bierze BKL jak dotąd.
- QEMU (4 CPU, stress 3 s): BKL ~330 wzięć (v0.17.12: ~1,9 tys.), ~100 skryptów (~88).

## v0.17.12 — 2026-10-07

### Zmienione – M17a krok g3: start i koniec procesu bez BKL, mocniejszy stress
- Legion z v0.17.11: czekanie na BKL 36,7 s (v0.17.10: 57,5 s, przed g: 173 s), ale stress w 76% bezczynny.
  Na górze tabeli: syscalle pod BKL 308 tys. (to `exit` – jeden na proces) i start zadania 308 tys. (start
  procesu – BKL brany tylko po to, żeby oddać go przed skokiem do ring 3).
- `exit` bez BKL: SYS_EXIT idzie ścieżką bez BKL, `exit_current` nie bierze BKL (wszystko, czego dotyka,
  ma własne blokady). Przestrzeń adresowa nadal zwalniana w `reap` pod BKL.
- Proces startuje bez BKL (`sched_new_task_start` bierze go tylko dla zadań kernela, `enter_user` oddaje
  tylko, jeśli jest).
- Stress: zadania kernela (spinlocki, alokacje) cały czas bez BKL, także w `sleep_ms` (wcześniej BKL wracał
  co rundę tylko na sen – 187 tys. wzięć "end of bkl::unlocked"). Pula procesów 3 na CPU, najwyżej 48
  (było 2 na CPU, najwyżej 12), bufor przechwyconego wyjścia 128 wpisów. **Liczby skryptów od tej wersji nie
  są porównywalne ze starszymi.** W QEMU (4 CPU): ~88 skryptów w 3 s zamiast ~55, BKL ~1,9 tys. wzięć
  zamiast ~4,2 tys.

### Naprawione (test)
- `[SMP TEST]` 5/5 na KVM raz zgłosił "no xmm process ever moved to another CPU": próbkowanie `cpu_mask` co
  5 ms gubiło migracje procesów, które zdążyły się zakończyć (procesy startują teraz bez BKL i na KVM kończą
  się w kilkadziesiąt ms). Scheduler liczy migracje procesów (`user_migrations`), test sprawdza licznik.
- Legion, pierwszy przebieg mocniejszego stressu: po ~7 s "job 38190 ended with None" – przy ~20 tys.
  procesów/s dziennik zakończeń (256 wpisów) wypychał wpis, zanim pętla stressu go sprawdziła. Teraz
  EXIT_LOG = 2048 (128 KiB), CAPTURED_LOG = 256; stress mówi wprost, gdy wpis już wypadł.
- `[INIT TEST]` 7/9 (u mnie raz): wewnętrzny `sh -c` kończył się, zanim test ustawił init – sierota szła
  do kernela. Skrypt shella-init zaczyna od `sleep 200`.
- Uwaga z tego przebiegu: blokada schedulera czekała w 52% wzięć, 17,5 s w ~7 s testu (~15% czasu 16 CPU) –
  przy tym obciążeniu kolejki per CPU (f3) zaczynają mieć znaczenie.

## v0.17.11 — 2026-10-07

### Zmienione – M17a krok g2
- Legion z v0.17.10: czekanie na BKL 173 s → 57,5 s (−67%), wzięcia 3,85 → 1,57 mln. Liczba skryptów bez
  zmian (39 482) – stress ma stałą pulę 12 zadań i pętlę co 2 ms, więc mierzy opóźnienie zadania, a nie
  przepustowość; na BKL czekały głównie bezczynne CPU.
- Sprząta jeden bezczynny CPU naraz (`REAPER`) – wcześniej wszystkie budziły się i stawały w kolejce do BKL
  po to samo zakończone zadanie (143 tys. wzięć, 78% z czekaniem).
- Wywłaszczenie z przerwania (`preempt_irq`): jeśli przerwany kontekst nie trzymał BKL, po powrocie
  z przełączenia BKL nie jest brany z powrotem – wcześniej brany tylko po to, żeby oddać go przy wyjściu.
- Statystyka: powrót po przełączeniu rozbity na wait_event / sleep / yield / preempt; "% idle" w wyniku
  stressu i linia "idle" w `cpus` (czas w zadaniu idle, liczony w `schedule()` przy przełączeniu).

### Naprawione
- Dziennik zakończeń procesów (`exit_info`) chroniony tylko BKL + IF = 0, a zapisywany także z syscalli
  bez BKL (kill w trakcie syscalla) – dwa zapisy naraz mogły zgubić wpis. Teraz własna `IrqSpinLock`
  (poziom 225, `EXIT_LOG`).

## v0.17.10 — 2026-10-07

### Zmienione – M17a krok g1: pętla idle bez Big Kernel Lock
- Pomiar g0 na Legionie (16 CPU, 60 s): z 173 s czekania na BKL 129 s (74%) to "wake from hlt" – pętla idle
  trzymała BKL, oddawała go na `hlt` i brała z powrotem po KAŻDEJ pobudce (2,37 mln razy, 89% z czekaniem),
  tylko żeby zawołać `reap` i znowu usnąć. Budziły ją głównie IPI TLB shootdown (4,8 mln), które same BKL
  nie biorą.
- Teraz idle działa bez BKL; bierze go tylko na `reap` i tylko gdy są zakończone zadania (licznik
  `DEAD_TASKS`, zwiększany w `sched::exit`, zmniejszany w `reap`). Nowe miejsce w statystyce: "idle: reap
  dead tasks"; start kernela: "boot (kernel_main)".
- Statystyka BKL: bez kalibracji LAPIC (1 CPU) czas trzymania = 0 zamiast liczby taktów TSC.

## v0.17.9 — 2026-10-07

### Dodane – M17a krok g0: kto bierze Big Kernel Lock
- Statystyka BKL per miejsce wzięcia (`bkl.rs`): liczba wzięć, ile czekało, czas czekania i czas trzymania
  (TSC tego samego CPU). Klucz: plik:linia (`#[track_caller]`) albo nazwa (`bkl::tag`). Tablica bez blokad.
- Nazwane miejsca: wejście przerwania rozbite na PIT / LAPIC timer / resched IPI / urządzenia (MSI) /
  wyjątki × przerwany proces albo kernel; powrót po przełączeniu, start zadania, syscall pod BKL, koniec
  procesu, pobudka z `hlt`, koniec `bkl::unlocked`, `yield_if_contended`, start AP.
- `cpus` (i ekran autostress): "BKL by site" – 8 miejsc z największym czasem czekania + trzymania.
- `[NOBKL TEST]` 9/9: wszystkie wzięcia przypisane miejscom, syscall pod BKL policzony, czas trzymania
  mierzony; log testów pokazuje tabelę.

### Uwagi
- W QEMU (4 CPU, samotesty) na górze: powrót po przełączeniu, tick PIT i LAPIC timer przerywające kernel,
  pobudka z `hlt`. Legion: patrz v0.17.10.

## v0.17.8 — 2026-10-06

### Zmienione – M17a krok f2: scheduler bez Big Kernel Lock
- Lista zadań i stan schedulera chroni już tylko blokada schedulera (f1). Bez BKL: czekanie
  (`WaitQueue::wait_until` → nowe `sched::wait_event` – warunek i uśpienie pod blokadą schedulera, pobudka
  z innego CPU nie przepada), budzenie, `sleep`, `yield`, `spawn`, `reap`, `tasks`, `kill`. Wszystkie
  `bkl::with` z e2 usunięte.
- BKL przy przełączeniu zadań (jak `release/reacquire_kernel_lock` w Linuksie 2.x): `schedule()` oddaje go
  tuż przed przełączeniem (`Task::bkl_dropped`), `after_switch()` bierze z powrotem, już po oddaniu blokady
  schedulera; nowe zadanie – w `sched_new_task_start`. Trzymając blokadę schedulera BKL wolno oddać, nie
  wolno na niego czekać.
- Syscalle `sleep` i `yield` bez BKL (`cpus`: nowy licznik „sleep/yield”).
- Strony stosów zadań (`stack-pages`), przechwycone stdout i linia shella na `IrqSpinLock`.
- `[NOBKL TEST]` 7/8: burza pobudek bez BKL (k zadań × 3000 pokoleń) i równolegle `sleep(100)` w procesach;
  8/8: kill procesów śpiących bez BKL – kończą się po chwili, nie po końcu snu.
- `build.sh`: `rustup target add` tylko, gdy targetu brak (build bez sieci).

### Naprawione (w trakcie kroku)
- Zadanie wracało ze snu bez BKL: przerwanie między uśpieniem a `after_switch` zabierało flagę
  `bkl_dropped` i oddawało BKL. `preempt` zachowuje teraz flagę przerwanego kontekstu; `sleep_until`
  i `wait_event` sprawdzają assertem, że kto czekał z BKL, wraca z BKL.
- Zakleszczenie „CPU 2 waits for 'stack-pages', held by CPU 1”: przerwanie w sekcji pod `SpinLock` (IF = 1)
  czekało na BKL, a właściciel BKL czekał na ten SpinLock. Zasada (ARCHITEKTURA.md): blokada brana i z BKL,
  i bez niego musi być `IrqSpinLock`.

- `bkl::held()` odczytywał numer CPU i właściciela z IF = 1 – zadanie przeniesione na inny CPU między
  odczytami dostawało zły wynik (od f2 BKL idzie za zadaniem przez przełączenie): fałszywy panic „wait_event
  returned without the BKL” (~1 na 15 przebiegów testów), a `enable_and_hlt` mógł usnąć z BKL. Teraz odczyt
  z IF = 0.

### Uwagi
- Wejście przerwania (tick zegara) nadal bierze BKL – to krok g.
- QEMU TCG z 8 CPU na hoście z 2 rdzeniami: `[TIME TEST]` 7/8 (ticki względem RTC, przed startem SMP)
  potrafi pokazać ~400–500 ticków/s – host nie nadąża z emulacją; 1, 2 i 4 CPU – 24/24.
- Legion (16 CPU, autostress 60 s): PASS – BKL brany 3,65 mln razy (v0.17.7: ~12 mln), czekanie 171 s;
  blokada schedulera: 19% wzięć czeka, łącznie 9,8 s (~1% czasu CPU); 41 140 skryptów (bez zmian – wąskim
  gardłem nadal BKL). Kolejki per CPU (f3) odłożone na po M17b, następny krok g.

## v0.17.7 — 2026-10-05

### Dodane – M17a krok f1: blokada schedulera (obok Big Kernel Lock)
- Lista zadań i stan schedulera pod własną blokadą (`lock_sched`, `sched/mod.rs`). Na razie brana pod BKL –
  chroni to samo, więc zachowanie się nie zmienia; w f2 BKL zniknie ze ścieżki schedulera.
- Blokada rekurencyjna na tym samym CPU (wake → kick, sleep → block → schedule), zawsze z IF = 0 (bierze ją
  też przerwanie zegara), poza lockdep.
- Trzymana PRZEZ przełączenie zadań: bierze ją stare zadanie w `schedule()`, oddaje nowe – po powrocie ze
  swojego `schedule()` albo w `sched_new_task_start` (task_trampoline, przed `sti`). Głębokość per CPU
  zapisywana w zadaniu (`Task::sched_depth`) i odtwarzana po powrocie, także na innym CPU.
- `sched()` sprawdza assertem BKL i blokadę schedulera; `schedule()` – że następne zadanie nie jest
  bieżącym innego CPU.
- `[NOBKL TEST]` 6/6: ping-pong dwóch zadań przez WaitQueue (2 × 1000 pobudek; zgubiona = zawieszenie) przy
  zadaniach robiących w kółko `yield` na wielu CPU; potem blokada wolna, głębokość 0.
- `cpus`: wzięcia blokady schedulera, czekanie (dziś 0% – pod BKL nikt nie czeka; po f2 to dane do decyzji
  o kolejkach per CPU).

### Uwagi
- Pierwsza wersja testu 6 stała przy 8 CPU: zadania z `yield` trzymały BKL w ciasnej pętli (zadanie kernela
  domyślnie ma BKL) i głodziły resztę. Teraz działają bez BKL, z chwilą pracy między przełączeniami.

## v0.17.6 — 2026-10-05

### Dodane – M17a krok e2: procesy bez Big Kernel Lock
- `spawn`, `wait`, `kill`, `getppid` bez BKL. Tablica zombie (`procs.rs`) już miała własną blokadę (KMutex –
  od e1 bezpieczny na wielu CPU); lista zadań bierze BKL tylko na chwilę: publiczne funkcje schedulera
  (`spawn`, `reap`, `tasks`, `task_info`, `with_process`, `children_of`, `reparent`, `request_exit`,
  `current_on`...) przez `bkl::with`.
- `sched()` sprawdza assertem, że BKL jest wzięty – dostęp do listy zadań bez BKL to czytelny panic
  (raporty błędów: `sched_raw`).
- Spawn: wczytanie ELF i budowa przestrzeni adresowej bez BKL; utworzenie zadania i wpis na pierwszy plan –
  razem pod BKL, więc dziecko nie ruszy, zanim Ctrl+C je zobaczy (luka z `[INIT TEST]` 8/9 zamknięta).
- `[NOBKL TEST]` 5/5: 4 shelle naraz uruchamiają po 15 programów (spawn + wait), każdy wypisuje się, zero
  zombie. `cpus`: licznik syscalli procesowych bez BKL. W stressie ~97% syscalli bez BKL (v0.17.5: ~89%).
- Pod BKL zostają: exit (koniec zadania = scheduler), klawiatura, sleep, yield, tasks, kcmd.

## v0.17.5 — 2026-10-05

### Dodane – M17a krok e1: VFS, warstwa block i syscalle plikowe bez Big Kernel Lock
- `KMutex` (blokada usypiająca VFS i warstwy block) bierze właściciela przez `compare_exchange` – wcześniej
  wystarczało `without_interrupts`, bo w kernelu był jeden CPU naraz.
- `bkl::with(f)` – kod bez BKL wchodzi do schedulera tylko na chwilę: `WaitQueue::wait_until` (sprawdzenie
  warunku i uśpienie pod BKL – pobudka z innego CPU nie przepada), `wake_channel`, `sleep_until`, `yield_now`;
  `sched::exit` i `exit_current` biorą BKL same. `schedule()` sprawdza assertem, że BKL jest wzięty.
- `current_id`, `current_process`, `should_exit`, `can_block` – przez wskaźnik per CPU, bez listy zadań.
- Bez BKL idą też: `open`, `close`, `read` z pliku albo z bufora stdin, `readkey` z bufora, `write` do pliku,
  `stat`, `readdir`, `mkdir`, `unlink`, `chdir`, `getcwd`. Pod BKL zostają: exit, spawn, wait, kill, getppid,
  klawiatura, sleep, yield, tasks, kcmd.
- `[NOBKL TEST]` 4/4: 4 shelle naraz dopisują po 41 linii do własnych plików (`echo >>`), treść dokładna.
- `cpus`: licznik syscalli plikowych bez BKL. W stressie ~89% syscalli bez BKL (v0.17.4: ~45%).

### Poprawione
- Dziennik przechwyconego wyjścia (testy): zapisuje tylko proces, który utworzył bufor (albo jego ostatni
  właściciel) – dzieci dziedziczące bufor wypychały wpis rodzica z dziennika 32 wpisów (SMP TEST 4 przy 8 CPU:
  "sh 4 output lacks hello4"). Dziennik: 64 wpisy.
- `[INIT TEST]` 8/9 (u Dawida raz "foreground 0 is not primes"): shell rejestruje dziecko na pierwszym planie
  tuż po utworzeniu zadania, a test na innym CPU widział zadanie "primes" chwilę wcześniej – test czeka teraz
  na oba warunki. (W tym oknie Ctrl+C nie trafiłby jeszcze w nowy program – do poprawy przy e2.)
- `[ALLOC TEST]` 2/3: zapas na tablice stron obszarów kernela 32 → 64 ramek (raz u mnie brakowało 34 – sloty
  stosów do 2000 zadań; wyciek dałby ramki na każdą rundę, nie stałą kilkudziesięciu).

## v0.17.4 — 2026-10-05

### Dodane – M17a krok d: pierwsze syscalle bez Big Kernel Lock
- `getpid`, `uptime` i `write` na konsolę (ekran albo przechwycone stdout) nie biorą BKL – ścieżka
  `try_fast` w `syscall_dispatch`, przed `bkl::acquire`. Wszystko inne (pliki, spawn, wait, read, sleep)
  oraz kill / zły adres powrotu – zwykłą ścieżką pod BKL.
- `sched::current_unlocked`: wskaźnik per CPU na strukturę bieżącego zadania (ustawiany przy
  przełączeniu) – zadanie i jego proces bez przeszukiwania listy zadań (ta zmienia się pod BKL);
  `should_exit_unlocked` – kill / Ctrl+C bez BKL.
- Przechwycone stdout procesów i linia edytowana przez shell na `SpinLock` (poziom 100, `OUTPUT`) zamiast
  usypiającego Mutexa (ten wymaga schedulera, czyli BKL).
- Framebuffer: właściciel (numer CPU) zamiast samej flagi – inny CPU czeka na koniec rysowania (do 50 ms)
  zamiast gubić tekst na ekranie; ten sam CPU w środku rysowania (wyjątek) dalej pisze tylko na serial.
- Programy testowe `lines` (2000 × write) i `pidloop` (getpid bez końca).
- `[NOBKL TEST]` 1–3: 4 × 100 000 getpid przy ~150 wzięciach BKL w tym czasie (rejestry przeżywają
  syscall), 4 procesy × 2000 linii naraz do przechwyconego stdout – każda linia cała, kill procesu, który
  robi wyłącznie syscalle bez BKL.
- `cpus`: ile syscalli poszło bez BKL (getpid / uptime / write) i ile pod BKL. W stressie ~45% bez BKL.

## v0.17.3 — 2026-10-05

### Dodane – M17a krok c: heap i alokator ramek bez Big Kernel Lock
- Heap kernela i alokator ramek na własnych `IrqSpinLock` (zamiast samego `without_interrupts` + BKL):
  alokacje i zwalnianie działają na wielu CPU naraz, także z kodu bez BKL i z handlerów przerwań.
- Poziomy blokad przestawione: heap 230, ramki 240, TLB 250, konsola 255 – alokować wolno z każdego
  miejsca (także z przerwania, które wskoczyło w sekcję pod dowolnym SpinLockiem), więc alokatory muszą
  być prawie najbardziej wewnętrzne. Tabela w ARCHITEKTURA.md.
- Heap powiększa się (`map_page` w swoim obszarze PML4[384]) i zmniejsza (unmap + TLB shootdown) bez BKL –
  tablice tego obszaru zmienia tylko heap, pod swoją blokadą; czekający na blokadę heapa potwierdzają
  shootdown w pętli czekania.
- `[ALLOC TEST]` 1–3: 4 zadania bez BKL × 12 × 640 KiB (heap rośnie i maleje równolegle, dane całe),
  małe bloki + ramki na kilku CPU, alokacje w przerwaniu zegara, w tym czasie tworzenie i kończenie zadań
  (stosy w innym obszarze kernela); nic nie ginie, 0 raportów zakleszczeń.
- Stress test: zadania na spinlockach robią też rundy alokacji heapa i ramek bez BKL (wzór zależny od
  zadania – nadpisanie przez inny CPU = FAIL), przerwanie zegara alokuje. Raport: "heap + frame allocs
  without BKL". Uwaga: przez dodatkową pracę liczba skryptów w stressie nie jest wprost porównywalna
  z v0.17.2.

### Poprawione
- TIME TEST 8 (heap pod obciążeniem przerwaniami) stał u Dawida (QEMU TCG, timeout 180 s): w ciasnej
  pętli alokacji pod nowym `IrqSpinLock` przerwania były włączone tylko przez kilka instrukcji między
  `sti` a kolejnym `cli`, a TCG sprawdza przerwania na granicach bloków kodu – przerwanie zegara nie
  trafiało w okno, więc licznik przerwań i ticki stały. Pętla testu ma teraz co rundę krótkie okno
  z IF = 1 i limit czasu z HPET (zamiast zawieszenia – czytelny FAIL).

## v0.17.2 — 2026-10-04

### Dodane – M17a krok b: TLB shootdown
- `kernel/arch/x86_64/tlb.rs`: wektor IPI 0x43, jedno żądanie naraz (zakres albo pełny flush, maska CPU,
  które jeszcze nie potwierdziły). Handler bez BKL i bez blokad (inicjator zwykle trzyma BKL). CPU czekające
  z IF = 0 – na BKL, na spinlock, na konsolę, na samą blokadę żądania, w raporcie watchdoga – obsługują
  żądanie same (`tlb::poll`), więc nie ma zakleszczenia "czekam na BKL / czekam na potwierdzenie".
  Raport po 1 s czekania (kto nie odpowiada). Powyżej 32 stron – pełny flush (CR3).
- `paging::unmap_range_free`: PTE → shootdown → dopiero `free_frame`, paczki po 32 strony (jeden shootdown
  na paczkę); `unmap_page` w górnej połowie też robi shootdown. Zwolnione tablice stron = pełny flush.
- Zdjęte obejścia z M17: heap znowu oddaje strony przy SMP, tablice stron kernela znowu zwalniane,
  CR3 przeładowywany tylko przy zmianie przestrzeni adresowej (wcześniej przy każdym przełączeniu).
  Dolna połowa (procesy) bez shootdownu – proces jest jednowątkowy, a CPU, który go opuszcza, ładuje inny
  CR3; wątki (M17b) będą wymagały maski `active_cpus`.
- `map_mmio` / podział strony 2 MiB / write-combining – shootdown na wszystkie CPU.
- Start AP: pełny flush TLB po wzięciu BKL (w trakcie czekania BSP mógł zdjąć mapowania).
- `[TLB TEST]` 1–5: potwierdzenia od wszystkich CPU; kontrola, że BEZ shootdownu czytelnik na innym CPU
  naprawdę widzi starą stronę (QEMU TCG: tak – test coś sprawdza); przemapowanie widoczne zaraz po
  shootdownie; 4 inicjatorów naraz bez BKL; heap rośnie i oddaje strony przy SMP.
- `cpus`: statystyka shootdownu (żądania, pełne flushe, IPI, potwierdzenia, ile w pętlach czekania, czas)
  i liczba ticków doliczonych z HPET.
- Automatyczny stress test po starcie: `DESOOS_AUTOSTRESS=60 ./make-usb.sh /media/...` albo
  `./build.sh --autostress=60` – 5 s po starcie stress test, potem wynik, `cpus` i `mem` na ekranie
  (laptop bez działającej klawiatury USB).

### Poprawione
- Czas systemu przy SMP: ticki doganiają HPET. CPU 0 czekający na BKL z IF = 0 gubił przerwania PIT –
  u mnie (4 CPU na 2 rdzeniach) ginęło ~60% przerwań, `stress 30` trwał ~115 s. Przerwanie PIT jest teraz
  "budzikiem" (co najmniej 1 tick), brakujące ms dolicza HPET; czas CPU i kwant według zegara. Na jednym CPU
  (samotesty przed SMP) bez zmian.
- TLB: znalezione testem 4/5 – cele shootdownu liczone z IF = 1 (zadanie przenosiło się na inny CPU i czekało
  na potwierdzenie od samego siebie); `poll` z IF = 1 mógł skasować bit następnego żądania bez flusha.
- Dziennik zakończeń procesów 64 → 256 wpisów (SMP TEST 4 przy 8 CPU: "exit info missing").
- TIME TEST 8 liczy przerwania zamiast ticków.

## v0.17.1 — 2026-10-04

### Dodane – M17a krok a: narzędzia do zdejmowania Big Kernel Lock
- `kernel/sched/spin.rs`: `SpinLock<T>` (wstrzymuje wywłaszczanie CPU) i `IrqSpinLock<T>` (wyłącza
  przerwania, przywraca IF). Lockdep-mini: poziomy i kolejność blokad, rekurencja na tym samym CPU,
  przełączenie zadania ze spinlockiem (panic w `schedule()`), raport zakleszczenia po ~6 mld taktów TSC
  (kto czeka i gdzie, kto trzyma, od kiedy i skąd), panic po 5x tyle.
- Licznik wywłaszczania i flaga "w przerwaniu" per CPU (`cpu.rs`); `preempt()` czeka, gdy CPU trzyma
  spinlock.
- `bkl::unlocked(f)` – kod kernela bez BKL. Przerwanie w takim kodzie bierze BKL na czas handlera i oddaje
  go przy powrocie (stan BKL należy do przerwanego kontekstu).
- **Watchdog zawieszeń** (`smp.rs`): zegar PIT stoi 10 s → NMI do wszystkich CPU, raport: RIP, IF, bilet
  BKL każdego CPU. Sprawdzany w pętlach czekania (BKL, spinlocki) i w ticku zegara (przed BKL).
- Statystyka BKL i spinlocków w `cpus` (ile wzięć, ile z czekaniem, ile taktów czekania).
- TSC kalibrowany razem z timerem LAPIC (log `[APIC]`).
- Stress test SMP (`kernel/user/stress.rs`): pula procesów (shell: katalogi, pliki, spawn/wait;
  `primes`), procesy `xmm`, zadania kernela na spinlockach bez BKL, hook ticku na `IrqSpinLock`;
  sprawdza wyniki, liczniki co do sztuki, raporty zakleszczeń, sprzątanie zadań i wycieki ramek.
  Komenda `stress [s]` (domyślnie 10 s).
- Samotesty `[LOCK TEST]` 6/6 i `[STRESS TEST]` 1/1 (21 zestawów).
- `test.sh`: zmienna `SMP` (domyślnie 4).

### Naprawione
- `preempt_disable`: odczyt numeru CPU i zwiększenie licznika nie były niepodzielne – tick zegara
  pomiędzy przenosił zadanie na inny CPU, a licznik rósł na starym (znalezione przez stress test:
  "task switch while holding a spinlock").
- Kolejność blokad w stress teście: blokada z handlera przerwania musi być wyżej niż blokady trzymane
  z włączonymi przerwaniami (wychwycone przez lockdep) – zasada spisana w ARCHITEKTURA.md.
- TIME TEST 5/8: wyścig w samym teście (odczyt licznika przed `cli`).
- SMP TEST 3/5 przy 2 CPU (równoległość procesów wymaga >= 3 CPU, jeden zajmuje test).
- Watchdog (po teście na komputerze Dawida): fałszywe "PIT clock stuck" przy działającym zegarze –
  wspólna para (ostatni tick, TSC) pisana przez kilka CPU rozjeżdżała się; teraz każdy CPU śledzi zegar
  sam. Raport podaje też różnicę TSC między rdzeniami; pełne raporty najwyżej 3 na uruchomienie.
- Watchdog: spóźnione NMI szło zwykłą ścieżką i brało BKL, na który ten CPU już czekał (panic "nested
  acquire"). NMI nigdy nie bierze BKL; każdy CPU wie, czy NMI było dla niego.
- **Zegar odcinków czasu na HPET** (`arch/x86_64/clock.rs`, tablica ACPI HPET; 32- i 64-bitowy licznik):
  watchdog, detektor zakleszczeń spinlocków, czas trzymania i czekania na BKL. Wcześniej TSC – na komputerze
  Dawida (QEMU/TCG) liczniki TSC wirtualnych CPU różniły się o skoki ~2,5 s (czasy odpowiedzi na NMI równo
  1x, 2x, 3x, 5x 2535 ms), co dawało fałszywe "zegar stoi" i fałszywy panic "deadlock" w stress teście.
  Bez HPET – TSC jak dotąd. `cpus` podaje czekanie na BKL w ms.
- **Martwe zadania sprzątane przy każdym `spawn`** (wcześniej tylko w pętli idle). Przy wielu CPU pod
  obciążeniem idle prawie nie działał i zakończone zadania (stos 64 KiB + pamięć procesu) piętrzyły się:
  `stress 30` u Dawida kończył się "out of memory" (2308 martwych zadań naraz), a powłoka testowa wykonywała
  swój skrypt na konsoli. Po poprawce: `stress 150` = 7948 skryptów + 3973 `primes`, pamięć wraca do stanu
  sprzed testu. `mem` pokazuje zajęte sloty stosów; `stress` podaje prawdziwy powód błędu startu procesu.
- **SYSRET na AMD** (KVM na Ryzenie, a więc i Legion): STAR[63:48] = 0x13 (RPL 3 w selektorze, jak Linux)
  zamiast 0x10. Intel sam wymusza RPL 3, AMD nie – SS po SYSRET było 0x18 i najbliższy powrót z przerwania do
  procesu (`iretq`) dawał #GP(0x18) w kernelu (samotest 3 x 100 000 syscalli pod `ACCEL=kvm`).
- Przy wielu CPU tablice stron górnej połowy nie są zwalniane przy `unmap_page` (inny CPU mógłby mieć w TLB
  wpis zwolnionej tablicy – do TLB shootdown w kroku M17a.b).
- FPU TEST 2/5: próg przełączeń 6 zamiast 20 (pod KVM procesy kończą się w kilku kwantach).
- **BKL: przerwanie oddaje BKL tylko, gdy przerwany kod go trzymał.** Wcześniej przerwanie, które obudziło
  bezczynny CPU z `hlt`, brało BKL, a w `after_interrupt` od razu go oddawało i stawało w kolejce jeszcze raz
  – przy każdym ticku każdego CPU. BKL krążył tysiące razy na sekundę, a bezczynne CPU brały gotowe zadania
  po sekundach zamiast milisekund (znalezione dzięki testowi 2/5 na komputerze Dawida: 11 204 przekazania
  BKL w 2,8 s; po poprawce drugi CPU przejmuje pracę po 1–8 ms).
- SMP TEST 2/5: spinnery kończą się same – gdy razem były na >= 2 CPU albo po 10 s (wcześniej czekały na STOP
  od zadania testowego, które przy wolnym przekazywaniu BKL było zagładzane – na komputerze Dawida test stał
  minutami); rdzenie, na których działały, zapisują same (pomysł Dawida); test podaje, po ilu ms drugi CPU
  przejął pracę.
- Watchdog: drugi czujnik – CPU czeka na BKL dłużej niż 10 s (HPET) → pełny raport (zegar przy tym może iść).
- Tick zegara liczony przed BKL (`time::pit_tick_early`): czas systemu idzie dokładnie także przy kolejce
  do BKL, a watchdog zgłasza tylko prawdziwy brak przerwań zegara. Test 6/6 maskuje IRQ0.
- `test.sh` / `run-qemu.sh`: `ACCEL=kvm` (wirtualizacja sprzętowa – prawdziwe równoległe CPU) i domyślne
  `-accel tcg,thread=multi`. U Dawida QEMU odpowiadał na NMI po 2,5–5 s – wirtualne CPU wykonywały się
  po kolei, a BKL przekazywany "po kolei" dawał sekundowe przestoje i przekroczony limit testów.
- Raport watchdoga: gdzie i od kiedy właściciel trzyma BKL; licznik wywłaszczania, spinlocki, przerwanie
  i bieżące zadanie każdego CPU.
- BSP w idle bierze gotowe zadania także w swoim ticku (PIT) – wcześniej robiły to tylko AP (`ap_tick`),
  a BSP czekał na IPI, które przy zajętych pobudkach mogło nie przyjść.
- SMP TEST 2/5: zrzut stanu, gdy po 3 s żaden drugi CPU nie przejął pracy (BKL: bilety i właściciel,
  każdy CPU: bieżące zadanie, NEED_RESCHED, ticki LAPIC, IPI, czekanie na BKL; każdy spinner) –
  diagnostyka rzadkiego FAIL "CPU mask 0b10" pod TCG z 4 CPU.
- Konsola: cała linia logu wypisywana na raz (własna blokada wyjścia, wywłaszczanie wstrzymane na czas
  linii). W `stress` komunikaty dwóch CPU mieszały się w połowie linii. Blokada nie może zawiesić
  systemu: ten sam CPU wchodzi ponownie (panic/NMI w trakcie), obcy czeka najwyżej ~20 ms.
- HPET: 64-bitowy licznik czytany jako górna/dolna/górna połowa (QEMU dzieli 64-bitowy odczyt na dwa
  32-bitowe – przy przeniesieniu wynik skakał o 2^32 taktów). Skutek u Dawida: "368934882128455 ms"
  czekania na BKL w `cpus` po `stress 300`. Ujemny odcinek liczony jako 0, nie 2^64.
- `cpus`: czas czekania na BKL opisany jako suma po wszystkich CPU.
- SMP TEST 2/5 (przyczyna rzadkiego FAIL "CPU mask 0b10/0b1000" pod TCG, znaleziona dzięki zrzutowi stanu
  z logu Dawida): spinner trzymał BKL cały czas (oddawał go tylko w ticku co 10 ms), więc zadanie testowe
  tworzyło kolejne spinnery po kawałku, a BSP czekał na BKL z wyłączonymi przerwaniami i gubił ticki PIT –
  "10 s" testu trwało 99 s, spinnery 1–3 startowały po terminie. Teraz spinnery kręcą się bez BKL, startują
  razem (po utworzeniu wszystkich), a termin i "second CPU after" liczy zegar HPET.

### Uwagi
- Znany problem (do M17a): CPU 0 czekający na BKL z wyłączonymi przerwaniami gubi przerwania PIT, więc przy
  dużym zatorze czas systemu (`uptime`, `sleep`) się spóźnia. Naprawa: ticki doganiające zegar HPET albo
  krótsze trzymanie BKL (kolejne kroki M17a).
- `[NVME TEST] FAIL: partition not found after writing GPT` w `run-qemu.sh` z buildem `--selftest` to nie
  błąd: `run-qemu` używa trwałego `nvme.img` (GPT z poprzedniego uruchomienia już jest), a test zakłada
  pusty dysk, jaki daje `test.sh`. Do testów ręcznych: zwykły `./build.sh`.
- Wcześniejsze wyjaśnienie raportów watchdoga jako "przestojów emulatora" okazało się w dużej mierze
  błędne – większość była fałszywymi alarmami (patrz wyżej). Przy 4 wirtualnych CPU na 2 rdzeniach hosta
  przekazywanie BKL nadal bywa wolne (np. 3 x 100 000 syscalli), więc na słabym hoście: `SMP=2 ./test.sh`.

## v0.17 — 2026-10-04

### Dodane
- **M17: ACPI MADT, I/O APIC, timer LAPIC, SMP – wszystkie rdzenie pracuja.**
  - `acpi.rs`: MADT – rdzenie (LAPIC i x2APIC), I/O APIC, przekierowania przerwan ISA; widac w `acpi`.
  - `ioapic.rs`: linie ISA (zegar, klawiatura, serial, mysz) przez I/O APIC (wektor 0x20 + IRQ, do BSP),
    PIC 8259 calkowicie zamaskowany, EOI do LAPIC. virtio-blk przeszedl z INTx na MSI-X.
  - `smp.rs`: start AP przez INIT-SIPI-SIPI – trampolina pod 1 MiB (ramka rezerwowana przy starcie
    alokatora), z trybu rzeczywistego od razu do 64 bitow, tymczasowa PML4 ponizej 4 GiB.
    Kazdy AP: wlasna GDT/TSS ze stosami IST ze straznikami, IDT, FPU, SMEP/SMAP, PAT (WC), SYSCALL,
    LAPIC i timer LAPIC 100 Hz (kalibrowany zegarem PIT).
  - `cpu.rs`: numer procesora z RDTSCP (MSR TSC_AUX), do 16 CPU.
  - `sched/bkl.rs`: **Big Kernel Lock** (ticket lock) – kernel wykonuje jeden CPU naraz, procesy w ring 3
    rownolegle. Brany przy wejsciu do kernela (syscall, przerwanie, wyjatek), oddawany przy powrocie do
    ring 3, na czas `hlt` i w ticku zegara, gdy inny CPU czeka.
  - Scheduler per CPU: `current`, kwant, zadanie idle (przypiete), NEED_RESCHED; gotowe zadanie budzi
    bezczynny rdzen przez IPI. TSS.RSP0 i blok SYSCALL (KERNEL_GS_BASE) per CPU.
  - TLB bez shootdown: przy wielu CPU pelny flush przy kazdym przelaczeniu, heap nie oddaje stron.
  - Panic zatrzymuje pozostale rdzenie (IPI).
  - Komenda `cpus`; kolumna `CPU` w `ps` (shell kernela i `/bin/ps`; syscall `tasks` ma nowe pole).
  - `test.sh` i `run-qemu.sh`: `-smp 4` (`run-qemu.sh` takze `-cpu max`).
  - Samotesty `[SMP TEST]` 5/5 (19 zestawow): 4 CPU online i timery LAPIC, zadania kernela na wszystkich
    rdzeniach, 4 x `primes` naraz, 8 shelli naraz (spawn/wait/VFS), 8 procesow xmm migrujacych miedzy
    rdzeniami bez wycieku rejestrow. Test bramek IDT obejmuje wektory 0x40-0x42.

### Prawdziwy sprzet
- Lenovo Legion 5 (Ryzen 7 4800H): **16 CPU online** – MADT z APIC id 0-15 (xAPIC), wszystkie AP wstaly
  za pierwszym razem, timer LAPIC 6237 taktow/ms (magistrala ~100 MHz).

### Uwagi
- Caly wczesniejszy zestaw testow przechodzi takze z SMP wlaczonym od startu (poza testami liczacymi
  przelaczenia na jednym rdzeniu). W QEMU (4 wirtualne CPU na 2 rdzeniach hosta) przekazywanie BKL jest
  wolne: 3 x 100 000 syscalli trwa ~48 s zamiast ~1 s – na prawdziwym sprzecie to ~100 ns na przekazanie.
- Drobne blokady zamiast BKL i TLB shootdown – przed M18 (roadmapa).

## v0.16.1 — 2026-10-04

### Test na prawdziwym sprzecie (Lenovo Legion 5 15ARH05H, Ryzen 7 4800H)
- DeSoOS startuje z pendrive'a: ACPI, ECAM, 36 urzadzen PCI, NVMe SK hynix (tylko do odczytu),
  partycje GPT, `/esp` read-only, init + shell. Klawiatura laptopa jest na USB (ITE 8910) - bedzie po M20.

### Naprawione
- DSB: "more than 512 GiB of RAM is not supported" na laptopie z 16 GB - framebuffer grafiki Ryzena lezy
  ~2 TiB wysoko. DSB mapuje teraz tylko obszary z mapy UEFI (RAM, ACPI, firmware) i framebuffer, do 64 TiB.
- PS/2: inicjalizacja jak w Linuksie na x86 - bez testu kontrolera (0xAA/0xAB) i resetu klawiatury (0xFF),
  ktore psuja emulacje 8042 w EC czesci laptopow; odpytywanie portu co 5 ms, gdy IRQ1 nie dochodzi.

### Dodane
- Pasek stanu w prawym gornym rogu (tylko bez portu szeregowego): czas od startu, bajty klawiatury
  (IRQ / odpytywanie), rejestr stanu 8042 - widac, czy system zyje.
- `irq` pokazuje tez bajty klawiatury (IRQ1 / odpytywanie) i liczniki MSI.

## v0.16 — 2026-10-03

### Dodane
- **M16b: NVMe, PCIe ECAM, MSI-X, GPT – przygotowanie do startu na prawdziwym komputerze.**
  - DSB przekazuje adres RSDP (tablica konfiguracyjna UEFI) – `BootInfo.acpi_rsdp`, magic `DSBOOT11`.
  - `kernel/acpi.rs`: RSDP -> XSDT/RSDT, sumy kontrolne, lista tablic, MCFG; komenda `acpi`.
    Tablice mapowane tylko do odczytu (`memory::map_firmware`).
  - PCI: PCIe ECAM z MCFG – wlaczane po sprawdzeniu, ze odczyty zgadzaja sie z portami 0xCF8/0xCFC;
    rozszerzona konfiguracja `read32_ext`; bez MCFG - porty jak dotad.
  - `arch/x86_64/lapic.rs`: Local APIC (xAPIC i x2APIC) w minimalnym zakresie - EOI dla MSI; PIC dziala
    dalej przez "virtual wire". `arch/x86_64/msi.rs`: wektory 0x30-0x3F (bez IST), spurious 0xFF.
  - PCI `enable_msix` / `enable_msi`.
  - `drivers/nvme.rs`: reset i wlaczenie kontrolera, kolejki admin + I/O (64 wpisy), Identify, pierwsza
    aktywna przestrzen nazw, bloki 512 B i 4 KiB (z read-modify-write), PRP i listy PRP, bufor DMA 128 KiB,
    polecenia po max 32 KiB (albo MDTS) - kilka naraz w kolejce, MSI-X / MSI / odpytywanie.
  - **Ochrona danych:** zapis tylko do kontrolera QEMU (1b36:0010); prawdziwy SSD = tylko do odczytu
    w sterowniku, a warstwa block niezaleznie odrzuca zapis na dysk tylko do odczytu (takze `mkfs`,
    `disk write`, pliki). System plikow zglasza wtedy EROFS ("read-only file system").
  - `kernel/gpt.rs`: GPT (ochronny MBR, naglowek i tablica z CRC32, bloki 512/4096); partycje jako osobne
    dyski (`nvme0n1p1`...) z typem i nazwa; pierwsza partycja EFI System z FAT32 montowana w `/esp`.
  - `make-usb.sh`: `--list`, wgranie DeSoOS na zamontowany pendrive FAT32 (sprawdza: USB, nie dysk
    systemowy, vfat, nie nadpisuje obcego bootloadera), opcjonalnie `--format /dev/sdX` z potwierdzeniem.
  - README: start na prawdziwym komputerze, BIOS (Secure Boot, BitLocker), dlaczego dane sa bezpieczne.
  - Samotesty `[NVME TEST]` 9/9: ACPI + MCFG, ECAM == porty + rozszerzona konfiguracja, LAPIC + MSI-X,
    rejestracja NVMe, zapis/odczyt z przywroceniem i przerwaniami, kolejka (4 polecenia naraz), ochrona
    zapisu (block + sterownik + mkfs), GPT -> partycja -> FAT32 -> /esp, partycja tylko do odczytu.
    Razem 18 zestawow.

### Naprawione
- **Brak portu szeregowego (laptopy) zawieszal start**: `enable_rx_interrupts` czekal w nieskonczonosc
  na pusty odbiornik (port bez UART czyta 0xFF). Teraz UART jest wykrywany (rejestr scratch) – bez niego
  serial jest wylaczony, a test petli zwrotnej pomijany.
- QEMU: `build/` byl dyskiem `fat:rw:` – OVMF zapisywal tam NvVars, a vvfat potrafil przy tym uszkodzic
  `BOOTX64.EFI` (start konczyl sie w shellu UEFI). Teraz `build/` to pendrive USB tylko do odczytu.

### Zmienione
- Wspolny koniec przerwania (`irq::after_interrupt`) dla IRQ i MSI.
- `test.sh` / `run-qemu.sh`: dysk NVMe (`build-test-nvme.img` / `nvme.img`), start z USB.
- Wersja 0.16.0.

## v0.15 — 2026-10-03

### Dodane
- **M16: init + shell w user space.**
  - Kernel po starcie uruchamia tylko `/bin/init` (`user::run_init`) i go pilnuje: gdy init sie
    skonczy - start od nowa; brak pliku albo 3 konce w 10 s - awaryjny shell kernela.
  - `/bin/init`: uruchamia `/bin/sh`, zbiera zakonczone procesy (takze sieroty), po wyjsciu albo
    zabiciu shella uruchamia nowy. Init jest chroniony (`kill` -> EPERM).
  - `/bin/sh` (ring 3): edycja linii jak w shellu kernela (strzalki, historia, Tab z /bin i komendami
    kernela, Ctrl+C/U/L, Ctrl+D = wyjscie), slowa w cudzyslowach, `> plik`, `>> plik`, `< plik`, `&`
    (koniec programu w tle zglaszany przed promptem), wbudowane `cd pwd echo exit help history clear
    wait k`, programy po nazwie (`/bin/<nazwa>`) albo sciezce (`./a`), `sh -c "..."`. Prompt
    `desoos:/$` (shell kernela ma `>`).
  - Nowe programy: `ls ps kill mkdir rm touch cp mv stat sleep` (`user/lib/copy.rs` dla cp/mv).
  - Komendy diagnostyczne kernela (mem, lspci, disk, mkfs, df, date, run...) dzialaja w shellu
    procesu wprost albo jako `k <komenda>` - syscall `kcmd` (tymczasowy most, wyjscie respektuje `>`).
  - Rodzina procesow (`kernel/user/procs.rs`): rodzic (`Process.ppid`), zombie z kodem wyjscia do
    czasu `wait`, sieroty do init (bez init - do kernela), wszystko pod jedna blokada, wiec dziecko
    konczace sie razem z rodzicem nie ginie. Status: kod 0..255 albo 0x100 | powod (9 = kill).
  - Syscalle 9-21: spawn (argv, flaga FOREGROUND, deskryptory dla 0/1/2 dziecka), wait (dowolne
    dziecko, WNOHANG), getppid, kill, chdir, getcwd, readdir, stat, mkdir, unlink, readkey (surowe
    klawisze dla edytora linii, z odrysowaniem linii przy komunikatach z tla), tasks, kcmd.
  - Ctrl+C: stos procesow pierwszego planu - konczy program z wierzchu, a nie shell (takze shell
    w shellu). Shell wypisuje `^C`.
  - Biblioteka `user/lib/desoos.rs`: spawn/wait/kill/..., `Key` + `readkey`, sterta (alokator klas
    rozmiarow na 256 KiB w .bss) - program z `extern crate alloc;` ma `Vec`/`String`.
  - Samotesty `[INIT TEST]` 9/9: stosy IST ze straznikami, podzial strony 2 MiB, stos pierwszego
    planu, skrypt shella (wbudowane, programy, przekierowania, cudzyslowy, edycja i historia, `k`,
    kod wyjscia), brak zombie, sierota bez init i z init, kill(init) = EPERM, Ctrl+C konczy program
    a nie shell, brak wycieku ramek. Razem 17 zestawow.
- **Porzadki przed M16:**
  - Niezmiennik `irq::dispatch -> preempt() -> kill_from_interrupt` opisany w kodzie (IRQ bez IST,
    ramka na stosie zadania) + samotest: wektory 0x20-0x2F maja IST 0.
  - Asercja w `schedule()`: przelaczenie zadania na stosie IST = blad kernela.
  - Stosy IST przeniesione z .bss na stosy ze stronami-straznikami (5 x 64 KiB) zaraz po starcie heapa.
  - `map_mmio`: rejestry w stronie 2 MiB direct mapy dziela ja na strony 4 KiB - bez cache sa tylko
    strony rejestrow (`split_direct_map_huge`); MMIO z NX.

### Zmienione
- Proces z rodzicem-procesem: kernel wypisuje koniec tylko przy awarii (wyjatek CPU); normalny koniec
  i kill zglasza shell. Procesy uruchamiane przez kernel (shell kernela, testy) - jak dotad.
- Wyjscie/wejscie testowe procesu (bufory) dziedzicza dzieci - testy obejmuja cale drzewo procesow.
- `FsError::NotEmpty` -> ENOTEMPTY (-39).
- Shell kernela: awaryjny + zrodlo komend dla `kcmd`.
- Wersja 0.15.0.

## v0.14 — 2026-10-02

### Dodane
- **M15: ladowanie programow ELF.**
  - `common/elf.rs`: jeden parser ELF64 dla DSB (kernel) i kernela (programy) - bez alokacji;
    sprawdza magie, klase, kolejnosc bajtow, maszyne, typ ET_EXEC, tablice naglowkow, filesz <= memsz,
    dane w pliku i przepelnienia adresow. DSB uzywa go zamiast wlasnego kodu.
  - `kernel/user/elf_loader.rs`: segmenty PT_LOAD tylko w dolnej polowie (od 1 MiB - NULL daje #PF),
    W^X (dane NX, kod tylko do odczytu, takze przy stronie dzielonej przez dwa segmenty), `.bss`
    zerowane, punkt wejscia w kodzie, limity (obraz 64 MiB, plik 8 MiB, 32 argumenty / 4 KiB).
    Stos 16 KiB ze straznikiem, na nim argc, argv[], NULL, envp NULL, auxv AT_NULL (System V),
    RSP % 16 == 0.
  - Programy w Rust: `user/lib/desoos.rs` (syscalle, `print!`/`println!`/`eprintln!` z buforem - cala
    linia idzie jednym write, argumenty, `_start`, panic -> exit 101), `user/user.ld` (od 0x400000,
    sekcje od nowych stron), `user/bin/`: hello, args, cat (pliki albo stdin), save, primes.
  - `build.sh` kompiluje `user/bin/*.rs` (target x86_64-unknown-none, static) do `build/user/` i generuje
    `build/user/initrd.rs`; kernel przy starcie zapisuje programy do `/bin` (`kernel/initrd.rs`).
  - `run <nazwa|sciezka> [argumenty...] [&]`: najpierw `/bin/<nazwa>` (albo sciezka z `/`, wzgledem
    `cd`), potem programy testowe w asm; `run` bez argumentow pokazuje obie listy; podpowiedz przy
    literowce obejmuje /bin.
  - Proces ma katalog biezacy (cwd shella) - `open` ze sciezka wzgledna liczy od niego.
  - Normalny koniec programu na pierwszym planie (exit 0) bez komunikatu `[USER] ...`; kod != 0,
    bledy i procesy w tle - z komunikatem.
  - Samotesty `[ELF TEST]` 9/9: /bin parsuje sie i laduje, 14 uszkodzonych plikow odrzuconych (magia,
    klasa, endian, maszyna, ET_DYN, obciecie, segment w kernelu i na stronie 0, W+X, filesz > memsz,
    wejscie w danych, offset poza plikiem, za duzo argumentow), prawa stron (text RX, rodata R+NX,
    data/stos RW+NX, .bss zerowane), uklad stosu, exec hello/args/save/cat/primes, bledy exec,
    brak wycieku ramek. Razem 16 zestawow.

### Zmienione
- `run hello` i `run cat` uruchamiaja programy ELF z /bin (wersje asm z M14 zostaja w testach).
- Roadmapa: M15 zrobione, nastepny M16 (init + shell w user space); ARCHITEKTURA.md: programy ELF,
  W^X, uklad procesu i stosu.
- Wersja 0.14.0.

## v0.13 — 2026-10-02

### Dodane
- **M14: syscalle.**
  - `arch/x86_64/syscall.rs`: SYSCALL/SYSRET (EFER.SCE, STAR, LSTAR, SFMASK czysci IF/DF/TF/AC/NT).
    Wejscie: `swapgs` tylko na czas wziecia stosu kernela z bloku per CPU (MSR KERNEL_GS_BASE),
    ramka z rejestrami uzytkownika, `cli` przed odtworzeniem rejestrow, `sysretq`. Scheduler ustawia
    stos dla SYSCALL razem z TSS.RSP0.
  - Ochrona przed pulapka SYSRET: gdy RIP powrotu nie jest kanoniczny (syscall na samym koncu dolnej
    polowy), proces jest konczony zamiast #GP w ring 0 na stosie uzytkownika.
  - `user/syscalls.rs`: exit, write, read, open, close, getpid, sleep, yield, uptime (ABI jak
    w Linuksie: RAX = numer, RDI/RSI/RDX/R10/R8/R9, wynik w RAX, bledy jako -errno).
  - `user/process.rs`: proces = przestrzen adresowa + deskryptory (0/1/2 konsola, 3+ pliki z VFS:
    sciezka, pozycja, prawa, dopisywanie).
  - copy_from_user / copy_to_user: sprawdzenie zakresu (dolna polowa, strony z USER, przy zapisie
    WRITABLE), kopiowanie miedzy `stac` i `clac`; SMAP (CR4) wlaczony, jesli CPU go ma.
  - Konsola dla procesu: read(0) czyta linie z echem i Backspace; wyjscie procesu z tla nie psuje
    linii shella. Ctrl+C konczy proces na pierwszym planie juz w przerwaniu klawiatury/seriala
    (shell nie czyta wtedy klawiatury, wiec proces moze z niej czytac) i wyrzuca wpisane, nieodczytane
    znaki. Komunikat konca procesu zaczyna sie od nowej linii, jesli trzeba.
  - `kill` budzi zadanie czekajace w dowolnej kolejce (proces czekajacy w read konczy sie od razu).
  - Programy: hello, cat, files, ticker, pid, sleeper, regs, badptr, badsys (stary hello -> `sum`).
  - Samotesty 10/10: MSR-y i stos per CPU, write+exit, pliki w VFS, read ze stdin, EFAULT/ENOSYS/
    getpid, 3 x 100 000 syscalli bez zmiany rejestrow, sleep w 4 procesach naraz, kill w trakcie
    read, niekanoniczny RIP przy SYSRET, SMAP. Razem 15 zestawow.

### Zmienione
- Roadmapa: M14 zrobione, nastepny M15 (ELF loader); ARCHITEKTURA.md: tabela syscalli.
- Wersja 0.13.0.

## v0.12.1 — 2026-10-02

### Dodane
- `run <program> [n] [&]`: n kopii programu naraz (1..16), kazda z inna wartoscia startowa; na
  pierwszym planie shell czeka na wszystkie (Ctrl+C konczy wszystkie) i podsumowuje wynik.
  Np. `run xmm 3` sprawdza przelaczanie rejestrow SSE jedna komenda.
- Komunikat z tla (koniec procesu) nie rozbija linii shella: linia jest czyszczona, komunikat
  wypisany, a prompt z wpisanym tekstem i pozycja kursora rysuje sie od nowa (jak readline w Linuxie).
  `console::print_async` + linia edytowana zapamietywana przez shell przed czekaniem na klawisz.
- Samotest konsoli 9/10 sprawdza skladanie takiego komunikatu.

### Zmienione
- Wersja 0.12.1.

## v0.12 — 2026-10-02

### Dodane
- **M13b: stan FPU/SSE procesow.**
  - `arch/x86_64/fpu.rs`: FXSAVE/FXRSTOR (512 B na zadanie), CR4.OSFXSR + OSXMMEXCPT, CR0.MP/NE.
  - Scheduler przy kazdym przelaczeniu zapisuje rejestry x87/SSE procesu, ktory oddaje CPU, i odtwarza
    rejestry nastepnego (eager - bez leniwego przelaczania przez #NM, wiec bez podatnosci typu
    LazyFP i prosciej przy SMP). Zadania kernela dzialaja z CR0.TS = 1 - instrukcja FPU/SSE w kernelu
    konczy sie raportem bledu.
  - Nowy proces zaczyna z czystym stanem (rejestry 0, FCW 0x037F, MXCSR 0x1F80) - nie widzi
    rejestrow poprzednich procesow.
  - #XM (odmaskowany wyjatek SSE) konczy tylko proces.
  - Programy testowe: `sse` (21 + 21 w xmm0 = 42), `x87` (1 + 1 + 1 = 3), `xmm` (xmm0-15 + st0
    sprawdzane 2 mln razy), `fpuclean` (czysty stan nowego procesu), `simdexc` (#XM).
  - Samotesty FPU 5/5: CR0/CR4, 3 procesy z roznymi wartosciami we wszystkich rejestrach XMM i st0
    przelaczane w kolko (ok. 40 przelaczen, zadne wartosci sie nie mieszaja; test sprawdzony takze
    negatywnie - bez zapisu w schedulerze wykrywa blad), czysty stan nowego procesu, #XM (QEMU TCG
    go nie zglasza - wtedy pomijany), CR0.TS wraca w zadaniu kernela. Razem 14 zestawow.
- `run`: podpowiedz przy literowce (`run see` -> `did you mean 'sse'?`); kazde uruchomienie dostaje
  inna wartosc startowa w stronie danych.

### Zmienione
- Test USER 7/9: SSE i x87 w ring 3 dzialaja (w M13a konczyly proces przez #NM).
- Roadmapa: M13b zrobione, nastepny M14 (syscalle).
- Wersja 0.12.0.

## v0.11 — 2026-10-02

### Dodane
- **M13a: tryb uzytkownika i izolacja procesow.**
  - Proces = zadanie schedulera + wlasna przestrzen adresowa (`kernel/user/space.rs`): osobny PML4,
    dolna polowa tylko procesu (bit USER na calej sciezce tablic), gorna polowa wspolna z kernelem,
    PML4[510] wskazuje na wlasny PML4 procesu.
  - Wejscie do ring 3 przez `iretq` (CS 0x23, SS 0x1b, IF = 1, wyzerowane rejestry).
  - Scheduler przy kazdym przelaczeniu ustawia TSS.RSP0 (stos kernela zadania) i CR3 procesu.
  - NX: EFER.NXE, dane procesu/stos/heap/stosy zadan/direct map bez prawa wykonywania.
  - SMEP (CR4, jesli CPU ma): kernel nie wykona kodu ze strony uzytkownika.
  - Wyjatki z ring 3 (#BP, #PF, #GP, #UD, #NM i inne poza NMI/#DF/#MC) koncza tylko proces. Handler
    dziala na stosie IST, wiec nie przelacza tam zadan: zapisuje przyczyne i podmienia ramke
    powrotu - `iretq` wraca do ring 0 na stos kernela zadania (RSP0) i dopiero tam proces sie konczy.
    Komunikat np. `[USER] process 3 'pf' killed: #PF reading 0x0 (not mapped) at 0x400002`.
  - Wywlaszczanie procesow w ring 3 (tick PIT) i `kill` procesu z przerwania (proces nie musi
    nic sprawdzac).
  - FPU/SSE zablokowane do M13b: CR0.TS = 1, instrukcja FPU/SSE procesu -> #NM -> koniec procesu
    z komunikatem; #NM w kernelu = raport bledu kernela.
  - #BP ma w IDT DPL 3 (`int3` z ring 3). Wpisy PML4 gornej polowy alokowane od startu (procesy
    kopiuja je przy tworzeniu).
  - Shell: `run <program> [&]` (programy testowe ring 3: hello, counter, loop, pf, pfkernel,
    writecode, nx, gp, ud, sse, x87), Ctrl+C konczy proces na pierwszym planie; `ps` pokazuje
    kolumne MODE (kernel/user).
  - Samotesty 9/9: segmenty/IDT/TSS/CR0.TS, przestrzen adresowa (wspolna gorna polowa, flagi
    USER/NX), pierwszy ring 3 (suma 5050, CS = 0x23), 6 rodzajow bledow x 3 rundy naraz (stosy IST
    uzywane wielokrotnie), izolacja dwoch procesow pod tym samym adresem, wywlaszczanie petli
    w ring 3 + kill z przerwania, SSE/x87 -> #NM, SMEP, powrot RSP0/CR3 bez wyciekow pamieci.
    Razem 13 zestawow.
- `test.sh` uruchamia QEMU z `-cpu max` (NX, SMEP).

### Zmienione
- Roadmapa: M13 podzielone na M13a (zrobione) i M13b (FPU/SSE - nastepne); M14 rozpisane
  (SYSCALL/SYSRET, swapgs, stos per CPU, SMAP).
- Wersja 0.11.0.

## v0.10 — 2026-10-01

### Dodane
- **M12: scheduler - zadania kernela z wywlaszczaniem.**
  - `kernel/sched/`: zadania (`spawn`, `exit`, `yield_now`, `sleep`), round-robin z kwantem 10 ms
    liczonym w ticku PIT; przelaczenie kontekstu w asemblerze (rejestry zachowywane + RSP).
    Wywlaszczenie dzieje sie w `irq::dispatch` po wyslaniu EOI, wiec zadanie obudzone przerwaniem
    (klawiatura, dysk) dostaje CPU od razu.
  - Zadanie 1 "kernel" to kod startowy (potem shell), zadanie 0 "idle" robi `hlt`, gdy nikt nie jest
    gotowy, i sprzata zakonczone zadania (stos i struktura wracaja do pamieci).
  - Stosy zadan 64 KiB w osobnym obszarze `0xffff_e000_0000_0000` (slot 1 MiB na zadanie) - pod
    stosem nic nie jest zamapowane, przepelnienie konczy sie raportem
    `KERNEL STACK OVERFLOW` z nazwa zadania (`[EXC] task: 2 'boom'`).
  - Miejsce na stan FPU/SSE (FXSAVE, 512 B) w strukturze zadania - uzyje go M13.
  - `sched::sync`: `WaitQueue` (czekanie na warunek z pobudka z przerwania i limitem czasu) oraz
    `KMutex`/`Mutex<T>` (usypiajace, reentrant).
  - Czekanie bez marnowania CPU: shell czeka na klawisz w kolejce wejscia (budza ja IRQ klawiatury,
    seriala i myszy), virtio-blk usypia zadanie do przerwania dysku, `sleep` usypia zadanie.
  - Blokady: caly VFS (jedna blokada, kolejnosc: VFS -> dyski) i warstwa block.
  - `map_page`/`unmap_page` przy wylaczonych przerwaniach (zadania moga sie wywlaszczac w dowolnym
    miejscu).
  - Shell: `ps` (zadania, stan, czas CPU, przelaczenia), `spawn spin|tick` (zadania demo),
    `kill <id>` (prosba o zakonczenie).
  - Samotesty schedulera 8/8: spawn + sprzatanie stosu, yield, wywlaszczanie zadania, ktore nigdy
    nie oddaje CPU, sen 30 ms, kolejka oczekiwania (pobudka + limit czasu), mutex (600/600
    aktualizacji przy wywlaszczeniu w sekcji krytycznej), strona-straznik stosu. Razem 12 zestawow.

### Zmienione
- Roadmapa: M12 zrobione, nastepny M13 (user mode).
- Wersja 0.10.0.

## v0.9.3 — 2026-10-01

### Zmienione
- Przewijanie konsoli dziala tez z klawiatury numerycznej: Shift + 8/2 (o linie), Shift + 9/3
  (o ekran) - na czesci klawiatur i laptopow PgUp/PgDn sa tylko tam. Sprawdzone w QEMU: lewy
  i prawy Shift z PgUp/PgDn oraz Shift z klawiatura numeryczna.
- Wersja 0.9.3.

## v0.9.2 — 2026-10-01

### Zmienione
- Przewijanie konsoli klawiatura: Shift+strzalka w gore / w dol przewija o 1 linie,
  Shift+PgUp / Shift+PgDn o caly ekran (tyle linii, ile ma konsola - zalezy od rozdzielczosci;
  wczesniej o pol ekranu). Kolko myszy bez zmian (3 linie). Opis w `help` i README.
- Shift+strzalki nie trafiaja juz do shella (wczesniej Shift+gora/dol przegladalo historie komend
  tak jak zwykle strzalki - ta funkcja zostaje pod strzalkami bez Shift).
- Wersja 0.9.2.

## v0.9.1 — 2026-10-01

### Dodane
- **Mysz PS/2: kolko przewija konsole** (3 linie na zabek, jak Shift+PgUp/PgDn).
  - `ps2.rs`: inicjalizacja portu 2 - test portu, reset myszy, tryb z kolkiem (IntelliMouse /
    Explorer przez sekwencje czestotliwosci 200/100/80 i 200/200/80), wlaczenie raportowania, IRQ12.
    Brak myszy nie przeszkadza - port 2 zostaje wylaczony.
  - `drivers/mouse.rs`: dekoder pakietow 3/4-bajtowych z resynchronizacja (bit 3 bajtu 0),
    licznik kolka odbierany przez konsole poza przerwaniem (przerysowanie ekranu jest za dlugie na IRQ).
  - Samotesty myszy 3/3 (pakiety wstrzykiwane przez kontroler komenda 0xD3 -> IRQ12): ID 3/4,
    kolko w gore i w dol, przycisk, resynchronizacja. Razem 11 zestawow testow.
- `help` i README: przewijanie dziala w oknie QEMU (w terminalu przewija sam terminal); mysz trzeba
  przechwycic kliknieciem w okno (zwolnienie: Ctrl+Alt+G).

### Zmienione
- Wersja 0.9.1.

## v0.9 — 2026-10-01

### Dodane
- **M11: narzedzia i porzadki pod scheduler.**
  - `test.sh`: samotesty w QEMU bez okna, wynik jako kod wyjscia (0 PASS, 1 FAIL, 2 timeout,
    3 blad QEMU), log w `test.log`, osobny pusty dysk testowy. Kernel rozpoznaje tryb automatyczny
    po pliku fw_cfg `opt/desoos/autotest` i wylacza QEMU przez `isa-debug-exit` - takze przy panice
    i krytycznym wyjatku. Na koncu samotestow podsumowanie `Self-tests: 10/10 suites passed`.
  - Alokator ramek na bitmapie (1 bit na ramke, 16 KiB na 512 MiB RAM, polozona powyzej 1 MiB):
    `free_frame` wykrywa double-free jednym bitem (O(1)) zamiast przechodzic po liscie; wolne ramki
    nie sa juz zapisywane.
  - `alloc_frames(n, align)` / `free_frames(first, n)`: ciagle ramki (np. bufory DMA), wszystko albo nic.
  - virtio-blk: bufor DMA 64 KiB (16 ciaglych ramek) zamiast 4 KiB - 16 razy mniej zadan przy
    duzych odczytach.
  - Heap sie kurczy: gdy na jego koncu zbierze sie ponad 512 KiB wolnego miejsca, strony wracaja do
    alokatora ramek (zostaje zapas 128 KiB, nigdy mniej niz 128 KiB heapa). Po samotestach `mem`
    pokazuje znowu ok. 128 KiB zamiast 10 MiB.
  - Scrollback konsoli: 1000 linii, Shift+PgUp / Shift+PgDn przewija o pol ekranu, w prawym gornym
    rogu wskaznik (np. `-50/64`); nowe wyjscie (pisanie) wraca na dol. Opis w `help`.
  - Nowe samotesty: alokator ramek 8/8 (ciagle ramki, bledy, double-free), heap 9/9 (kurczenie),
    konsola 10/10 (scrollback), dysk 4/8 (160 sektorow = 2 zadania przez bufor 64 KiB).

### Zmienione
- Roadmapa: M11 zrobione, nastepny M12 (scheduler).
- Wersja 0.9.0.

## v0.8 — 2026-10-01

### Dodane
- **M10: kernel w gornej polowie + ELF w DSB.**
  - Kernel linkowany pod `0xffffffff80000000` (PML4[511], `kernel/linker.ld`); sekcje wyrownane
    do 4 KiB.
  - DSB (`boot/dsb.rs`) laduje `kernel.elf`: sprawdza naglowek (x86_64, ET_EXEC), kopiuje segmenty
    PT_LOAD do ciaglego bloku fizycznego pod dowolnym adresem, alokuje stos 256 KiB, buduje wlasne
    tablice stron (identity na czas skoku, direct map, kernel stronami 4 KiB), po ExitBootServices
    laduje CR3, ustawia RSP i skacze do `e_entry`. Bledy (zly ELF, brak pamieci) sa wypisywane na
    ekranie zamiast samego kodu statusu.
  - Direct map: fizyczny adres X jest widoczny pod `0xffff800000000000 + X` (`memory::phys_to_virt`).
    Kernel buduje go od nowa stronami 2 MiB tylko dla RAM-u i rezerwacji - dziury (okno PCI pod
    4 GiB) zostaja puste, wiec rejestry urzadzen dostaja tam mapowanie bez cache.
  - Dolna polowa przestrzeni adresowej jest pusta (PML4[0..256)) - miejsce na procesy (M13);
    dereferencja null pointera to teraz zawsze #PF.
  - Stos kernela ze strona-straznikiem: przepelnienie konczy sie raportem
    `KERNEL STACK OVERFLOW (hit the guard page below the stack)` zamiast cichego nadpisania pamieci.
  - Kod i rodata kernela tylko do odczytu, wlaczony CR0.WP (zapis do kodu = #PF).
  - `BootInfo` rozszerzone o magic `DSBOOT10` (kernel i DSB z roznych buildow sie wykryja),
    polozenie kernela i stosu; `memory/layout.rs` opisuje caly uklad adresow.
  - Komenda `mem` pokazuje adres i rozmiar kernela oraz stosu.
  - Samotesty: paging 7/7 (direct map + pusta dolna polowa, kernel RO, CR0.WP, stos i strona-straznik),
    wyjatki 8/8 (#PF na stronie-strazniku obsluzony przez IST), alokator ramek nie przyjmuje
    pamieci kernela ani stosu.

### Zmienione
- Ramki fizyczne (lista wolnych ramek, tablice stron, bufory DMA virtio, framebuffer, mapa pamieci
  UEFI) kernel czyta i pisze przez direct map zamiast przez identity map.
- `map_mmio` zwraca adres w direct mapie; virtio-blk pamieta osobno adresy fizyczne (dla urzadzenia)
  i wirtualne (dla CPU).
- TSS.RSP0 = szczyt stosu z BootInfo zamiast stalego `0x300000`.
- `build.sh`: zamiast `kernel.bin` powstaje `kernel.boot.elf` (kernel bez symboli, wbudowany w DSB);
  sprawdza typ ELF i punkt wejscia. Znika limit 512 KiB i kontrola miejsca na stos - kernel
  zbudowany bez optymalizacji (ok. 880 KiB) tez startuje.
- Roadmapa: M10 zrobione, numeracja dalszych etapow przesunieta (M11 narzedzia, M12 scheduler,
  M13 user mode, M14 syscalle, M15 ELF loader, M16 init + shell, M16b NVMe, M17 APIC + SMP,
  M18 sterowniki w user space, M19 USB).
- Wersja 0.8.0.

### Uwaga
- DSB i kernel trzeba budowac razem (`./build.sh`) - stary DSB nie uruchomi nowego kernela i odwrotnie.

## v0.7.2 — 2026-09-30

### Naprawione
- **Klawiatura PS/2 nie dzialala w buildzie z optymalizacja (-O)** – terminal (serial) dzialal.
  Wstawki `cli` / `sti` / `sti; hlt` byly oznaczone `nomem`, wiec kompilator zakladal, ze podczas
  `hlt` pamiec sie nie zmienia, i nie odczytywal ponownie kolejki zdarzen zapelnianej przez
  przerwanie klawiatury. Teraz te instrukcje sa bariera dla kompilatora.
- **`/disk` istnial takze bez sformatowanego dysku** – byl wtedy zwyklym katalogiem w RAM (ramfs),
  wiec pliki zapisane "na dysk" po cichu znikaly po restarcie (np. po literowce w `mkfs 0 yes`).
  Teraz `/disk` powstaje dopiero przy zamontowaniu FAT32; bez tego `cd /disk` zglasza blad.

### Dodane
- Podpowiedz przy literowce w komendzie: `mfks` -> `unknown command: mfks - did you mean 'mkfs'?`

## v0.7.1 — 2026-09-30

### Naprawione
- **Start konczyl sie `Buffer Too Small`** (i przejsciem do PXE). Kernel budowany bez optymalizacji
  urosl po M9 do ok. 627 KB (z samotestami 785 KB), a DSB przyjmuje obraz max 512 KiB
  (`KERNEL_MAX_IMAGE`). `build.sh` kompiluje teraz kernel z `-C opt-level=2` (ok. 280 KB,
  z samotestami ok. 390 KB) i zostawia kontrole przepelnien (`-C overflow-checks=on`).
- `build.sh` sprawdza po kompilacji rozmiar `kernel.bin` i miejsce na stos pod 0x300000 i konczy sie
  czytelnym bledem, zamiast budowac obraz, ktory nie wystartuje.
- Test heapa 4/8 przy optymalizacji: kompilator mogl usunac pare alloc+dealloc nieuzywanej pamieci,
  wiec test nie widzial oczekiwanej dziury. Testy heapa wolaja teraz alokator bezposrednio.

## v0.7 — 2026-09-30

### Dodane
- **M9: system plikow.**
  - `kernel/fs/mod.rs` (VFS): drzewo z punktami montowania, normalizacja sciezek (`.`, `..`),
    trait `FileSystem`, operacje stat/read_dir/read/write/truncate/create/mkdir/remove/sync,
    pomocnicze read_file/write_file/append_file; nie da sie usunac punktu montowania.
  - `kernel/fs/ramfs.rs`: system plikow w pamieci, zamontowany w `/` (z katalogami `/tmp` i `/disk`).
  - `kernel/fs/fat32.rs`: FAT32 - odczyt i zapis plikow i katalogow, dlugie nazwy (LFN/VFAT,
    UTF-16, polskie znaki), nazwy 8.3 z flagami malych liter, unikalne nazwy `~N`, wyszukiwanie bez
    rozrozniania wielkosci liter, dopisywanie, zapis w srodku pliku, dziury wypelniane zerami,
    truncate, katalog rosnie o klastry, FSInfo, cache sektorow FAT, `mkfs` (tabela rozmiarow
    klastrow Microsoftu), dysk bez tablicy partycji albo pierwsza partycja FAT32 z MBR.
  - `kernel/drivers/rtc.rs`: data i godzina z CMOS RTC (daty plikow, komenda `date`).
  - Shell: katalog biezacy w prompcie (`desoos:/disk>`), komendy ls, cd, pwd, cat, hexdump, touch,
    write, mkdir, rm, cp, mv, stat, mount, df, mkfs, sync, date; przekierowanie `>` i `>>`;
    argumenty w cudzyslowach; `reboot` i `halt` najpierw zapisuja bufory.
  - Przy starcie: `/` = ramfs, `/disk` = FAT32 z pierwszego dysku (jesli jest sformatowany).
  - 10 samotestow na dysku w RAM (8 MiB, nie rusza `disk.img`): sciezki, ramfs, mkfs, nazwy,
    pliki wieloklastrowe, dziury i truncate, 40 dlugich nazw w katalogu, brak wyciekow klastrow,
    trwalosc po ponownym montowaniu, kopiowanie ramfs -> FAT32, przekierowanie i cudzyslowy.
- Sprawdzona zgodnosc z Linuxem (dosfstools/mtools): dysk sformatowany i zapisany przez DeSoOS
  przechodzi `fsck.fat` bez bledow i jest czytelny w Linuxie; dysk sformatowany przez `mkfs.fat`
  (takze z tablica partycji MBR) DeSoOS czyta i zapisuje, pliki po kopiowaniu identyczne.

### Zmienione
- Wersja 0.7.0; roadmapa: M9 zrobione, nastepne M9b (NVMe).

## v0.6 — 2026-09-30

### Dodane
- **M8: PCI + virtio-blk.**
  - `kernel/drivers/pci.rs`: skan wszystkich szyn/urzadzen/funkcji (porty 0xCF8/0xCFC), rozmiary
    i typy BAR-ow (32/64-bit, IO), lista capabilities, wlaczanie DMA/INTx; urzadzeniom bez
    sterownika wylaczane sa przerwania INTx (w QEMU karta sieciowa dzieli IRQ 11 z dyskiem).
    Tryb poziomowy przerwan PCI w PIC (ELCR).
  - `memory::map_mmio`: rejestry urzadzen mapowane identycznie, bez cache (UC) – takze powyzej
    512 GiB (w QEMU/OVMF konfiguracja virtio lezy pod 0xC0_0000_0000).
  - `kernel/drivers/virtio_blk.rs`: virtio 1.0 (modern) – inicjalizacja wg specyfikacji, negocjacja
    funkcji (VERSION_1, RO, FLUSH), virtqueue (split ring) z DMA, zadania odczytu/zapisu/flush,
    przerwanie INTx (odczyt ISR kasuje linie), czekanie przez hlt z limitem czasu.
  - `kernel/block.rs`: wspolny interfejs dyskow (`BlockDevice`) i lista dyskow – system plikow (M9)
    i przyszle NVMe (M9b) korzystaja tylko z niego.
  - Shell: `lspci [-v]`, `disk`, `disk read`, `disk write` (hexdump sektora).
  - `run-qemu.sh`: tworzy `disk.img` (64 MiB) i podlacza go jako dysk virtio.
  - 8 samotestow (PCI, INTx, rejestracja dysku, odczyt wieloma zadaniami, zapis + flush + odczyt
    kontrolny z przywroceniem danych, bledy zakresu, przerwanie, predkosc odczytu).

### Zmienione
- Wersja 0.6.0; roadmapa: M8 zrobione, M9 nastepne, nowy etap M9b (NVMe); testy na prawdziwym
  komputerze przy bardziej rozbudowanym systemie.

## v0.5 — 2026-09-30

### Dodane
- **M7: konsola + shell.**
  - `kernel/drivers/fbcon.rs`: konsola tekstowa na framebufferze UEFI – siatka znakow 8x16
    (1280x800 -> 160x50), 16 kolorow, kursor, zawijanie i przewijanie (rysowane sa tylko zmienione
    komorki, framebuffer tylko zapisywany), UTF-8, podzbior ANSI (ESC[K, ESC[2J, ESC[H, ESC[nC/D, kolory).
  - `kernel/drivers/font.rs`: czcionka 8x16 – 234 znaki (ASCII, Latin-1, polskie litery, €, ramki,
    strzalki) wygenerowane z Terminus Font; licencja w `FONT-LICENSE.txt` (SIL OFL 1.1).
  - Framebuffer jako pamiec write-combining: PAT (PA1 = WC) + bit PWT na stronach 2 MiB framebuffera
    (`memory::map_write_combining`); strony zachodzace na RAM sa pomijane.
  - `kernel/console.rs`: wspolne wyjscie serial + ekran (wszystkie logi `serial_println!` sa od teraz
    tez na ekranie), wejscie z klawiatury PS/2 i z terminala (dekoder UTF-8 i sekwencji ESC).
  - Serial: odbior na przerwaniach (COM1, IRQ4, bufor 256 B), FIFO z progiem 1 bajt.
  - `kernel/shell.rs`: shell w kernelu – edycja linii (strzalki, Home/End, Delete), historia (32),
    Tab (dopelnianie komend), Ctrl+C/U/L; komendy: help, clear, echo, ver, uptime, mem, irq, sleep,
    keys, colors, history, reboot (8042 + triple fault), halt.
  - 9 samotestow konsoli i shella (piksele glifu, ANSI, przewijanie, polskie znaki, COM1 RX przez
    petle zwrotna UART + IRQ4, dekoder terminala, edytor linii, komendy).
  - `build.sh` przekazuje wersje z `Cargo.toml` do kernela (`DESOOS_VERSION`, komenda `ver`).

### Zmienione
- `serial_println!` pisze przez konsole (serial + ekran).
- Wysylanie na serial ma limit czasu: gdy nikt nie odbiera danych, bajty przepadaja zamiast
  zatrzymywac kernel (ekran dziala dalej, serial wraca sam, gdy UART sie zwolni).
- Tymczasowe echo z M6 zastapione shellem.
- Wersja 0.5.0; roadmapa: M7 zrobione, M8 nastepne.

## v0.4 — 2026-09-30

### Dodane
- **M6: klawiatura PS/2.**
  - `kernel/drivers/ps2.rs`: kontroler 8042 – wylaczenie portow, flush, konfiguracja (translacja do
    zestawu 1, port 2 wylaczony), self-test kontrolera i portu 1, reset klawiatury, wlaczenie
    skanowania, IRQ1. Brak kontrolera nie zatrzymuje systemu (komunikat + praca bez klawiatury).
    Czekanie na kontroler przez `hlt` (bez ciasnej petli na portach).
  - `kernel/drivers/keyboard.rs`: handler IRQ1, dekoder zestawu 1 (prefiks E0, sekwencja Pause E1,
    ignorowanie sztucznych Shiftow), diody Caps/Num/Scroll Lock (maszyna stanow 0xED + ACK/RESEND).
  - `kernel/input.rs`: wspolny podsystem wejscia (interfejs dla PS/2 teraz i USB w M17): `KeyCode`
    niezalezny od sprzetu, modyfikatory i blokady (autorepeat nie przelacza Caps Lock), uklad polski
    programisty (AltGr: ąćęłńóśźż, AltGr+u = €), Ctrl+litera = znak sterujacy, kolejka 256 zdarzen
    (`read_event`, `read_char`, `wait_event`).
  - 9 samotestow klawiatury: bajty wstrzykiwane przez kontroler (komenda 0xD2) ida prawdziwa
    sciezka IRQ1.
  - Tymczasowe echo klawiatury na serial w `kernel_main` (zastapi je konsola M7).

### Zmienione
- Wersja 0.4.0; roadmapa: M6 zrobione, M7 nastepne; nowe pozycje w "Znanych brakach".

## v0.3 — 2026-09-30

### Dodane
- **M5: Timer + IRQ (PIC 8259 + PIT).**
  - `kernel/arch/x86_64/pic.rs`: remap IRQ0-15 -> wektory 0x20-0x2F, mask/unmask, EOI,
    wykrywanie falszywych IRQ7/IRQ15, odczyt ISR/IRR, `disable()` na przyszly APIC.
  - `kernel/arch/x86_64/pit.rs`: kanal 0 w trybie 2 @ 1000 Hz (dzielnik 1193), odczyt licznika.
  - `kernel/arch/x86_64/irq.rs`: rejestracja handlerow IRQ, dispatch, liczniki,
    automatyczne maskowanie linii bez handlera.
  - `kernel/arch/x86_64/interrupts.rs`: `enable`/`disable`/`are_enabled`, `enable_and_hlt`,
    `without_interrupts` (zagniezdzalne).
  - `kernel/arch/x86_64/port.rs`: wspolne `inb`/`outb`/`io_wait`.
  - `kernel/time.rs`: ticki, `uptime_ms`, `sleep_ms`/`sleep_ticks` (przez `hlt`), hook na tick
    (pod scheduler M10); 8 samotestow (m.in. porownanie z zegarem CMOS RTC).
  - IDT: stuby IRQ0-15 (`idt.rs`), przekierowanie wektorow 0x20-0x2F do `irq::dispatch`.
- **Flaga `--selftest`** w `build.sh` (`--cfg selftest`): samotesty wszystkich etapow tylko w buildzie
  testowym; kod testow oznaczony `#[cfg(selftest)]`. Zwykly build konczy sie komunikatem
  `[DeSoOS] Kernel ready (idle)`.
- `CHANGELOG.md`.
- `ARCHITEKTURA.md`: decyzja o architekturze (modularny monolit teraz, hybryda po M12) i podziale sterownikow.
- `ARCHITEKTURA.md`: zasada "najpierw monolit, hybryda tam gdzie daje stabilnosc bez straty szybkosci", sekcja o wydajnosci IPC (pomiar przed przeniesieniem, ring buffery, batching).

### Zmienione
- Heap (`GlobalAlloc`) i alokator ramek dzialaja z wylaczonymi przerwaniami — mozna alokowac w handlerze IRQ.
- Test #GP w M4 uzywa wektora 0x7F zamiast 0x21 (0x21 to teraz IRQ1).
- Roadmapa: dodany M16 Sterowniki w user space (opcjonalnie).
- Roadmapa: dodany M17 USB (xHCI + klawiatura/mysz USB) po M16; do tego czasu wejscie przez PS/2 (M6).
- Roadmapa: M5 = PIC + PIT; APIC przeniesiony na koniec jako **M15 APIC + SMP** (dopiero gdy potrzebne SMP).
- Wersja: README v0.3, `Cargo.toml` 0.3.0.

### Naprawione
- Test M5 3/8 (`only 1 ticks in 20 PIT periods`) i 7/8 pod QEMU/OVMF w buildzie bez optymalizacji:
  test czekal w ciasnej petli czytajacej porty PIT/CMOS, co w QEMU (TCG) zaglodzalo watek
  zglaszajacy IRQ z PIT. Teraz test czeka przez `hlt` (CPU spi do przerwania), a petle
  odczytu portow maja przerwe. Sam kod PIC/PIT/IRQ byl poprawny.

## v0.2 — 2026-09-29
- M1 Frame allocator, M2 Paging, M3 Kernel heap, M4 GDT + IDT + wyjatki + mapowanie on-demand.
- DSB: SysV ABI przy skoku do kernela, `BootInfo` w zaalokowanej pamieci, `uefi 0.41`
  `exit_boot_services()` z zachowana mapa pamieci; kernel zeruje `.bss`; QEMU z dyskiem FAT z `build/`.
