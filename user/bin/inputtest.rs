// M20.e: test uchwytu INPUT i syscalla input_inject (USB TEST 3/4) – ścieżka
// usbd -> jądro bez sprzętu.  Uruchamia go jądro z uchwytem INPUT; jądro po
// teście czyta kolejkę wejścia i sprawdza znaki, autorepeat i modyfikatory.
//   1. błędy: nie-INPUT (EBADF), bez WRITE (EACCES), n = 0 / 65, zły rodzaj
//      (EINVAL – żadne zdarzenie nie przechodzi), puszczenie niewciśniętego,
//   2. "hi" + Shift+a -> jądro: "hiA",
//   3. 'b' trzymane 700 ms -> autorepeat jądra (500 ms, potem ~30/s),
//   4. Caps Lock -> stan diod (bit 1), drugi raz -> zgaszona,
//   5. dziecko z kopią uchwytu wciska Shift i 'q', zostaje zabite -> jądro
//      puszcza jego klawisze (Shift nie wisi, 'q' się nie powtarza).
// Wynik: "inputtest: N checks OK".
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const EINVAL: i64 = -22;
const EACCES: i64 = -13;
const SHIFT: u8 = 0xE1;
const CAPS: u8 = 0x39;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("inputtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn find_input() -> Option<u64> {
    (3..16).find(|&h| handle_info(h).map(|(k, _)| k) == Ok(KIND_INPUT))
}

fn tap(h: u64, usage: u8) -> i64 {
    input_inject(h, &[key_event(usage, true), key_event(usage, false)])
}

fn main(args: Args) -> i32 {
    // Dziecko: Shift + 'q' wciśnięte, potem czeka na kill.
    if args.get(1) == Some("child") {
        let h = find_input().unwrap_or(5);
        input_inject(h, &[key_event(SHIFT, true), key_event(0x14, true)]);
        println!("inputtest-child: pressed");
        sleep_ms(10_000);
        return 0;
    }
    let mut n = 0;
    let h = find_input();
    check!(n, h.is_some(), "no INPUT handle");
    let h = h.unwrap();

    // 1. Błędy.
    check!(n, input_inject(1, &[key_event(4, true)]) == EBADF, "console handle -> EBADF");
    let ro = handle_dup(h, 0);
    check!(n, ro >= 0 && input_inject(ro as u64, &[key_event(4, true)]) == EACCES, "INPUT without WRITE -> EACCES");
    close(ro as u64);
    check!(n, input_inject(h, &[]) == EINVAL, "n = 0 -> EINVAL");
    let many = [key_event(4, false); 65];
    check!(n, input_inject(h, &many) == EINVAL, "n = 65 -> EINVAL");
    check!(n, input_inject(h, &[key_event(0x07, true), [9, 0, 0, 0, 0, 0, 0, 0]]) == EINVAL, "bad kind -> EINVAL, nothing applied");
    check!(n, input_inject(h, &[key_event(0x08, false)]) >= 0, "release of a key never pressed is ignored");

    // 2. "hi" + Shift+a.
    check!(n, tap(h, 0x0B) >= 0 && tap(h, 0x0C) >= 0, "h, i");
    check!(n, input_inject(h, &[key_event(SHIFT, true), key_event(0x04, true), key_event(0x04, false), key_event(SHIFT, false)]) >= 0, "Shift+a");

    // 3. Autorepeat: 'b' trzymane 700 ms.
    check!(n, input_inject(h, &[key_event(0x05, true)]) >= 0, "b down");
    sleep_ms(700);
    check!(n, input_inject(h, &[key_event(0x05, false)]) >= 0, "b up");

    // 4. Caps Lock -> dioda.
    let on = tap(h, CAPS);
    check!(n, on >= 0 && on & 2 != 0, "Caps Lock on -> LED bit 1: {}", on);
    let off = tap(h, CAPS);
    check!(n, off >= 0 && off & 2 == 0, "Caps Lock off -> LED clear: {}", off);

    // 5. Dziecko z kopią uchwytu (osobne źródło) – zabite z wciśniętym Shiftem i 'q'.
    let Ok((r, w)) = pipe() else { return 2 };
    let pid = spawn_ex("/bin/inputtest", &["inputtest", "child"], &[(w, 1), (h, 5)], 0);
    close(w);
    check!(n, pid > 0, "spawn child");
    let mut buf = [0u8; 64];
    let k = read(r, &mut buf);
    check!(n, k > 0, "child pressed keys");
    sleep_ms(100); // < 500 ms – 'q' jeszcze się nie powtarza
    kill(pid as u64);
    let st = wait(pid as u64, 0);
    check!(n, matches!(st, Ok((_, s)) if s & STATUS_SIGNALED != 0), "child killed: {:?}", st);
    close(r);
    sleep_ms(700); // tick puszcza klawisze; 'q' nie może się powtarzać
    println!("inputtest: {} checks OK, errors, hiA, autorepeat, Caps Lock LED, keys of a killed source released", n);
    0
}
