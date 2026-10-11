// M15: primes [N] – liczy liczby pierwsze poniżej N (domyślnie 100000);
// zajmuje CPU, więc dobrze widać wywłaszczanie ('primes 3000000 &' + 'ps').
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

entry!(main);

fn parse(s: &str) -> Option<u64> {
    let mut v: u64 = 0;
    if s.is_empty() {
        return None;
    }
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(v)
}

fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    let mut d = 2;
    while d * d <= n {
        if n % d == 0 {
            return false;
        }
        d += 1;
    }
    true
}

fn main(args: desoos::Args) -> i32 {
    let limit = match args.get(1) {
        None => 100_000,
        Some(s) => match parse(s) {
            Some(v) => v,
            None => {
                eprintln!("usage: primes [N]");
                return 2;
            }
        },
    };
    let t0 = desoos::uptime_ms();
    let count = (0..limit).filter(|&n| is_prime(n)).count();
    println!("{} primes below {} ({} ms)", count, limit, desoos::uptime_ms() - t0);
    0
}
